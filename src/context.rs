use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use crate::journal::{self, JournalData};
use crate::state::{Metrics, Snapshot};
use crate::util::{
    parse_percent, parse_size_mib, read_trim, sh_lines, sh_ok, sh_trim, shell_quote,
};

#[derive(Debug, Clone)]
pub struct KernelPackage {
    pub name: String,
    pub version: String,
}

pub struct Context {
    pub host: String,
    pub running_kernel: String,
    pub installed_kernels: Vec<KernelPackage>,
    pub uptime_seconds: u64,
    pub is_kde: bool,
    pub previous: Option<Snapshot>,
    pub journal: JournalData,
    pub metrics: Metrics,
    pub orphan_names: Vec<String>,
    pub mem_sleep: String,
}

impl Context {
    pub fn collect(previous: Option<Snapshot>) -> Self {
        let host = read_trim("/proc/sys/kernel/hostname")
            .or_else(|| {
                std::env::var("HOSTNAME")
                    .ok()
                    .filter(|value| !value.is_empty())
            })
            .or_else(|| sh_trim("hostname"))
            .unwrap_or_else(|| "unknown".to_string());
        let running_kernel = sh_trim("uname -r").unwrap_or_else(|| "unknown".to_string());
        let installed_kernels = installed_kernels();
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let orphan_names = sh_lines("pacman -Qdtq 2>/dev/null");
        let journal = journal::collect(7, previous.as_ref());
        let mut metrics = collect_metrics(&home, &orphan_names);
        metrics.journal_errors_7d = Some(journal.total_entries);
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let is_kde = desktop.to_uppercase().contains("KDE")
            || crate::util::sh("pgrep -x plasmashell >/dev/null 2>&1").0;

        Self {
            host,
            running_kernel,
            installed_kernels,
            uptime_seconds: uptime_seconds(),
            is_kde,
            previous,
            journal,
            metrics,
            orphan_names,
            mem_sleep: read_trim("/sys/power/mem_sleep").unwrap_or_default(),
        }
    }

    pub fn kernel_flavor(&self) -> Option<&'static str> {
        let kernel = self.running_kernel.as_str();
        if kernel.contains("-rt-lts") {
            Some("linux-rt-lts")
        } else if kernel.contains("-zen") {
            Some("linux-zen")
        } else if kernel.contains("-lts") {
            Some("linux-lts")
        } else if kernel.contains("-hardened") {
            Some("linux-hardened")
        } else if kernel.contains("-mainline") {
            Some("linux-mainline")
        } else if kernel.contains("-next") {
            Some("linux-next")
        } else if kernel.contains("-rt") {
            Some("linux-rt")
        } else if kernel.contains("-arch") {
            Some("linux")
        } else {
            None
        }
    }

    pub fn uptime_human(&self) -> String {
        let secs = self.uptime_seconds;
        let days = secs / 86_400;
        let hours = (secs % 86_400) / 3_600;
        let minutes = (secs % 3_600) / 60;
        if days > 0 {
            format!("{days}d {hours}h")
        } else if hours > 0 {
            format!("{hours}h {minutes}m")
        } else {
            format!("{minutes}m")
        }
    }
}

fn installed_kernels() -> Vec<KernelPackage> {
    const KNOWN: &[&str] = &[
        "linux",
        "linux-zen",
        "linux-lts",
        "linux-hardened",
        "linux-rt",
        "linux-rt-lts",
        "linux-mainline",
        "linux-next",
        "linux-cachyos",
        "linux-clear",
        "linux-xanmod",
    ];
    sh_lines("pacman -Q 2>/dev/null")
        .into_iter()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?.to_string();
            let version = parts.next()?.to_string();
            KNOWN
                .contains(&name.as_str())
                .then_some(KernelPackage { name, version })
        })
        .collect()
}

fn collect_metrics(home: &Path, orphans: &[String]) -> Metrics {
    let (disk_used_pct, disk_avail_gib) = df_root().unzip();
    let pacman_cache_mib = du_mib("/var/cache/pacman/pkg");
    let baloo_mib = du_mib(home.join(".local/share/baloo").to_string_lossy().as_ref());
    let cache_mib = du_mib(home.join(".cache").to_string_lossy().as_ref());
    let journal_mib = journal_disk_mib();
    let (explicit_packages, foreign_packages) = package_counts();

    Metrics {
        disk_used_pct,
        disk_avail_gib,
        boot_seconds: boot_seconds(),
        pacman_cache_mib,
        orphans: Some(orphans.len()),
        orphan_mib: orphan_size_mib(orphans),
        baloo_mib,
        cache_mib,
        journal_mib,
        explicit_packages,
        foreign_packages,
        failed_units: None,
        journal_errors_7d: None,
    }
}

fn df_root() -> Option<(f64, f64)> {
    let out = sh_ok("df -P -l / 2>/dev/null")?;
    let line = out.lines().nth(1)?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return None;
    }
    let used_pct = parse_percent(fields[4])?;
    let avail_gib = fields[3].parse::<f64>().ok()? / 1024.0 / 1024.0;
    Some((used_pct, avail_gib))
}

fn boot_seconds() -> Option<f64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let out = sh_ok("systemd-analyze 2>/dev/null")?;
    let re = RE.get_or_init(|| Regex::new(r"=\s*([0-9.]+)s").expect("valid regex"));
    re.captures(&out)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse().ok())
}

fn du_mib(path: &str) -> Option<f64> {
    if !std::path::Path::new(path).exists() {
        return None;
    }
    let cmd = format!("timeout 8s du -sm {} 2>/dev/null", shell_quote(path));
    let (_, out, _) = crate::util::sh(&cmd);
    out.split_whitespace().next()?.parse().ok()
}

fn orphan_size_mib(names: &[String]) -> Option<f64> {
    if names.is_empty() {
        return Some(0.0);
    }
    let args = names
        .iter()
        .map(|name| shell_quote(name))
        .collect::<Vec<_>>()
        .join(" ");
    let out = sh_ok(&format!("pacman -Qi {args} 2>/dev/null"))?;
    let total = out
        .split("\n\n")
        .filter_map(|block| {
            block.lines().find_map(|line| {
                line.strip_prefix("Installed Size")
                    .and_then(|rest| rest.split(':').nth(1))
                    .and_then(parse_size_mib)
            })
        })
        .sum();
    Some(total)
}

fn journal_disk_mib() -> Option<f64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let out = sh_ok("journalctl --disk-usage 2>/dev/null")?;
    let re = RE.get_or_init(|| Regex::new(r"([0-9.]+)\s*([KMGT])").expect("valid regex"));
    let caps = re.captures(&out)?;
    let value: f64 = caps.get(1)?.as_str().parse().ok()?;
    let factor = match caps.get(2)?.as_str() {
        "K" => 1.0 / 1024.0,
        "M" => 1.0,
        "G" => 1024.0,
        "T" => 1024.0 * 1024.0,
        _ => 1.0,
    };
    Some(value * factor)
}

fn package_counts() -> (Option<usize>, Option<usize>) {
    let explicit = sh_ok("pacman -Qeq 2>/dev/null").map(|out| out.lines().count());
    let foreign = sh_ok("pacman -Qmq 2>/dev/null").map(|out| out.lines().count());
    (explicit, foreign)
}

fn uptime_seconds() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|raw| {
            raw.split_whitespace()
                .next()
                .and_then(|value| value.parse::<f64>().ok())
        })
        .unwrap_or(0.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_is_positive() {
        assert!(uptime_seconds() > 0);
    }
}
