use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use regex::Regex;

use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::util::{fmt_datetime, human_secs, parse_percent, sh, sh_ok, shell_quote};

pub fn kernel_pending(ctx: &Context) -> Vec<Finding> {
    let Some(flavor) = ctx.kernel_flavor() else {
        return Vec::new();
    };
    let Some(pkg) = ctx.installed_kernels.iter().find(|pkg| pkg.name == flavor) else {
        return vec![Finding::new(
            "boot.running_kernel_unmanaged",
            Severity::Watch,
            "运行中的内核没有对应的 pacman 包",
            format!(
                "当前运行 {}，但没有找到 {} 包。可能是手动编译内核、包已被移除，或使用了未识别的内核变体。",
                ctx.running_kernel, flavor
            ),
        )
        .tag("boot")
        .evidence(format!("uname -r: {}", ctx.running_kernel))
        .evidence(format!("已安装内核: {}", kernel_list(ctx)))
        .fix(
            Fix::new(
                "确认内核来源；如果是手动内核，可忽略此项",
                vec!["pacman -Q | grep '^linux'".into()],
                Risk::Low,
            )
            .manual(),
        )];
    };

    let running = version_triplet(&ctx.running_kernel);
    let installed = version_triplet(&pkg.version);

    if running < installed {
        let mut finding = Finding::new(
            "boot.kernel_pending",
            Severity::Action,
            "内核已更新，尚未重启",
            format!(
                "运行 {}，已安装 {} {}。升级后尚未重启，内核模块与用户空间可能不匹配。",
                ctx.running_kernel, pkg.name, pkg.version
            ),
        )
        .tag("boot")
        .tag("pacman")
        .evidence(format!("运行内核: {}", ctx.running_kernel))
        .evidence(format!("已安装: {} {}", pkg.name, pkg.version))
        .evidence(format!("已开机: {}", ctx.uptime_human()))
        .fix(
            Fix::new(
                "重启进入新内核（先保存工作）",
                vec!["sudo reboot".into()],
                Risk::Medium,
            )
            .manual(),
        );
        if ctx.uptime_seconds > 86_400 {
            finding = finding.evidence("已运行超过 24 小时，仍在使用旧内核。");
        }
        vec![finding]
    } else if running > installed {
        vec![Finding::new(
            "boot.kernel_newer_than_package",
            Severity::Watch,
            "运行中的内核比 pacman 记录更新",
            format!(
                "运行 {}，但 {} 包版本是 {}。可能是自定义内核、降级了包，或 pacman 数据库不一致。",
                ctx.running_kernel, pkg.name, pkg.version
            ),
        )
        .tag("boot")
        .evidence(format!("uname -r: {}", ctx.running_kernel))
        .evidence(format!("pacman -Q {}: {}", pkg.name, pkg.version))]
    } else {
        Vec::new()
    }
}

pub fn failed_units(_ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (scope, command) in [
        (
            "system",
            "systemctl --failed --no-legend --plain 2>/dev/null",
        ),
        (
            "user",
            "systemctl --user --failed --no-legend --plain 2>/dev/null",
        ),
    ] {
        let (ok, stdout, _) = sh(command);
        if !ok && scope == "user" {
            continue;
        }
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let Some(unit) = fields.first() else {
                continue;
            };
            if !unit.contains('.') {
                continue;
            }
            let description = fields
                .get(4..)
                .map(|rest| rest.join(" "))
                .unwrap_or_default();
            let scope_label = if scope == "user" { "用户" } else { "系统" };
            let prefix = if scope == "user" {
                "boot.failed_user_unit"
            } else {
                "boot.failed_system_unit"
            };
            let quoted = shell_quote(unit);
            let status_cmd = if scope == "user" {
                format!("systemctl --user status {quoted} --no-pager")
            } else {
                format!("systemctl status {quoted} --no-pager")
            };
            let log_cmd = if scope == "user" {
                format!("journalctl --user -u {quoted} -b --no-pager -n 50")
            } else {
                format!("journalctl -u {quoted} -b --no-pager -n 50")
            };
            let restart_cmd = if scope == "user" {
                format!("systemctl --user restart {quoted}")
            } else {
                format!("sudo systemctl restart {quoted}")
            };
            let summary = if description.is_empty() {
                "单元处于 failed 状态。".to_string()
            } else {
                format!("{description}（单元处于 failed 状态）")
            };
            findings.push(
                Finding::new(
                    format!("{prefix}:{unit}"),
                    Severity::Action,
                    format!("{scope_label}单元失败：{unit}"),
                    summary,
                )
                .tag("boot")
                .tag("systemd")
                .evidence(format!("systemctl {scope} --failed: {unit}"))
                .fix(Fix::new(
                    "查看状态与日志，确认后再重启该单元",
                    vec![status_cmd, log_cmd, restart_cmd],
                    Risk::Medium,
                )),
            );
        }
    }
    findings
}

pub fn initramfs_stale(ctx: &Context) -> Vec<Finding> {
    let boot = Path::new("/boot");
    let Ok(entries) = fs::read_dir(boot) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let current_flavor = ctx.kernel_flavor();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(flavor) = name
            .strip_prefix("vmlinuz-")
            .filter(|flavor| !flavor.is_empty())
        else {
            continue;
        };
        let kernel_path = boot.join(&name);
        let initramfs_path = boot.join(format!("initramfs-{flavor}.img"));
        let Ok(kernel_meta) = fs::metadata(&kernel_path) else {
            continue;
        };
        let Ok(kernel_time) = kernel_meta.modified() else {
            continue;
        };
        let initramfs_time = fs::metadata(&initramfs_path)
            .ok()
            .and_then(|meta| meta.modified().ok());
        let stale = match initramfs_time {
            None => true,
            Some(time) => time + std::time::Duration::from_secs(3_600) < kernel_time,
        };
        if !stale {
            continue;
        }
        let is_current = current_flavor.is_some_and(|current| current == flavor);
        let severity = if is_current {
            Severity::Action
        } else {
            Severity::Watch
        };
        let detail = if let Some(initramfs_time) = initramfs_time {
            format!(
                "vmlinuz {} 比 initramfs {} 新，mkinitcpio 可能没有跑成功。",
                fmt_system_time(kernel_time),
                fmt_system_time(initramfs_time)
            )
        } else {
            format!("找到 /boot/vmlinuz-{flavor}，但没有对应的 /boot/initramfs-{flavor}.img。")
        };
        findings.push(
            Finding::new(
                format!("boot.initramfs_stale:{flavor}"),
                severity,
                format!("initramfs 落后于内核：{flavor}"),
                detail,
            )
            .tag("boot")
            .tag("kernel")
            .evidence(format!("内核: {}", kernel_path.display()))
            .evidence(format!("initramfs: {}", initramfs_path.display()))
            .fix(Fix::new(
                "重新生成全部 initramfs",
                vec!["sudo mkinitcpio -P".into()],
                Risk::Medium,
            )),
        );
    }
    findings
}

pub fn boot_time(ctx: &Context) -> Vec<Finding> {
    let Some(out) = sh_ok("systemd-analyze 2>/dev/null") else {
        return Vec::new();
    };
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"=\s*([0-9.]+)s").expect("valid regex"));
    let Some(total) = re
        .captures(&out)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<f64>().ok())
    else {
        return Vec::new();
    };
    let previous = ctx
        .previous
        .as_ref()
        .and_then(|snap| snap.metrics.boot_seconds);
    let regression = previous.is_some_and(|prev| total > prev + 5.0);
    if total < 60.0 && !regression {
        return Vec::new();
    }
    let summary = match previous {
        Some(prev) if regression => format!(
            "本次启动 {}，上次 {}（+{}）。",
            human_secs(total),
            human_secs(prev),
            human_secs(total - prev)
        ),
        _ => format!("本次启动 {}，超过 60 秒。", human_secs(total)),
    };
    vec![
        Finding::new("boot.boot_time", Severity::Watch, "启动耗时偏长", summary)
            .tag("boot")
            .tag("performance")
            .evidence(out.lines().next().unwrap_or_default().to_string())
            .fix(
                Fix::new(
                    "查看启动耗时分布",
                    vec![
                        "systemd-analyze blame | head -20".into(),
                        "systemd-analyze critical-chain".into(),
                    ],
                    Risk::Low,
                )
                .manual(),
            ),
    ]
}

pub fn efi_space(_ctx: &Context) -> Vec<Finding> {
    let mount = if crate::util::sh_trim("findmnt -no TARGET /boot/efi 2>/dev/null").is_some() {
        "/boot/efi"
    } else if crate::util::sh_trim("findmnt -no TARGET /boot 2>/dev/null").is_some() {
        "/boot"
    } else {
        return Vec::new();
    };
    let out = sh_ok(&format!("df -P -l {} 2>/dev/null", shell_quote(mount)));
    let Some(out) = out else {
        return Vec::new();
    };
    let Some(line) = out.lines().nth(1) else {
        return Vec::new();
    };
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return Vec::new();
    }
    let Some(used_pct) = parse_percent(fields[4]) else {
        return Vec::new();
    };
    if used_pct < 85.0 {
        return Vec::new();
    }
    let severity = if used_pct >= 95.0 {
        Severity::Action
    } else {
        Severity::Watch
    };
    vec![Finding::new(
        format!("boot.efi_space:{mount}"),
        severity,
        format!("{mount} 分区空间不足"),
        format!("已用 {used_pct:.0}%，EFI/boot 分区过满会影响内核与 initramfs 更新。"),
    )
    .tag("boot")
    .tag("disk")
    .evidence(format!("df: {}", fields[2..6].join(" ")))
    .fix(
        Fix::new(
            "查看占用并清理旧内核/残留文件",
            vec![format!(
                "sudo du -xhd1 {} | sort -h | tail -20",
                shell_quote(mount)
            )],
            Risk::Low,
        )
        .manual(),
    )]
}

pub fn tainted(_ctx: &Context) -> Vec<Finding> {
    let Some(raw) = std::fs::read_to_string("/proc/sys/kernel/tainted").ok() else {
        return Vec::new();
    };
    let Ok(bits) = raw.trim().parse::<u64>() else {
        return Vec::new();
    };
    if bits == 0 {
        return Vec::new();
    }
    const FLAGS: &[(u64, &str)] = &[
        (1 << 0, "专有模块"),
        (1 << 1, "强制加载模块"),
        (1 << 2, "CPU 不在规格"),
        (1 << 3, "强制卸载模块"),
        (1 << 4, "机器检查"),
        (1 << 5, "坏页"),
        (1 << 7, "内核 die/oops"),
        (1 << 8, "ACPI 表被覆盖"),
        (1 << 9, "内核警告"),
        (1 << 10, "staging 驱动"),
        (1 << 11, "固件 workaround"),
        (1 << 12, "树外模块"),
        (1 << 13, "未签名模块"),
        (1 << 14, "soft lockup"),
        (1 << 15, "livepatch"),
    ];
    let flags: Vec<&str> = FLAGS
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, label)| *label)
        .collect();
    if flags.is_empty() {
        return Vec::new();
    }
    let severity = if bits & ((1 << 7) | (1 << 4) | (1 << 5) | (1 << 14)) != 0 {
        Severity::Watch
    } else {
        Severity::Info
    };
    vec![Finding::new(
        "boot.kernel_tainted",
        severity,
        "内核带有 taint 标记",
        format!(
            "内核 taint 值 {bits}：{}。树外/专有模块本身不一定有问题，但排障时需要知道。",
            flags.join("、")
        ),
    )
    .tag("boot")
    .tag("kernel")
    .evidence(format!("/proc/sys/kernel/tainted: {bits}"))
    .fix(
        Fix::new(
            "确认模块来源",
            vec!["cat /proc/sys/kernel/tainted".into(), "lsmod".into()],
            Risk::Low,
        )
        .manual(),
    )]
}

fn version_triplet(version: &str) -> (u64, u64, u64) {
    let mut numbers = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok());
    (
        numbers.next().unwrap_or(0),
        numbers.next().unwrap_or(0),
        numbers.next().unwrap_or(0),
    )
}

fn kernel_list(ctx: &Context) -> String {
    if ctx.installed_kernels.is_empty() {
        "无".to_string()
    } else {
        ctx.installed_kernels
            .iter()
            .map(|pkg| format!("{} {}", pkg.name, pkg.version))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn fmt_system_time(time: SystemTime) -> String {
    let dt: DateTime<Local> = time.into();
    fmt_datetime(&dt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare() {
        assert_eq!(version_triplet("7.2.9-zen1-1-zen"), (7, 2, 9));
        assert_eq!(version_triplet("7.2.11.zen1-1"), (7, 2, 11));
        assert!(version_triplet("7.2.9-zen1-1-zen") < version_triplet("7.2.11.zen1-1"));
    }
}
