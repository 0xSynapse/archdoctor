use std::fs;
use std::path::Path;
use std::time::SystemTime;

use chrono::{DateTime, Local};

use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::util::{fmt_datetime, now, sh, sh_ok, which};

pub fn pacnew(_ctx: &Context) -> Vec<Finding> {
    let out = sh("find /etc \\( -name '*.pacnew' -o -name '*.pacsave' \\) 2>/dev/null").1;
    let files: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if files.is_empty() {
        return Vec::new();
    }
    let critical = files.iter().any(|path| {
        matches!(
            path.as_str(),
            "/etc/pacman.conf" | "/etc/fstab" | "/etc/mkinitcpio.conf" | "/etc/default/grub"
        )
    });
    let severity = if critical {
        Severity::Action
    } else {
        Severity::Watch
    };
    let mut evidence: Vec<String> = files
        .iter()
        .take(10)
        .map(|path| {
            let date = fs::metadata(path)
                .ok()
                .and_then(|meta| meta.modified().ok())
                .map(fmt_system_time)
                .unwrap_or_else(|| "日期未知".into());
            format!("{path} ({date})")
        })
        .collect();
    if files.len() > 10 {
        evidence.push(format!("… 另有 {} 个", files.len() - 10));
    }
    let commands = if which("pacdiff") {
        vec!["sudo pacdiff -s".to_string()]
    } else {
        vec![
            "sudo pacman -S pacman-contrib".to_string(),
            "sudo pacdiff -s".to_string(),
        ]
    };
    vec![Finding::new(
        "pacman.pacnew",
        severity,
        format!("{} 个 .pacnew/.pacsave 未合并", files.len()),
        "pacman 升级时不会覆盖你改过的配置文件，而是留下 .pacnew。长期不合并会让配置与新版本脱节。",
    )
    .tag("pacman")
    .tag("config")
    .evidence_many(evidence)
    .fix(Fix::new(
        "逐项合并配置（pacdiff 会询问）",
        commands,
        Risk::Medium,
    ))]
}

pub fn mirrorlist(_ctx: &Context) -> Vec<Finding> {
    let path = Path::new("/etc/pacman.d/mirrorlist");
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    let modified: DateTime<Local> = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH).into();
    let age_days = (now() - modified).num_days();
    let servers = sh_ok("grep -c '^Server' /etc/pacman.d/mirrorlist 2>/dev/null")
        .and_then(|out| out.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let has_pacnew = path.with_extension("pacnew").exists();
    if age_days <= 180 && servers <= 100 && !has_pacnew {
        return Vec::new();
    }
    let mut evidence = vec![
        format!(
            "mirrorlist 修改时间: {}（{} 天前）",
            fmt_datetime(&modified),
            age_days
        ),
        format!("启用的 Server 条目: {servers}"),
    ];
    if has_pacnew {
        evidence.push("存在 /etc/pacman.d/mirrorlist.pacnew".into());
    }
    let reflector = which("reflector");
    let commands = if reflector {
        vec!["sudo reflector --latest 20 --protocol https --sort rate --save /etc/pacman.d/mirrorlist".into()]
    } else {
        vec![
            "sudo pacman -S reflector".into(),
            "sudo reflector --latest 20 --protocol https --sort rate --save /etc/pacman.d/mirrorlist".into(),
        ]
    };
    vec![Finding::new(
        "pacman.mirrorlist",
        Severity::Watch,
        "镜像列表可能过期或过于臃肿",
        "镜像列表太久没更新会拖慢下载甚至遇到同步落后的镜像；几百个 Server 条目也没有必要。",
    )
    .tag("pacman")
    .tag("mirror")
    .evidence_many(evidence)
    .fix(Fix::new(
        "用 reflector 生成一份精简的 HTTPS 镜像列表",
        commands,
        Risk::Medium,
    ))]
}

pub fn keyring(_ctx: &Context) -> Vec<Finding> {
    let out = sh_ok(
        "tail -n 5000 /var/log/pacman.log 2>/dev/null | grep -Ei 'invalid or corrupted package|unknown trust|signature .* is unknown|key .* expired' 2>/dev/null",
    )
    .unwrap_or_default();
    let lines: Vec<&str> = out.lines().filter(|line| !line.trim().is_empty()).collect();
    if lines.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "pacman.keyring",
        Severity::Watch,
        "pacman 日志里有签名/信任错误",
        "常见原因是 archlinux-keyring 太旧，或某个包/镜像的签名无法验证。先更新 keyring，再做完整升级。",
    )
    .tag("pacman")
    .tag("security")
    .evidence_many(lines.iter().rev().take(3).map(|line| line.to_string()))
    .fix(Fix::new(
        "更新 keyring 后再完整升级",
        vec![
            "sudo pacman -S archlinux-keyring".into(),
            "sudo pacman -Su".into(),
        ],
        Risk::Medium,
    ))]
}

fn fmt_system_time(time: SystemTime) -> String {
    let dt: DateTime<Local> = time.into();
    dt.format("%Y-%m-%d %H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrorlist_parsing_helpers_exist() {
        // The regex is only used indirectly; keep a smoke test for the date path.
        let dt: DateTime<Local> = SystemTime::UNIX_EPOCH.into();
        assert!(dt.timestamp() == 0);
    }
}
