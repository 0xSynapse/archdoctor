use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::util::{human_mib, parse_percent, sh, sh_ok, shell_quote, which};

pub fn usage(_ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    let out = sh_ok("df -P -l -x tmpfs -x devtmpfs -x efivarfs -x squashfs 2>/dev/null");
    if let Some(out) = out {
        let mut rows: BTreeMap<String, DiskRow> = BTreeMap::new();
        for line in out.lines().skip(1) {
            let Some(row) = DiskRow::parse(line) else {
                continue;
            };
            if row.mount.starts_with("/var/lib/docker")
                || row.mount.starts_with("/run")
                || row.mount.starts_with("/dev")
            {
                continue;
            }
            rows.entry(row.device.clone())
                .and_modify(|existing| {
                    if row.mount == "/" || row.mount.len() < existing.mount.len() {
                        *existing = row.clone();
                    }
                })
                .or_insert(row);
        }
        for row in rows.into_values() {
            if row.used_pct < 80.0 {
                continue;
            }
            let severity = if row.used_pct >= 95.0 {
                Severity::Action
            } else if row.used_pct >= 85.0 {
                Severity::Watch
            } else {
                Severity::Info
            };
            findings.push(
                Finding::new(
                    format!("disk.usage:{}", row.mount),
                    severity,
                    format!("{} 空间使用率 {:.0}%", row.mount, row.used_pct),
                    format!(
                        "{} 已用 {} / {}，剩余 {}。",
                        row.mount,
                        blocks_human(&row.used),
                        blocks_human(&row.size),
                        blocks_human(&row.avail)
                    ),
                )
                .tag("disk")
                .evidence(format!(
                    "{} {} {} {} {}% {}",
                    row.device,
                    blocks_human(&row.size),
                    blocks_human(&row.used),
                    blocks_human(&row.avail),
                    row.used_pct,
                    row.mount
                ))
                .fix(
                    Fix::new(
                        "查看目录占用（不要盲目删除）",
                        vec![
                            format!(
                                "sudo du -xhd1 {} 2>/dev/null | sort -h | tail -20",
                                shell_quote(&row.mount)
                            ),
                            "archdoctor explain disk".into(),
                        ],
                        Risk::Low,
                    )
                    .manual(),
                ),
            );
        }
    }

    if let Some(out) = sh_ok("df -Pi -l 2>/dev/null") {
        let mut seen = std::collections::BTreeSet::new();
        for line in out.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                continue;
            }
            let Some(used_pct) = parse_percent(fields[4]) else {
                continue;
            };
            if used_pct < 90.0 || !seen.insert(fields[0].to_string()) {
                continue;
            }
            findings.push(
                Finding::new(
                    format!("disk.inodes:{}", fields[5]),
                    if used_pct >= 95.0 {
                        Severity::Action
                    } else {
                        Severity::Watch
                    },
                    format!("{} inode 使用率 {:.0}%", fields[5], used_pct),
                    "inode 用尽后即使还有空间也无法创建新文件；常见原因是大量小文件/缓存。",
                )
                .tag("disk")
                .evidence(format!("df -i: {}", fields[2..6].join(" ")))
                .fix(
                    Fix::new(
                        "定位小文件目录",
                        vec![format!(
                            "sudo find {} -xdev -type f | wc -l",
                            shell_quote(fields[5])
                        )],
                        Risk::Low,
                    )
                    .manual(),
                ),
            );
        }
    }
    findings
}

pub fn pacman_cache(ctx: &Context) -> Vec<Finding> {
    let Some(mib) = ctx.metrics.pacman_cache_mib else {
        return Vec::new();
    };
    if mib < 8_192.0 {
        return Vec::new();
    }
    let severity = if mib >= 20_480.0 {
        Severity::Action
    } else {
        Severity::Watch
    };
    let command = if which("paccache") {
        "sudo paccache -rk2"
    } else {
        "sudo pacman -Sc"
    };
    vec![Finding::new(
        "disk.pacman_cache",
        severity,
        format!("pacman 包缓存 {}", human_mib(mib)),
        "旧版本安装包会一直留在 /var/cache/pacman/pkg；保留最近 2 个版本通常足够回滚。",
    )
    .tag("disk")
    .tag("pacman")
    .evidence(format!("/var/cache/pacman/pkg = {}", human_mib(mib)))
    .fix(Fix::new(
        "清理旧缓存（paccache 可保留最近 2 个版本）",
        vec![command.into()],
        Risk::Low,
    ))]
}

pub fn journal_size(ctx: &Context) -> Vec<Finding> {
    let Some(mib) = ctx.metrics.journal_mib else {
        return Vec::new();
    };
    if mib < 1_024.0 {
        return Vec::new();
    }
    let severity = if mib >= 4_096.0 {
        Severity::Action
    } else {
        Severity::Watch
    };
    vec![Finding::new(
        "disk.journal_size",
        severity,
        format!("systemd journal {}", human_mib(mib)),
        "journal 过大通常意味着某个服务在持续刷错误，先看日志再清理。",
    )
    .tag("disk")
    .tag("logs")
    .evidence(format!("journalctl --disk-usage = {}", human_mib(mib)))
    .fix(Fix::new(
        "保留最近 500 MiB journal",
        vec!["sudo journalctl --vacuum-size=500M".into()],
        Risk::Low,
    ))]
}

pub fn user_cache(ctx: &Context) -> Vec<Finding> {
    let Some(mib) = ctx.metrics.cache_mib else {
        return Vec::new();
    };
    if mib < 10_240.0 {
        return Vec::new();
    }
    let severity = if mib >= 20_480.0 {
        Severity::Watch
    } else {
        Severity::Info
    };
    vec![Finding::new(
        "disk.user_cache",
        severity,
        format!("用户缓存 {}", human_mib(mib)),
        "~/.cache 大多可以安全重建，但不要直接清空正在运行应用的缓存；先按目录定位大头。",
    )
    .tag("disk")
    .tag("desktop")
    .evidence(format!("~/.cache = {}", human_mib(mib)))
    .fix(
        Fix::new(
            "查看缓存占用",
            vec!["du -xhd1 ~/.cache 2>/dev/null | sort -h | tail -20".into()],
            Risk::Low,
        )
        .manual(),
    )]
}

pub fn orphans(ctx: &Context) -> Vec<Finding> {
    let count = ctx.orphan_names.len();
    if count < 20 {
        return Vec::new();
    }
    let mib = ctx.metrics.orphan_mib.unwrap_or(0.0);
    let debug_count = ctx
        .orphan_names
        .iter()
        .filter(|name| name.ends_with("-debug"))
        .count();
    let mut evidence: Vec<String> = ctx.orphan_names.iter().take(12).cloned().collect();
    if count > 12 {
        evidence.push(format!("… 另有 {} 个", count - 12));
    }
    if debug_count > 0 {
        evidence.push(format!(
            "其中 {debug_count} 个是 *-debug 包；如果不用 debuginfod 可以移除"
        ));
    }
    vec![Finding::new(
        "disk.orphans",
        Severity::Watch,
        format!("{count} 个孤儿包（{}）", human_mib(mib)),
        "孤儿包是“不再被任何包依赖”的包。删除前请确认不是 AUR 包的可选依赖。",
    )
    .tag("disk")
    .tag("pacman")
    .evidence_many(evidence)
    .fix(Fix::new(
        "交互式删除孤儿包（pacman 会再确认一次）",
        vec!["sudo pacman -Rns $(pacman -Qdtq)".into()],
        Risk::High,
    ))]
}

pub fn baloo(ctx: &Context) -> Vec<Finding> {
    let Some(mib) = ctx.metrics.baloo_mib else {
        return Vec::new();
    };
    if mib < 2_048.0 {
        return Vec::new();
    }
    let severity = if mib >= 8_192.0 {
        Severity::Action
    } else {
        Severity::Watch
    };
    let status = sh_ok("balooctl6 status 2>/dev/null")
        .or_else(|| sh_ok("balooctl status 2>/dev/null"))
        .unwrap_or_else(|| "状态未知".to_string());
    let tool = if which("balooctl6") {
        "balooctl6"
    } else {
        "balooctl"
    };
    vec![Finding::new(
        "disk.baloo",
        severity,
        format!("baloo 索引 {}", human_mib(mib)),
        "KDE 文件索引过大时会占磁盘并增加 I/O；purge 后会在空闲时重建。",
    )
    .tag("disk")
    .tag("desktop")
    .tag("kde")
    .evidence(format!("~/.local/share/baloo = {}", human_mib(mib)))
    .evidence(status.lines().take(3).collect::<Vec<_>>().join(" / "))
    .fix(Fix::new(
        "清空并重建 baloo 索引",
        vec![format!("{tool} purge")],
        Risk::Low,
    ))]
}

pub fn trim(_ctx: &Context) -> Vec<Finding> {
    let enabled = sh("systemctl is-enabled fstrim.timer 2>/dev/null").1;
    let enabled = enabled.trim();
    if enabled == "enabled" {
        return Vec::new();
    }
    let options = sh("findmnt -no OPTIONS / 2>/dev/null").1;
    if options.contains("discard") {
        return Vec::new();
    }
    vec![Finding::new(
        "disk.trim",
        Severity::Info,
        "fstrim.timer 未启用",
        "根分区挂载参数没有 discard，且周期性 TRIM 未启用。SSD 长期不 TRIM 可能影响写入性能。",
    )
    .tag("disk")
    .evidence(format!("systemctl is-enabled fstrim.timer: {enabled}"))
    .evidence(format!("findmnt / options: {}", options.trim()))
    .fix(Fix::new(
        "启用每周 TRIM",
        vec!["sudo systemctl enable --now fstrim.timer".into()],
        Risk::Low,
    ))]
}

pub fn docker(_ctx: &Context) -> Vec<Finding> {
    let active = sh("systemctl is-active docker 2>/dev/null").1;
    if active.trim() != "active" || !which("docker") {
        return Vec::new();
    }
    let out = sh_ok("timeout 5s docker system df --format '{{json .}}' 2>/dev/null");
    let Some(out) = out else {
        return Vec::new();
    };
    let mut reclaimable_mib = 0.0;
    let mut lines = Vec::new();
    for line in out.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let kind = value.get("Type").and_then(|v| v.as_str()).unwrap_or("?");
        let size = value.get("Size").and_then(|v| v.as_str()).unwrap_or("?");
        let reclaimable = value
            .get("Reclaimable")
            .and_then(|v| v.as_str())
            .unwrap_or("0B");
        if let Some(mib) = parse_docker_size(reclaimable) {
            reclaimable_mib += mib;
        }
        lines.push(format!("{kind}: {size} (可回收 {reclaimable})"));
    }
    if reclaimable_mib < 1_024.0 {
        return Vec::new();
    }
    vec![Finding::new(
        "disk.docker",
        if reclaimable_mib >= 5_120.0 {
            Severity::Watch
        } else {
            Severity::Info
        },
        format!("Docker 可回收 {}", human_mib(reclaimable_mib)),
        "未使用的镜像、容器和构建缓存可以回收；prune 前确认没有需要保留的停止容器。",
    )
    .tag("disk")
    .tag("docker")
    .evidence_many(lines)
    .fix(
        Fix::new(
            "清理未使用的 Docker 资源",
            vec!["docker system prune".into()],
            Risk::Medium,
        )
        .manual(),
    )]
}

fn parse_docker_size(raw: &str) -> Option<f64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)^\s*([0-9.]+)\s*([KMGT]?B)").expect("valid regex"));
    let caps = re.captures(raw)?;
    let value: f64 = caps.get(1)?.as_str().parse().ok()?;
    let factor = match caps.get(2)?.as_str().to_ascii_uppercase().as_str() {
        "B" => 1.0 / 1024.0 / 1024.0,
        "KB" => 1.0 / 1024.0,
        "MB" => 1.0,
        "GB" => 1024.0,
        "TB" => 1024.0 * 1024.0,
        _ => 1.0,
    };
    Some(value * factor)
}

#[derive(Debug, Clone)]
struct DiskRow {
    device: String,
    size: String,
    used: String,
    avail: String,
    used_pct: f64,
    mount: String,
}

impl DiskRow {
    fn parse(line: &str) -> Option<Self> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return None;
        }
        Some(Self {
            device: fields[0].to_string(),
            size: fields[1].to_string(),
            used: fields[2].to_string(),
            avail: fields[3].to_string(),
            used_pct: parse_percent(fields[4])?,
            mount: fields[5..].join(" "),
        })
    }
}

fn blocks_human(raw: &str) -> String {
    raw.parse::<f64>()
        .map(|blocks| human_mib(blocks / 1024.0))
        .unwrap_or_else(|_| raw.to_string())
}
