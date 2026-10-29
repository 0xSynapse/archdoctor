use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::journal::merge_time;
use crate::util::{fmt_short, sh, sh_ok, which};

const COVERED_BY_SPECIFIC_CHECKS: &[&str] = &[
    "bluetooth",
    "bluez",
    "sco packet",
    "acl packet",
    "raop",
    "bluez_output",
    "bluez_input",
    "pipewire",
    "wireplumber",
    "wpa_supplicant",
    "iwlwifi",
    "ath10k",
    "ath11k",
    "ath12k",
    "mt76",
    "brcmfmac",
    "networkmanager",
    "dhcp",
    "wlan",
    "wifi",
    "pm:",
    "suspend",
    "resume",
    "hibernate",
    "freezing of tasks",
    "systemd-sleep",
    "acpi: pm",
    "wakeup",
    "plasmashell",
    "kwin",
    "kded",
    "baloo",
    "akonadi",
    "kscreen",
    "plasma",
];

pub fn error_signatures(ctx: &Context) -> Vec<Finding> {
    let signatures: Vec<_> = ctx
        .journal
        .signatures
        .iter()
        .filter(|sig| {
            let haystack = format!("{} {}", sig.sample, sig.identifier).to_lowercase();
            !COVERED_BY_SPECIFIC_CHECKS
                .iter()
                .any(|needle| haystack.contains(needle))
        })
        .collect();
    if signatures.is_empty() {
        return Vec::new();
    }
    let total = crate::journal::JournalData::sum_count(&signatures);
    let any_new = signatures.iter().any(|sig| sig.is_new);
    let new_count = signatures.iter().filter(|sig| sig.is_new).count();
    let sig_count = signatures.len();
    let chronic = signatures
        .iter()
        .filter(|sig| sig.kind == crate::finding::TimeKind::Chronic)
        .count();
    if total < 5 && !any_new {
        return Vec::new();
    }
    let severity = if (any_new && total >= 3) || (chronic > 0 && total >= 20) {
        Severity::Watch
    } else {
        Severity::Info
    };
    let time = merge_time(&signatures);
    let top: Vec<_> = signatures.into_iter().take(5).collect();
    let examples = top
        .iter()
        .map(|sig| {
            format!(
                "{} ×{} · {} · {} → {}",
                sig.sample,
                sig.count,
                sig.kind.label_zh(),
                sig.first.map(|t| fmt_short(&t)).unwrap_or_default(),
                sig.last.map(|t| fmt_short(&t)).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    vec![Finding::new(
        "logs.error_signatures",
        severity,
        format!("未分类错误日志 {total} 条（7 天）"),
        format!(
            "共 {} 类；{} 类持续出现，{} 类新出现。已按归一化签名聚合，避免同一错误刷屏。",
            sig_count, chronic, new_count
        ),
    )
    .tag("logs")
    .evidence_many(examples)
    .time(time.unwrap_or(crate::finding::TimeProfile {
        kind: crate::finding::TimeKind::Normal,
        count: total,
        first: None,
        last: None,
        days: 0,
        boots: 0,
        is_new: false,
    }))
    .fix(
        Fix::new(
            "查看原始错误日志",
            vec!["journalctl -p 3 --since '7 days ago' --no-pager".into()],
            Risk::Low,
        )
        .manual(),
    )]
}

pub fn oom(_ctx: &Context) -> Vec<Finding> {
    let out = sh_ok(
        "journalctl --since '7 days ago' --no-pager -o cat -g 'Out of memory|oom-kill|Killed process|oom_reaper' 2>/dev/null",
    )
    .unwrap_or_default();
    let lines: Vec<&str> = out.lines().filter(|line| !line.trim().is_empty()).collect();
    if lines.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "logs.oom",
        Severity::Watch,
        format!("7 天内发生 {} 条 OOM 记录", lines.len()),
        "OOM 会直接杀掉进程，表现为应用突然消失或桌面卡死。先看是哪个进程、是否有内存泄漏。",
    )
    .tag("logs")
    .tag("memory")
    .evidence_many(lines.iter().rev().take(3).map(|line| line.to_string()))
    .fix(
        Fix::new(
            "查看 OOM 事件",
            vec![
                "journalctl -k -g 'Out of memory|oom' --no-pager -n 80".into(),
                "free -h".into(),
            ],
            Risk::Low,
        )
        .manual(),
    )]
}

pub fn coredumps(_ctx: &Context) -> Vec<Finding> {
    if !which("coredumpctl") {
        return Vec::new();
    }
    let out = sh("coredumpctl list --since '7 days ago' --no-pager --no-legend 2>/dev/null").1;
    let lines: Vec<&str> = out.lines().filter(|line| !line.trim().is_empty()).collect();
    if lines.is_empty() {
        return Vec::new();
    }
    let severity = if lines.len() >= 5 {
        Severity::Watch
    } else {
        Severity::Info
    };
    vec![Finding::new(
        "logs.coredumps",
        severity,
        format!("7 天内 {} 个核心转储", lines.len()),
        "核心转储说明进程崩溃过；如果对应你常用的应用，值得进一步看堆栈。",
    )
    .tag("logs")
    .evidence_many(lines.iter().rev().take(3).map(|line| line.to_string()))
    .fix(
        Fix::new(
            "查看最近一次崩溃",
            vec!["coredumpctl info".into()],
            Risk::Low,
        )
        .manual(),
    )]
}
