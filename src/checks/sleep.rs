use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::journal::merge_time;
use crate::util::fmt_short;

pub fn suspend_errors(ctx: &Context) -> Vec<Finding> {
    let signatures: Vec<&crate::journal::Signature> = ctx
        .journal
        .signatures
        .iter()
        .filter(|sig| {
            let haystack = format!("{} {}", sig.sample, sig.identifier).to_lowercase();
            haystack.contains("pm: suspend")
                || haystack.contains("pm: resume")
                || haystack.contains("pm: hibernat")
                || haystack.contains("freezing of tasks")
                || haystack.contains("systemd-sleep")
                || (haystack.contains("acpi") && haystack.contains("sleep"))
                || haystack.contains("wakeup")
                || (haystack.contains("kernel: pm:") && haystack.contains("suspend"))
        })
        .collect();
    let total = crate::journal::JournalData::sum_count(&signatures);
    if total == 0 {
        return Vec::new();
    }
    let time = merge_time(&signatures);
    let chronic = time
        .as_ref()
        .is_some_and(|t| t.kind == crate::finding::TimeKind::Chronic);
    let severity = if total >= 5 || chronic {
        Severity::Watch
    } else {
        Severity::Info
    };
    let top: Vec<_> = signatures.into_iter().take(4).collect();
    let examples = top
        .iter()
        .map(|sig| {
            format!(
                "{} ×{} · {} → {}",
                sig.sample,
                sig.count,
                sig.first.map(|t| fmt_short(&t)).unwrap_or_default(),
                sig.last.map(|t| fmt_short(&t)).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    vec![Finding::new(
        "sleep.suspend_errors",
        severity,
        format!("挂起/唤醒错误 {total} 条（7 天）"),
        "如果出现睡眠后唤不醒、风扇狂转或设备失效，这些 PM/ACPI 日志就是线索；单条错误不一定代表失败。",
    )
    .tag("sleep")
    .evidence_many(examples)
    .evidence(format!(
        "/sys/power/mem_sleep: {}",
        if ctx.mem_sleep.is_empty() {
            "不可用"
        } else {
            ctx.mem_sleep.as_str()
        }
    ))
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
            "查看完整的挂起/唤醒时间线",
            vec![
                "journalctl -b -g 'PM:|suspend|resume|hibernate|Freezing of tasks' --no-pager -n 120".into(),
                "cat /sys/power/mem_sleep".into(),
                "cat /proc/cmdline".into(),
            ],
            Risk::Low,
        )
        .manual(),
    )]
}
