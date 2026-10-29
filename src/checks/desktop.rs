use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::journal::{merge_time, Signature};
use crate::util::fmt_short;

pub fn kde_errors(ctx: &Context) -> Vec<Finding> {
    if !ctx.is_kde && ctx.metrics.baloo_mib.is_none() {
        return Vec::new();
    }
    let needles = [
        "plasmashell",
        "kwin",
        "kded",
        "baloo",
        "akonadi",
        "kscreen",
        "plasma",
    ];
    let signatures = ctx.journal.filter(&needles);
    let total = crate::journal::JournalData::sum_count(&signatures);
    if total == 0 {
        return Vec::new();
    }
    let time = merge_time(&signatures);
    let chronic = time
        .as_ref()
        .is_some_and(|t| t.kind == crate::finding::TimeKind::Chronic);
    let severity = if total >= 10 || chronic {
        Severity::Watch
    } else {
        Severity::Info
    };
    let top: Vec<&Signature> = signatures.into_iter().take(4).collect();
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
        "desktop.kde_errors",
        severity,
        format!("KDE/Plasma 错误日志 {total} 条（7 天）"),
        "Plasma、KWin、Baloo 或 Akonadi 的错误可能表现为桌面卡顿、索引异常或托盘图标消失。",
    )
    .tag("desktop")
    .tag("kde")
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
            "查看 KDE 相关日志",
            vec![
                "journalctl --user -b -g 'plasmashell|kwin|baloo|akonadi' --no-pager -n 80".into(),
                "systemctl --user status plasma-plasmashell --no-pager".into(),
            ],
            Risk::Low,
        )
        .manual(),
    )]
}
