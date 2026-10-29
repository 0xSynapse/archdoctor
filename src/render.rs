use std::collections::BTreeSet;

use anyhow::Result;
use serde::Serialize;

use crate::diff::DiffReport;
use crate::finding::{Finding, Severity, TimeProfile};
use crate::journal::Signature;
use crate::state::Snapshot;
use crate::util::{fmt_datetime, fmt_short, sanitize_line};

#[derive(Debug, Clone, Copy)]
pub struct RenderOpts {
    pub color: bool,
}

struct Paint {
    enabled: bool,
}

impl Paint {
    fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn code(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.code("1", text)
    }

    fn dim(&self, text: &str) -> String {
        self.code("2", text)
    }

    fn red(&self, text: &str) -> String {
        self.code("1;31", text)
    }

    fn yellow(&self, text: &str) -> String {
        self.code("33", text)
    }

    fn cyan(&self, text: &str) -> String {
        self.code("36", text)
    }

    fn green(&self, text: &str) -> String {
        self.code("32", text)
    }

    fn severity(&self, severity: Severity, text: &str) -> String {
        match severity {
            Severity::Action => self.red(text),
            Severity::Watch => self.yellow(text),
            Severity::Info => self.cyan(text),
        }
    }
}

pub fn scan(snapshot: &Snapshot, diff: Option<&DiffReport>, opts: RenderOpts) {
    let paint = Paint::new(opts.color);
    let new_ids: BTreeSet<&str> = diff
        .map(|diff| {
            diff.new_findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect()
        })
        .unwrap_or_default();

    println!(
        "{} {} · {} · {} · {:.1}s",
        paint.bold("archdoctor"),
        env!("CARGO_PKG_VERSION"),
        snapshot.host,
        fmt_datetime(&snapshot.timestamp),
        snapshot.duration_ms as f64 / 1000.0
    );

    let action = snapshot.count(Severity::Action);
    let watch = snapshot.count(Severity::Watch);
    let info = snapshot.count(Severity::Info);
    println!(
        "{}   {}   {}   {}",
        paint.severity(Severity::Action, &format!("需要处理 {action}")),
        paint.severity(Severity::Watch, &format!("值得关注 {watch}")),
        paint.severity(Severity::Info, &format!("提示 {info}")),
        paint.green(&format!("通过 {}", snapshot.checks_passed))
    );

    if let Some(diff) = diff {
        let mut parts = Vec::new();
        if !diff.new_findings.is_empty() {
            parts.push(paint.red(&format!("+{} 新问题", diff.new_findings.len())));
        }
        if !diff.resolved_findings.is_empty() {
            parts.push(paint.green(&format!("-{} 已解决", diff.resolved_findings.len())));
        }
        if !diff.metric_changes.is_empty() {
            let disk = diff
                .metric_changes
                .iter()
                .find(|change| change.label == "磁盘使用率");
            if let Some(change) = disk {
                parts.push(format!(
                    "磁盘 {} → {}",
                    change.formatted_before(),
                    change.formatted_after()
                ));
            }
        }
        if !parts.is_empty() {
            println!(
                "{}",
                paint.dim(&format!(
                    "较上次（{}）: {}",
                    fmt_short(&diff.from),
                    parts.join(" · ")
                ))
            );
        }
    }
    println!();

    let sections = [
        (Severity::Action, "需要处理"),
        (Severity::Watch, "值得关注"),
        (Severity::Info, "提示"),
    ];
    let mut printed_any = false;
    for (severity, title) in sections {
        let findings: Vec<&Finding> = snapshot
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .collect();
        if findings.is_empty() {
            continue;
        }
        printed_any = true;
        println!("{}", paint.severity(severity, title));
        for finding in findings {
            print_finding(&paint, finding, new_ids.contains(finding.id.as_str()));
        }
        println!();
    }
    if !printed_any {
        println!("{}", paint.green("✓ 没有发现需要处理的问题"));
        println!();
    }

    if snapshot.ignored > 0 {
        println!(
            "{}",
            paint.dim(&format!(
                "已忽略 {} 项（archdoctor ignore --list）",
                snapshot.ignored
            ))
        );
    }
    println!(
        "{}",
        paint.dim("→ archdoctor diff 查看变化 · archdoctor explain <关键词> 查看证据")
    );
}

fn print_finding(paint: &Paint, finding: &Finding, is_new: bool) {
    let marker = paint.severity(finding.severity, "●");
    let new = if is_new {
        format!(" {}", paint.red("[NEW]"))
    } else {
        String::new()
    };
    println!("  {marker} {}{new}", paint.bold(&finding.title));
    println!("    {}", finding.summary);
    if let Some(time) = &finding.time {
        println!("    {}", paint.dim(&time_line(time)));
    }
    for line in finding.evidence.iter().take(12) {
        println!("    {} {}", paint.dim("·"), paint.dim(&truncate(line, 180)));
    }
    if let Some(fix) = &finding.fix {
        for command in &fix.commands {
            let manual = if fix.manual {
                paint.dim("（手动）")
            } else {
                String::new()
            };
            println!("    {} {}{manual}", paint.cyan("→"), command);
        }
        println!(
            "    {}",
            paint.dim(&format!(
                "风险 {} · {}",
                fix.risk.label_zh(),
                fix.description
            ))
        );
    }
    println!();
}

fn time_line(time: &TimeProfile) -> String {
    let mut parts = vec![
        format!("{} 条", time.count),
        time.kind.label_zh().to_string(),
    ];
    if let (Some(first), Some(last)) = (&time.first, &time.last) {
        parts.push(format!("{first} → {last}"));
    }
    if time.days > 1 {
        parts.push(format!("跨 {} 天", time.days));
    }
    if time.boots > 1 {
        parts.push(format!("{} 次启动", time.boots));
    }
    if time.is_new {
        parts.push("新出现".to_string());
    }
    parts.join(" · ")
}

pub fn diff(report: &DiffReport, opts: RenderOpts) {
    let paint = Paint::new(opts.color);
    println!(
        "{}  {} → {}",
        paint.bold("与上次体检相比"),
        fmt_datetime(&report.from),
        fmt_datetime(&report.to)
    );
    println!();

    if report.new_findings.is_empty()
        && report.resolved_findings.is_empty()
        && report.severity_changed.is_empty()
        && report.new_signatures.is_empty()
        && report.metric_changes.is_empty()
    {
        println!("{}", paint.green("没有变化。"));
        return;
    }

    if !report.new_findings.is_empty() {
        println!(
            "{}",
            paint.red(&format!("新出现 {}", report.new_findings.len()))
        );
        for finding in &report.new_findings {
            println!(
                "  {} [{}] {}",
                paint.red("+"),
                paint.severity(finding.severity, finding.severity.label_zh()),
                finding.title
            );
        }
        println!();
    }
    if !report.resolved_findings.is_empty() {
        println!(
            "{}",
            paint.green(&format!("已解决 {}", report.resolved_findings.len()))
        );
        for finding in &report.resolved_findings {
            println!(
                "  {} [{}] {}",
                paint.green("-"),
                paint.dim(finding.severity.label_zh()),
                finding.title
            );
        }
        println!();
    }
    if !report.severity_changed.is_empty() {
        println!("{}", paint.bold("严重度变化"));
        for change in &report.severity_changed {
            println!(
                "  {} {}: {} → {}",
                paint.yellow("~"),
                change.finding.title,
                change.before.label_zh(),
                change.after.label_zh()
            );
        }
        println!();
    }
    if !report.new_signatures.is_empty() {
        println!("{}", paint.bold("新错误签名"));
        for sig in report.new_signatures.iter().take(5) {
            println!(
                "  {} {} ×{} · {}",
                paint.red("+"),
                sig.sample,
                sig.count,
                sig.first.map(|t| fmt_short(&t)).unwrap_or_default()
            );
        }
        println!();
    }
    if !report.metric_changes.is_empty() {
        println!("{}", paint.bold("指标变化"));
        for change in &report.metric_changes {
            let tag = match change.improved {
                Some(true) => paint.green("改善"),
                Some(false) => paint.red("变差"),
                None => paint.dim("变化"),
            };
            println!(
                "  {}: {} → {} ({}) {}",
                change.label,
                change.formatted_before(),
                change.formatted_after(),
                change.formatted_delta(),
                tag
            );
        }
    }
}

pub fn explain(
    query: &str,
    findings: &[&Finding],
    signatures: &[&Signature],
    raw: &str,
    opts: RenderOpts,
) {
    let paint = Paint::new(opts.color);
    println!("{} {}", paint.bold("解释:"), query);
    println!();

    if !findings.is_empty() {
        println!(
            "{}",
            paint.bold(&format!("匹配 {} 个体检项", findings.len()))
        );
        for finding in findings {
            print_finding(
                &paint,
                finding,
                finding.time.as_ref().is_some_and(|t| t.is_new),
            );
        }
    }
    if !signatures.is_empty() {
        println!("{}", paint.bold("匹配的日志签名"));
        for sig in signatures.iter().take(8) {
            println!(
                "  {} {} ×{} · {} · {} → {}",
                paint.cyan("·"),
                sig.sample,
                sig.count,
                sig.kind.label_zh(),
                sig.first.map(|t| fmt_short(&t)).unwrap_or_default(),
                sig.last.map(|t| fmt_short(&t)).unwrap_or_default()
            );
        }
        println!();
    }
    if !raw.trim().is_empty() {
        println!("{}", paint.bold("原始日志（最近 20 条）"));
        for line in raw
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            println!("  {}", paint.dim(line));
        }
        println!();
    }
    if findings.is_empty() && signatures.is_empty() && raw.trim().is_empty() {
        println!("没有找到匹配项。");
        println!(
            "{}",
            paint
                .dim("可以试试更短的关键词，或直接 journalctl --since '7 days ago' -g '<pattern>'")
        );
    }
}

pub fn checks(list: &[(&str, &str)], opts: RenderOpts) {
    let paint = Paint::new(opts.color);
    println!("{}", paint.bold("可用检查"));
    for (id, description) in list {
        println!("  {:<32} {}", paint.cyan(id), description);
    }
}

pub fn to_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

fn truncate(value: &str, max: usize) -> String {
    let value = sanitize_line(value);
    if value.chars().count() <= max {
        value
    } else {
        let mut out: String = value.chars().take(max).collect();
        out.push('…');
        out
    }
}
