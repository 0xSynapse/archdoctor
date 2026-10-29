use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::time::Instant;

use anyhow::{bail, Result};
use chrono::Duration;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::checks::{self, CheckResult};
use crate::context::Context;
use crate::diff::{self, DiffReport};
use crate::finding::{Finding, Severity};
use crate::fix::{self, FixOpts};
use crate::journal::Signature;
use crate::render::{self, RenderOpts};
use crate::state::{self, IgnoreRule, Metrics, Snapshot};
use crate::util::{now, sh, shell_quote};

#[derive(Parser)]
#[command(
    name = "archdoctor",
    version,
    about = "Arch Linux 体检、历史 diff 与分诊",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// 输出 JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// 禁用颜色
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// 运行体检（默认命令）
    Scan(ScanArgs),
    /// 查看与上次体检的差异
    Diff,
    /// 解释某个问题或日志关键词
    Explain(ExplainArgs),
    /// 交互式修复
    Fix(FixArgs),
    /// 忽略某项检查
    Ignore(IgnoreArgs),
    /// 列出所有检查
    Checks,
}

#[derive(Args)]
pub struct ScanArgs {
    /// 不写入历史快照
    #[arg(long)]
    pub no_save: bool,
}

#[derive(Args)]
pub struct ExplainArgs {
    /// 检查 ID、标题关键词或日志关键词
    pub query: String,
}

#[derive(Args)]
pub struct FixArgs {
    /// 只处理指定检查 ID（支持 prefix*）
    pub id: Option<String>,

    /// 只预览命令，不执行
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args)]
pub struct IgnoreArgs {
    /// 检查 ID（支持 prefix*）
    pub id: Option<String>,

    /// 忽略原因
    #[arg(long)]
    pub reason: Option<String>,

    /// 有效天数；0 表示永久
    #[arg(long, default_value_t = 30)]
    pub days: i64,

    /// 列出忽略规则
    #[arg(long)]
    pub list: bool,

    /// 清空忽略规则
    #[arg(long)]
    pub clear: bool,
}

pub fn run() -> Result<i32> {
    let cli = Cli::parse();
    let color =
        !cli.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    let opts = RenderOpts { color };

    match cli
        .command
        .unwrap_or(Command::Scan(ScanArgs { no_save: false }))
    {
        Command::Scan(args) => run_scan(args, cli.json, opts),
        Command::Diff => run_diff(cli.json, opts),
        Command::Explain(args) => run_explain(args, cli.json, opts),
        Command::Fix(args) => run_fix(args),
        Command::Ignore(args) => run_ignore(args, cli.json),
        Command::Checks => {
            let list: Vec<(&str, &str)> = checks::all()
                .iter()
                .map(|check| (check.id, check.description))
                .collect();
            render::checks(&list, opts);
            Ok(0)
        }
    }
}

#[derive(Serialize)]
struct ScanJson<'a> {
    snapshot: &'a Snapshot,
    diff: Option<&'a DiffReport>,
}

fn run_scan(args: ScanArgs, json: bool, opts: RenderOpts) -> Result<i32> {
    let base = state::state_dir();
    let previous = state::load_latest(&base);
    let start = Instant::now();
    let (ctx, results, mut findings, ignored) = collect(previous.clone());
    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(&b.id)));

    let checks_total = results.len();
    let checks_passed = results
        .iter()
        .filter(|result| result.findings.is_empty() && result.error.is_none())
        .count();
    let failed_units = findings
        .iter()
        .filter(|finding| finding.id.starts_with("boot.failed_"))
        .count();
    let mut metrics: Metrics = ctx.metrics.clone();
    metrics.failed_units = Some(failed_units);
    let signatures: Vec<Signature> = ctx.journal.signatures.iter().take(200).cloned().collect();
    let snapshot = state::new_snapshot(
        ctx.host.clone(),
        ctx.running_kernel.clone(),
        start.elapsed().as_millis() as u64,
        checks_total,
        checks_passed,
        ignored,
        findings,
        metrics,
        signatures,
    );
    let report = previous
        .as_ref()
        .map(|previous| diff::compare(previous, &snapshot));

    if json {
        println!(
            "{}",
            render::to_json(&ScanJson {
                snapshot: &snapshot,
                diff: report.as_ref(),
            })?
        );
    } else {
        render::scan(&snapshot, report.as_ref(), opts);
    }

    for result in &results {
        if let Some(error) = &result.error {
            eprintln!("检查 {} 失败: {error}", result.id);
        }
    }

    if !args.no_save {
        state::save(&base, &snapshot)?;
    }
    Ok(exit_code(&snapshot))
}

fn run_diff(json: bool, opts: RenderOpts) -> Result<i32> {
    let base = state::state_dir();
    let snapshots = state::load_snapshots(&base);
    if snapshots.len() < 2 {
        println!("还没有足够的历史快照；先运行两次 archdoctor scan。");
        return Ok(0);
    }
    let previous = &snapshots[snapshots.len() - 2];
    let current = &snapshots[snapshots.len() - 1];
    let report = diff::compare(previous, current);
    if json {
        println!("{}", render::to_json(&report)?);
    } else {
        render::diff(&report, opts);
    }
    Ok(0)
}

fn run_explain(args: ExplainArgs, json: bool, opts: RenderOpts) -> Result<i32> {
    let base = state::state_dir();
    let previous = state::load_latest(&base);
    let (ctx, _results, findings, _ignored) = collect(previous);
    let terms = expand_query(&args.query);
    let matches: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding_matches(finding, &terms))
        .collect();
    let signatures: Vec<&Signature> = ctx
        .journal
        .signatures
        .iter()
        .filter(|sig| {
            let haystack = format!("{} {}", sig.sample, sig.identifier).to_lowercase();
            terms.iter().any(|term| haystack.contains(term))
        })
        .collect();
    let terms_set: BTreeSet<&str> = terms.iter().map(String::as_str).collect();
    let pattern = terms_set.into_iter().collect::<Vec<_>>().join("|");
    let raw = if pattern.is_empty() {
        String::new()
    } else {
        sh(&format!(
            "journalctl --since '7 days ago' -g {} --no-pager -o short 2>/dev/null | tail -20",
            shell_quote(&pattern)
        ))
        .1
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "query": args.query,
                "findings": matches,
                "signatures": signatures,
                "raw": raw,
            }))?
        );
    } else {
        render::explain(&args.query, &matches, &signatures, &raw, opts);
    }
    Ok(0)
}

fn run_fix(args: FixArgs) -> Result<i32> {
    let base = state::state_dir();
    let previous = state::load_latest(&base);
    let (_ctx, _results, findings, _ignored) = collect(previous);
    let summary = fix::run_interactive(
        &findings,
        &FixOpts {
            dry_run: args.dry_run,
            only: args.id,
        },
        &base,
    )?;
    Ok(if summary.failed > 0 { 1 } else { 0 })
}

fn run_ignore(args: IgnoreArgs, json: bool) -> Result<i32> {
    let base = state::config_dir();
    let mut config = state::load_ignore(&base);

    if args.clear {
        config.rules.clear();
        state::save_ignore(&base, &config)?;
        println!("已清空忽略规则。");
        return Ok(0);
    }
    if args.list {
        if config.rules.is_empty() {
            println!("没有忽略规则。");
        } else if json {
            println!("{}", render::to_json(&config)?);
        } else {
            for rule in &config.rules {
                let until = rule
                    .until
                    .map(|until| until.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "永久".to_string());
                println!(
                    "{} · 到期 {} · {}",
                    rule.id,
                    until,
                    if rule.reason.is_empty() {
                        "无原因"
                    } else {
                        &rule.reason
                    }
                );
            }
        }
        return Ok(0);
    }

    let Some(id) = args.id else {
        bail!("需要提供检查 ID，或使用 --list / --clear");
    };
    let until = if args.days == 0 {
        None
    } else {
        Some(now() + Duration::days(args.days.max(0)))
    };
    config.rules.retain(|rule| rule.id != id);
    config.rules.push(IgnoreRule {
        id: id.clone(),
        reason: args.reason.unwrap_or_else(|| "手动忽略".to_string()),
        until,
    });
    state::save_ignore(&base, &config)?;
    println!("已忽略 {id}。");
    Ok(0)
}

fn collect(previous: Option<Snapshot>) -> (Context, Vec<CheckResult>, Vec<Finding>, usize) {
    let ctx = Context::collect(previous);
    let results = checks::run_all(&ctx);
    let mut findings = Vec::new();
    for result in &results {
        findings.extend(result.findings.clone());
    }
    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(&b.id)));
    let config = state::load_ignore(&state::config_dir());
    let (findings, ignored) = state::filter_ignored(findings, &config, now());
    (ctx, results, findings, ignored)
}

fn exit_code(snapshot: &Snapshot) -> i32 {
    if snapshot.count(Severity::Action) > 0 {
        2
    } else if snapshot.count(Severity::Watch) > 0 {
        1
    } else {
        0
    }
}

fn finding_matches(finding: &Finding, terms: &[String]) -> bool {
    let mut haystack = format!(
        "{} {} {} {}",
        finding.id,
        finding.title,
        finding.summary,
        finding.tags.join(" ")
    )
    .to_lowercase();
    for line in &finding.evidence {
        haystack.push(' ');
        haystack.push_str(&line.to_lowercase());
    }
    terms.iter().any(|term| haystack.contains(term))
}

fn expand_query(query: &str) -> Vec<String> {
    let query = query.trim().to_lowercase();
    let mut terms = vec![query.clone()];
    let aliases: &[(&str, &[&str])] = &[
        ("蓝牙", &["bluetooth", "bluez", "sco", "pipewire"]),
        ("耳机", &["bluetooth", "bluez", "sco", "audio"]),
        ("音频", &["audio", "pipewire", "pulse", "wireplumber"]),
        ("声音", &["audio", "pipewire", "pulse"]),
        ("睡眠", &["suspend", "resume", "hibernate", "sleep"]),
        ("休眠", &["suspend", "resume", "hibernate"]),
        ("唤醒", &["resume", "wake", "suspend"]),
        ("网络", &["network", "wifi", "wlan", "wpa", "dhcp", "dns"]),
        ("无线", &["wifi", "wlan", "wpa", "iwlwifi"]),
        ("磁盘", &["disk", "space", "cache", "baloo", "orphan"]),
        ("空间", &["disk", "space", "cache"]),
        ("启动", &["boot", "kernel", "initramfs", "systemd"]),
        ("内核", &["kernel", "initramfs", "reboot"]),
        ("桌面", &["kde", "plasma", "baloo", "kwin"]),
        ("索引", &["baloo", "index"]),
    ];
    for (needle, values) in aliases {
        if query.contains(needle) {
            for value in *values {
                let value = value.to_string();
                if !terms.contains(&value) {
                    terms.push(value);
                }
            }
        }
    }
    terms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_chinese_aliases() {
        let terms = expand_query("蓝牙耳机");
        assert!(terms.iter().any(|term| term == "bluetooth"));
        assert!(terms.iter().any(|term| term == "bluez"));
    }
}
