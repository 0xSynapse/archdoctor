use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Result};

use crate::finding::{Finding, Risk};
use crate::state::{append_audit, AuditEntry};
use crate::util::now;

#[derive(Debug, Clone)]
pub struct FixOpts {
    pub dry_run: bool,
    pub only: Option<String>,
}

#[derive(Debug, Default)]
pub struct FixSummary {
    pub applied: usize,
    pub skipped: usize,
    pub failed: usize,
    pub manual: usize,
}

pub fn run_interactive(
    findings: &[Finding],
    opts: &FixOpts,
    state_base: &Path,
) -> Result<FixSummary> {
    let mut candidates: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.fix.is_some())
        .filter(|finding| match &opts.only {
            None => true,
            Some(only) => {
                if let Some(prefix) = only.strip_suffix('*') {
                    finding.id.starts_with(prefix)
                } else {
                    finding.id == *only
                }
            }
        })
        .collect();
    candidates.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(&b.id)));

    if candidates.is_empty() {
        println!("没有可执行的修复项。");
        return Ok(FixSummary::default());
    }
    if !opts.dry_run && !io::stdin().is_terminal() {
        bail!("fix 需要交互终端；用 --dry-run 查看命令");
    }

    println!(
        "{} 个可处理项{}（每项执行前都会确认）\n",
        candidates.len(),
        if opts.dry_run { "，仅预览" } else { "" }
    );

    let mut summary = FixSummary::default();
    for (index, finding) in candidates.iter().enumerate() {
        let Some(fix) = &finding.fix else {
            continue;
        };
        println!("[{}/{}] {}", index + 1, candidates.len(), finding.title);
        println!("  {}", finding.summary);
        for command in &fix.commands {
            println!("  $ {command}");
        }
        println!("  风险 {} · {}", fix.risk.label_zh(), fix.description);
        if fix.risk == Risk::High {
            for line in finding.evidence.iter().take(20) {
                println!("  · {line}");
            }
        }

        if fix.manual {
            println!("  → 此项需要手动执行，已跳过。\n");
            summary.manual += 1;
            continue;
        }
        if opts.dry_run {
            summary.skipped += 1;
            println!();
            continue;
        }

        let prompt = if fix.risk == Risk::High {
            "  高风险操作：输入 yes 确认执行（其他跳过）："
        } else {
            "  执行？[y/N/q] "
        };
        print!("{prompt}");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_ascii_lowercase();
        if answer == "q" {
            println!("已退出。\n");
            summary.skipped += candidates.len() - index;
            break;
        }
        let confirmed = if fix.risk == Risk::High {
            answer == "yes"
        } else {
            answer == "y" || answer == "yes"
        };
        if !confirmed {
            println!("  已跳过。\n");
            summary.skipped += 1;
            continue;
        }

        let mut failed = false;
        for command in &fix.commands {
            let status = Command::new("sh").arg("-c").arg(command).status();
            let exit_code = status.as_ref().ok().and_then(|status| status.code());
            let ok = status.as_ref().is_ok_and(|status| status.success());
            let _ = append_audit(
                state_base,
                &AuditEntry {
                    timestamp: now(),
                    check_id: finding.id.clone(),
                    command: command.clone(),
                    exit_code,
                    dry_run: false,
                },
            );
            if !ok {
                println!("  ✗ 命令失败，停止该项。\n");
                summary.failed += 1;
                failed = true;
                break;
            }
        }
        if !failed {
            summary.applied += 1;
            println!("  ✓ 完成。\n");
        }
    }

    println!(
        "完成：执行 {} · 跳过 {} · 手动 {} · 失败 {}",
        summary.applied, summary.skipped, summary.manual, summary.failed
    );
    println!("建议重新运行：archdoctor scan");
    Ok(summary)
}
