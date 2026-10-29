use std::collections::BTreeMap;

use chrono::{DateTime, Local};
use serde::Serialize;

use crate::finding::{Finding, Severity};
use crate::journal::Signature;
use crate::state::{Metrics, Snapshot};
use crate::util::human_mib;

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub from: DateTime<Local>,
    pub to: DateTime<Local>,
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub severity_changed: Vec<SeverityChange>,
    pub new_signatures: Vec<Signature>,
    pub metric_changes: Vec<MetricChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeverityChange {
    pub finding: Finding,
    pub before: Severity,
    pub after: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricChange {
    pub label: &'static str,
    pub before: f64,
    pub after: f64,
    pub unit: &'static str,
    pub improved: Option<bool>,
}

impl MetricChange {
    pub fn delta(&self) -> f64 {
        self.after - self.before
    }

    pub fn formatted_before(&self) -> String {
        format_value(self.before, self.unit)
    }

    pub fn formatted_after(&self) -> String {
        format_value(self.after, self.unit)
    }

    pub fn formatted_delta(&self) -> String {
        let delta = self.delta();
        let sign = if delta > 0.0 { "+" } else { "" };
        format!("{sign}{}", format_value(delta, self.unit))
    }
}

pub fn compare(previous: &Snapshot, current: &Snapshot) -> DiffReport {
    let previous_map: BTreeMap<&str, &Finding> = previous
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect();
    let current_map: BTreeMap<&str, &Finding> = current
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect();

    let mut new_findings = Vec::new();
    let mut severity_changed = Vec::new();
    for finding in &current.findings {
        match previous_map.get(finding.id.as_str()) {
            None => new_findings.push(finding.clone()),
            Some(old) if old.severity != finding.severity => {
                severity_changed.push(SeverityChange {
                    finding: finding.clone(),
                    before: old.severity,
                    after: finding.severity,
                });
            }
            _ => {}
        }
    }
    let resolved_findings = previous
        .findings
        .iter()
        .filter(|finding| !current_map.contains_key(finding.id.as_str()))
        .cloned()
        .collect();

    let previous_signatures: std::collections::BTreeSet<&str> = previous
        .signatures
        .iter()
        .map(|sig| sig.key.as_str())
        .collect();
    let new_signatures = current
        .signatures
        .iter()
        .filter(|sig| !previous_signatures.contains(sig.key.as_str()))
        .take(10)
        .cloned()
        .collect();

    let metric_changes = metric_changes(&previous.metrics, &current.metrics);

    DiffReport {
        from: previous.timestamp,
        to: current.timestamp,
        new_findings,
        resolved_findings,
        severity_changed,
        new_signatures,
        metric_changes,
    }
}

fn metric_changes(before: &Metrics, after: &Metrics) -> Vec<MetricChange> {
    let mut changes = Vec::new();
    push(
        &mut changes,
        "磁盘使用率",
        before.disk_used_pct,
        after.disk_used_pct,
        "%",
        Some(false),
    );
    push(
        &mut changes,
        "磁盘剩余",
        before.disk_avail_gib,
        after.disk_avail_gib,
        "GiB",
        Some(true),
    );
    push(
        &mut changes,
        "启动耗时",
        before.boot_seconds,
        after.boot_seconds,
        "s",
        Some(false),
    );
    push(
        &mut changes,
        "pacman 缓存",
        before.pacman_cache_mib,
        after.pacman_cache_mib,
        "MiB",
        Some(false),
    );
    push(
        &mut changes,
        "孤儿包",
        before.orphans.map(|v| v as f64),
        after.orphans.map(|v| v as f64),
        "个",
        Some(false),
    );
    push(
        &mut changes,
        "孤儿包体积",
        before.orphan_mib,
        after.orphan_mib,
        "MiB",
        Some(false),
    );
    push(
        &mut changes,
        "baloo 索引",
        before.baloo_mib,
        after.baloo_mib,
        "MiB",
        Some(false),
    );
    push(
        &mut changes,
        "用户缓存",
        before.cache_mib,
        after.cache_mib,
        "MiB",
        Some(false),
    );
    push(
        &mut changes,
        "journal",
        before.journal_mib,
        after.journal_mib,
        "MiB",
        Some(false),
    );
    push(
        &mut changes,
        "显式安装包",
        before.explicit_packages.map(|v| v as f64),
        after.explicit_packages.map(|v| v as f64),
        "个",
        None,
    );
    push(
        &mut changes,
        "AUR/外部包",
        before.foreign_packages.map(|v| v as f64),
        after.foreign_packages.map(|v| v as f64),
        "个",
        None,
    );
    push(
        &mut changes,
        "失败单元",
        before.failed_units.map(|v| v as f64),
        after.failed_units.map(|v| v as f64),
        "个",
        Some(false),
    );
    push(
        &mut changes,
        "错误日志",
        before.journal_errors_7d.map(|v| v as f64),
        after.journal_errors_7d.map(|v| v as f64),
        "条",
        Some(false),
    );
    changes
}

fn push(
    changes: &mut Vec<MetricChange>,
    label: &'static str,
    before: Option<f64>,
    after: Option<f64>,
    unit: &'static str,
    higher_is_better: Option<bool>,
) {
    let (Some(before), Some(after)) = (before, after) else {
        return;
    };
    let epsilon = match unit {
        "%" => 0.5,
        "MiB" => 50.0,
        "GiB" => 1.0,
        "s" => 0.5,
        _ => 0.5,
    };
    if (after - before).abs() < epsilon {
        return;
    }
    let improved = higher_is_better.map(|higher| {
        if higher {
            after > before
        } else {
            after < before
        }
    });
    changes.push(MetricChange {
        label,
        before,
        after,
        unit,
        improved,
    });
}

fn format_value(value: f64, unit: &str) -> String {
    match unit {
        "%" => format!("{value:.0}%"),
        "s" => format!("{value:.1}s"),
        "MiB" => human_mib(value),
        "GiB" => format!("{value:.1} GiB"),
        "个" => format!("{value:.0} 个"),
        "条" => format!("{value:.0} 条"),
        _ => format!("{value:.1} {unit}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::state::new_snapshot;

    #[test]
    fn diff_detects_new_and_resolved() {
        let mut before = new_snapshot(
            "h".into(),
            "k".into(),
            1,
            2,
            1,
            0,
            vec![Finding::new("a", Severity::Watch, "a", "a")],
            Metrics::default(),
            Vec::new(),
        );
        before.timestamp = Local::now() - chrono::Duration::hours(1);
        let after = new_snapshot(
            "h".into(),
            "k".into(),
            1,
            2,
            1,
            0,
            vec![Finding::new("b", Severity::Action, "b", "b")],
            Metrics::default(),
            Vec::new(),
        );
        let diff = compare(&before, &after);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].id, "b");
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.resolved_findings[0].id, "a");
    }
}
