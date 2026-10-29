use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Severity};
use crate::journal::Signature;
use crate::util::now;

pub const SNAPSHOT_VERSION: u32 = 1;
const MAX_SNAPSHOTS: usize = 100;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_used_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_avail_gib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pacman_cache_mib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphans: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphan_mib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baloo_mib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_mib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_mib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_packages: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_packages: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_units: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_errors_7d: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub timestamp: DateTime<Local>,
    pub host: String,
    pub running_kernel: String,
    pub duration_ms: u64,
    pub checks_total: usize,
    pub checks_passed: usize,
    #[serde(default)]
    pub ignored: usize,
    pub findings: Vec<Finding>,
    pub metrics: Metrics,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

impl Snapshot {
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }
}

pub fn state_dir() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".local/state"));
    base.join("archdoctor")
}

pub fn config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".config"));
    base.join("archdoctor")
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn save(base: &Path, snapshot: &Snapshot) -> Result<PathBuf> {
    let snapshots = base.join("snapshots");
    fs::create_dir_all(&snapshots)
        .with_context(|| format!("创建快照目录失败: {}", snapshots.display()))?;
    let stamp = snapshot.timestamp.format("%Y%m%dT%H%M%S%9f").to_string();
    let path = snapshots.join(format!("{stamp}.json"));
    let json = serde_json::to_string_pretty(snapshot)?;
    fs::write(&path, &json)?;
    fs::write(base.join("latest.json"), &json)?;
    prune(&snapshots, MAX_SNAPSHOTS)?;
    Ok(path)
}

pub fn load_latest(base: &Path) -> Option<Snapshot> {
    let path = base.join("latest.json");
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&raw) {
            return Some(snapshot);
        }
    }
    load_snapshots(base).pop()
}

pub fn load_snapshots(base: &Path) -> Vec<Snapshot> {
    let dir = base.join("snapshots");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            fs::read_to_string(path)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
        })
        .collect()
}

#[allow(dead_code)]
pub fn load_previous(base: &Path) -> Option<Snapshot> {
    let snapshots = load_snapshots(base);
    if snapshots.len() >= 2 {
        Some(snapshots[snapshots.len() - 2].clone())
    } else {
        None
    }
}

fn prune(dir: &Path, keep: usize) -> Result<()> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    if paths.len() > keep {
        for path in &paths[..paths.len() - keep] {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnoreRule {
    pub id: String,
    #[serde(default)]
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Local>>,
}

impl IgnoreRule {
    pub fn active(&self, at: DateTime<Local>) -> bool {
        self.until.is_none_or(|until| until > at)
    }

    pub fn matches(&self, id: &str) -> bool {
        if let Some(prefix) = self.id.strip_suffix('*') {
            id.starts_with(prefix)
        } else {
            self.id == id
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub rules: Vec<IgnoreRule>,
}

pub fn ignore_path(base: &Path) -> PathBuf {
    base.join("ignore.json")
}

pub fn load_ignore(base: &Path) -> IgnoreConfig {
    fs::read_to_string(ignore_path(base))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save_ignore(base: &Path, config: &IgnoreConfig) -> Result<()> {
    fs::create_dir_all(base)?;
    fs::write(ignore_path(base), serde_json::to_string_pretty(config)?)?;
    Ok(())
}

pub fn filter_ignored(
    findings: Vec<Finding>,
    config: &IgnoreConfig,
    at: DateTime<Local>,
) -> (Vec<Finding>, usize) {
    let active: Vec<&IgnoreRule> = config.rules.iter().filter(|rule| rule.active(at)).collect();
    let mut kept = Vec::new();
    let mut ignored = 0;
    for finding in findings {
        if active.iter().any(|rule| rule.matches(&finding.id)) {
            ignored += 1;
        } else {
            kept.push(finding);
        }
    }
    (kept, ignored)
}

#[allow(clippy::too_many_arguments)]
pub fn new_snapshot(
    host: String,
    running_kernel: String,
    duration_ms: u64,
    checks_total: usize,
    checks_passed: usize,
    ignored: usize,
    findings: Vec<Finding>,
    metrics: Metrics,
    signatures: Vec<Signature>,
) -> Snapshot {
    Snapshot {
        version: SNAPSHOT_VERSION,
        timestamp: now(),
        host,
        running_kernel,
        duration_ms,
        checks_total,
        checks_passed,
        ignored,
        findings,
        metrics,
        signatures,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Local>,
    pub check_id: String,
    pub command: String,
    pub exit_code: Option<i32>,
    pub dry_run: bool,
}

pub fn append_audit(base: &Path, entry: &AuditEntry) -> Result<()> {
    use std::io::Write;
    fs::create_dir_all(base)?;
    let path = base.join("audit.jsonl");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(file, "{}", serde_json::to_string(entry)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use tempfile::tempdir;

    fn sample_finding(id: &str) -> Finding {
        Finding::new(id, Severity::Watch, "test", "test")
    }

    #[test]
    fn snapshot_roundtrip_and_previous() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let mut snap = new_snapshot(
            "host".into(),
            "6.1".into(),
            10,
            3,
            2,
            0,
            vec![sample_finding("a")],
            Metrics::default(),
            Vec::new(),
        );
        snap.timestamp = Local::now() - chrono::Duration::seconds(2);
        save(base, &snap).unwrap();
        let mut snap2 = snap.clone();
        snap2.timestamp = Local::now();
        snap2.findings = vec![sample_finding("b")];
        save(base, &snap2).unwrap();

        assert_eq!(load_latest(base).unwrap().findings[0].id, "b");
        assert_eq!(load_previous(base).unwrap().findings[0].id, "a");
        assert_eq!(load_snapshots(base).len(), 2);
    }

    #[test]
    fn ignore_prefix_and_expiry() {
        let now = Local::now();
        let config = IgnoreConfig {
            rules: vec![
                IgnoreRule {
                    id: "boot.failed_unit:*".into(),
                    reason: String::new(),
                    until: None,
                },
                IgnoreRule {
                    id: "expired".into(),
                    reason: String::new(),
                    until: Some(now - chrono::Duration::days(1)),
                },
            ],
        };
        let (kept, ignored) = filter_ignored(
            vec![
                sample_finding("boot.failed_unit:foo.service"),
                sample_finding("expired"),
                sample_finding("other"),
            ],
            &config,
            now,
        );
        assert_eq!(ignored, 1);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|f| f.id == "expired"));
    }
}
