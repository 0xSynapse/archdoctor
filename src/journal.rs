use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use chrono::{DateTime, Local};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::finding::{TimeKind, TimeProfile};
use crate::state::Snapshot;
use crate::util::{fmt_short, micros_to_local, sanitize_line, sh};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub key: String,
    pub sample: String,
    pub identifier: String,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<DateTime<Local>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<DateTime<Local>>,
    pub days: usize,
    pub boots: usize,
    pub kind: TimeKind,
    #[serde(default)]
    pub is_new: bool,
}

#[derive(Debug, Clone, Default)]
pub struct JournalData {
    pub signatures: Vec<Signature>,
    pub total_entries: usize,
}

impl JournalData {
    pub fn filter(&self, needles: &[&str]) -> Vec<&Signature> {
        let needles: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();
        self.signatures
            .iter()
            .filter(|sig| {
                let haystack = format!("{} {}", sig.sample, sig.identifier).to_lowercase();
                needles.iter().any(|needle| haystack.contains(needle))
            })
            .collect()
    }

    pub fn sum_count(signatures: &[&Signature]) -> usize {
        signatures.iter().map(|sig| sig.count).sum()
    }
}

/// Collect priority <= 3 journal messages for the last `days` days and group
/// them into normalized signatures.
pub fn collect(days: u32, previous: Option<&Snapshot>) -> JournalData {
    let previous_keys: BTreeSet<String> = previous
        .map(|snap| snap.signatures.iter().map(|sig| sig.key.clone()).collect())
        .unwrap_or_default();

    let cmd = format!(
        "journalctl --since '{} days ago' -p 3 --no-pager -o json \
         --output-fields=MESSAGE,SYSLOG_IDENTIFIER,_COMM,_SYSTEMD_UNIT,_BOOT_ID,__REALTIME_TIMESTAMP 2>/dev/null",
        days
    );
    let (_, stdout, _) = sh(&cmd);

    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    let mut total_entries = 0usize;

    for line in stdout.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(message) = extract_message(&value) else {
            continue;
        };
        let message = message.trim().to_string();
        if message.is_empty() {
            continue;
        }
        total_entries += 1;

        let identifier = value
            .get("SYSLOG_IDENTIFIER")
            .and_then(Value::as_str)
            .or_else(|| value.get("_COMM").and_then(Value::as_str))
            .unwrap_or("unknown")
            .to_string();
        let unit = value
            .get("_SYSTEMD_UNIT")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let boot = value
            .get("_BOOT_ID")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let time = value
            .get("__REALTIME_TIMESTAMP")
            .and_then(Value::as_str)
            .and_then(|raw| raw.parse::<i64>().ok())
            .and_then(micros_to_local);

        let normalized = normalize(&message);
        let key = format!("{identifier}|{normalized}");
        let entry = acc.entry(key.clone()).or_insert_with(|| Acc {
            key,
            sample: truncate(&message, 220),
            identifier: identifier.clone(),
            count: 0,
            first: time,
            last: time,
            boots: BTreeSet::new(),
            days: BTreeSet::new(),
        });
        entry.count += 1;
        if let Some(t) = time {
            entry.first = Some(entry.first.map_or(t, |old| old.min(t)));
            entry.last = Some(entry.last.map_or(t, |old| old.max(t)));
            entry.days.insert(t.format("%Y-%m-%d").to_string());
        }
        if let Some(boot) = boot {
            entry.boots.insert(boot);
        }
        if let Some(unit) = unit {
            if entry.sample.is_empty() {
                entry.sample = unit;
            }
        }
    }

    let mut signatures: Vec<Signature> = acc
        .into_values()
        .map(|acc| {
            let kind = classify(acc.count, acc.first, acc.last, acc.days.len());
            Signature {
                is_new: previous.is_some() && !previous_keys.contains(&acc.key),
                key: acc.key,
                sample: acc.sample,
                identifier: acc.identifier,
                count: acc.count,
                first: acc.first,
                last: acc.last,
                days: acc.days.len(),
                boots: acc.boots.len(),
                kind,
            }
        })
        .collect();

    signatures.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    JournalData {
        signatures,
        total_entries,
    }
}

#[derive(Debug)]
struct Acc {
    key: String,
    sample: String,
    identifier: String,
    count: usize,
    first: Option<DateTime<Local>>,
    last: Option<DateTime<Local>>,
    boots: BTreeSet<String>,
    days: BTreeSet<String>,
}

fn classify(
    count: usize,
    first: Option<DateTime<Local>>,
    last: Option<DateTime<Local>>,
    day_count: usize,
) -> TimeKind {
    let duration_secs = match (first, last) {
        (Some(a), Some(b)) => (b - a).num_seconds().max(0),
        _ => 0,
    };
    if count >= 3 && duration_secs <= 300 {
        TimeKind::Burst
    } else if day_count >= 2 || (duration_secs >= 3600 && count >= 10) || count >= 50 {
        TimeKind::Chronic
    } else {
        TimeKind::Normal
    }
}

fn extract_message(value: &Value) -> Option<String> {
    match value.get("MESSAGE") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(items)) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(Value::as_u64)
                .map(|b| b as u8)
                .collect();
            Some(String::from_utf8_lossy(&bytes).to_string())
        }
        _ => None,
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let value = sanitize_line(value);
    let mut out: String = value.chars().take(max_chars).collect();
    if value.chars().count() > max_chars {
        out.push('…');
    }
    out
}

fn re<'a>(cell: &'a OnceLock<Regex>, pattern: &str) -> &'a Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

pub fn normalize(message: &str) -> String {
    static MAC: OnceLock<Regex> = OnceLock::new();
    static MAC_UNDERSCORE: OnceLock<Regex> = OnceLock::new();
    static UUID: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static HCI: OnceLock<Regex> = OnceLock::new();
    static BRACKET: OnceLock<Regex> = OnceLock::new();
    static NUMBER: OnceLock<Regex> = OnceLock::new();

    let mut out = message.to_string();
    out = re(&MAC, r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
        .replace_all(&out, "<mac>")
        .to_string();
    out = re(&MAC_UNDERSCORE, r"(?i)\b[0-9a-f]{2}(?:_[0-9a-f]{2}){5}\b")
        .replace_all(&out, "<mac>")
        .to_string();
    out = re(
        &UUID,
        r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    )
    .replace_all(&out, "<uuid>")
    .to_string();
    out = re(&HEX, r"(?i)\b0x[0-9a-f]+\b")
        .replace_all(&out, "<hex>")
        .to_string();
    out = re(&HCI, r"(?i)\bhci[0-9]+\b")
        .replace_all(&out, "hci<N>")
        .to_string();
    out = re(&BRACKET, r"\[\d+\]")
        .replace_all(&out, "[<n>]")
        .to_string();
    out = re(&NUMBER, r"\b\d+(?:\.\d+)?\b")
        .replace_all(&out, "<n>")
        .to_string();
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Combine several signatures into one time profile for a finding.
pub fn merge_time(signatures: &[&Signature]) -> Option<TimeProfile> {
    if signatures.is_empty() {
        return None;
    }
    let count = signatures.iter().map(|sig| sig.count).sum();
    let first = signatures.iter().filter_map(|sig| sig.first).min();
    let last = signatures.iter().filter_map(|sig| sig.last).max();
    let days = match (first, last) {
        (Some(first), Some(last)) => {
            ((last.date_naive() - first.date_naive()).num_days() + 1).max(0) as usize
        }
        _ => signatures.iter().map(|sig| sig.days).max().unwrap_or(0),
    };
    let boots = signatures.iter().map(|sig| sig.boots).max().unwrap_or(0);
    let is_new = signatures.iter().any(|sig| sig.is_new);
    let kind = if signatures.iter().any(|sig| sig.kind == TimeKind::Chronic) {
        TimeKind::Chronic
    } else if signatures.iter().all(|sig| sig.kind == TimeKind::Burst) {
        TimeKind::Burst
    } else {
        TimeKind::Normal
    };
    Some(TimeProfile {
        kind,
        count,
        first: first.map(|dt| fmt_short(&dt)),
        last: last.map(|dt| fmt_short(&dt)),
        days,
        boots,
        is_new,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_volatile_parts() {
        assert_eq!(
            normalize("Bluetooth: hci0: corrupted SCO packet 0xdeadbeef"),
            "Bluetooth: hci<N>: corrupted SCO packet <hex>"
        );
        assert_eq!(
            normalize("device B8:7B:D4:08:FE:0B disconnected"),
            "device <mac> disconnected"
        );
        assert_eq!(
            normalize("worker 12345 failed at 10.5 seconds"),
            "worker <n> failed at <n> seconds"
        );
    }

    #[test]
    fn classifies_burst_and_chronic() {
        let now = Local::now();
        assert_eq!(
            classify(500, Some(now), Some(now + chrono::Duration::seconds(2)), 1),
            TimeKind::Burst
        );
        assert_eq!(
            classify(20, Some(now - chrono::Duration::days(3)), Some(now), 3),
            TimeKind::Chronic
        );
    }
}
