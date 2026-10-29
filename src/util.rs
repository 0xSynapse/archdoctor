use std::process::Command;

use chrono::{DateTime, Local, TimeZone, Utc};

/// Run a shell command and return (success, stdout, stderr).
pub fn sh(cmd: &str) -> (bool, String, String) {
    match Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("LC_ALL", "C")
        .output()
    {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
            String::from_utf8_lossy(&out.stderr).trim_end().to_string(),
        ),
        Err(err) => (false, String::new(), err.to_string()),
    }
}

/// Run a shell command, returning stdout only when it succeeded.
pub fn sh_ok(cmd: &str) -> Option<String> {
    let (ok, out, _) = sh(cmd);
    ok.then_some(out)
}

/// Run a shell command and return non-empty output lines regardless of exit code.
pub fn sh_lines(cmd: &str) -> Vec<String> {
    let (_, out, _) = sh(cmd);
    out.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn sh_trim(cmd: &str) -> Option<String> {
    let (ok, out, _) = sh(cmd);
    let out = out.trim().to_string();
    if ok && !out.is_empty() {
        Some(out)
    } else {
        None
    }
}

pub fn which(bin: &str) -> bool {
    sh(&format!("command -v {} >/dev/null 2>&1", shell_quote(bin))).0
}

/// Quote a value for safe interpolation into `sh -c`.
pub fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Format a MiB value using binary units.
/// Remove control characters so untrusted log lines cannot mess up the terminal.
pub fn sanitize_line(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else if c.is_control() {
                '?'
            } else {
                c
            }
        })
        .collect()
}

pub fn human_mib(mib: f64) -> String {
    if mib >= 1024.0 * 1024.0 {
        format!("{:.1} TiB", mib / 1024.0 / 1024.0)
    } else if mib >= 1024.0 {
        format!("{:.1} GiB", mib / 1024.0)
    } else {
        format!("{mib:.0} MiB")
    }
}

pub fn human_secs(secs: f64) -> String {
    if secs >= 60.0 {
        format!("{:.0}m {:.0}s", (secs / 60.0).floor(), secs % 60.0)
    } else {
        format!("{secs:.1}s")
    }
}

/// Parse pacman-style sizes such as "101.44 MiB", "194.2M", "1.2 GiB".
pub fn parse_size_mib(raw: &str) -> Option<f64> {
    let raw = raw.trim();
    let split = raw
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(raw.len());
    let (number, unit) = raw.split_at(split);
    let value: f64 = number.trim().parse().ok()?;
    let unit = unit.trim().to_ascii_lowercase();
    let factor = match unit.as_str() {
        "b" | "" => 1.0 / 1024.0 / 1024.0,
        "k" | "kib" | "kb" => 1.0 / 1024.0,
        "m" | "mib" | "mb" => 1.0,
        "g" | "gib" | "gb" => 1024.0,
        "t" | "tib" | "tb" => 1024.0 * 1024.0,
        _ => return None,
    };
    Some(value * factor)
}

pub fn parse_percent(raw: &str) -> Option<f64> {
    raw.trim().trim_end_matches('%').parse().ok()
}

pub fn now() -> DateTime<Local> {
    Local::now()
}

pub fn fmt_datetime(dt: &DateTime<Local>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn fmt_short(dt: &DateTime<Local>) -> String {
    dt.format("%m-%d %H:%M").to_string()
}

pub fn micros_to_local(micros: i64) -> Option<DateTime<Local>> {
    Utc.timestamp_micros(micros)
        .single()
        .map(|dt| dt.with_timezone(&Local))
}

pub fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parser_handles_units() {
        assert!((parse_size_mib("101.44 MiB").unwrap() - 101.44).abs() < 0.01);
        assert!((parse_size_mib("1.5 GiB").unwrap() - 1536.0).abs() < 0.01);
        assert!((parse_size_mib("512 KiB").unwrap() - 0.5).abs() < 0.01);
        assert!((parse_size_mib("194.2M").unwrap() - 194.2).abs() < 0.01);
    }

    #[test]
    fn quoting_is_safe() {
        assert_eq!(shell_quote("foo.service"), "foo.service");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_mib(512.0), "512 MiB");
        assert_eq!(human_mib(2048.0), "2.0 GiB");
    }
}
