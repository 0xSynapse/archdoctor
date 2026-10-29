use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::journal::{merge_time, Signature};
use crate::util::{fmt_short, sh};

pub fn stack(_ctx: &Context) -> Vec<Finding> {
    if !crate::util::which("pipewire") {
        return Vec::new();
    }
    let mut missing = Vec::new();
    for unit in ["pipewire", "pipewire-pulse", "wireplumber"] {
        let status = sh(&format!("systemctl --user is-active {unit} 2>/dev/null")).1;
        if status.trim() != "active" {
            missing.push((unit, status.trim().to_string()));
        }
    }
    if missing.len() == 3 && missing.iter().all(|(_, status)| status.is_empty()) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    if !missing.is_empty() {
        let names = missing
            .iter()
            .map(|(unit, status)| format!("{unit}: {status}"))
            .collect::<Vec<_>>();
        findings.push(
            Finding::new(
                "audio.stack_inactive",
                Severity::Watch,
                "音频栈没有完整运行",
                format!(
                    "以下用户单元未处于 active：{}。声音可能缺失或只有部分应用能出声。",
                    names.join("、")
                ),
            )
            .tag("audio")
            .evidence_many(names)
            .fix(Fix::new(
                "启动 PipeWire 音频栈",
                vec!["systemctl --user start pipewire pipewire-pulse wireplumber".into()],
                Risk::Low,
            )),
        );
    }

    let has_bluetooth =
        crate::util::which("bluetoothctl") || std::path::Path::new("/sys/class/bluetooth").exists();
    if has_bluetooth {
        let status = sh("systemctl is-active bluetooth 2>/dev/null").1;
        if status.trim() != "active" && status.trim() != "unknown" {
            findings.push(
                Finding::new(
                    "audio.bluetooth_inactive",
                    Severity::Info,
                    "Bluetooth 服务未运行",
                    format!(
                        "bluetooth.service 状态为 {}；如果不用蓝牙可忽略。",
                        status.trim()
                    ),
                )
                .tag("audio")
                .tag("bluetooth")
                .evidence(format!("systemctl is-active bluetooth: {}", status.trim()))
                .fix(Fix::new(
                    "启动 Bluetooth 服务",
                    vec!["sudo systemctl start bluetooth".into()],
                    Risk::Low,
                )),
            );
        }
    }
    findings
}

pub fn bluetooth_errors(ctx: &Context) -> Vec<Finding> {
    let needles = [
        "bluetooth",
        "bluez",
        "sco packet",
        "acl packet",
        "raop",
        "bluez_output",
        "bluez_input",
    ];
    let signatures = ctx.journal.filter(&needles);
    let total = crate::journal::JournalData::sum_count(&signatures);
    if total == 0 {
        return Vec::new();
    }
    let time = merge_time(&signatures);
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
    let kind = time
        .as_ref()
        .map(|t| t.kind.label_zh().to_string())
        .unwrap_or_else(|| "偶发".to_string());
    vec![Finding::new(
        "audio.bluetooth_errors",
        Severity::Watch,
        format!("蓝牙/无线音频错误 {total} 条（7 天）"),
        format!(
            "检测到 {kind}的 SCO/BlueZ/PipeWire 错误。若耳机频繁断连、杂音或麦克风异常，先重启音频栈和蓝牙服务。"
        ),
    )
    .tag("audio")
    .tag("bluetooth")
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
    .fix(Fix::new(
        "重启音频栈（会短暂中断声音）",
        vec![
            "systemctl --user restart wireplumber".into(),
            "systemctl --user restart pipewire pipewire-pulse".into(),
            "sudo systemctl restart bluetooth".into(),
        ],
        Risk::Medium,
    ))]
}
