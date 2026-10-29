use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::journal::merge_time;
use crate::util::{fmt_short, sh, sh_ok, which};

pub fn connectivity(_ctx: &Context) -> Vec<Finding> {
    let route = sh("ip route show default 2>/dev/null").1;
    if route.trim().is_empty() {
        let links = sh_ok("ip -br addr 2>/dev/null").unwrap_or_default();
        return vec![Finding::new(
            "network.no_default_route",
            Severity::Watch,
            "没有默认路由",
            "系统当前没有默认网关，外网访问会失败。可能是 Wi-Fi 未连接、NetworkManager 未运行，或接口配置错误。",
        )
        .tag("network")
        .evidence("ip route show default: 空")
        .evidence_many(links.lines().take(6).map(ToOwned::to_owned))
        .fix(
            Fix::new(
                "检查网络管理器与接口",
                vec![
                    "systemctl status NetworkManager --no-pager".into(),
                    "nmcli device status".into(),
                    "ip -br addr".into(),
                ],
                Risk::Low,
            )
            .manual(),
        )];
    }

    let gateway = route
        .split_whitespace()
        .skip_while(|token| *token != "via")
        .nth(1)
        .map(ToOwned::to_owned);
    let mut findings = Vec::new();

    if let Some(gateway) = gateway {
        if which("ping")
            && !sh(&format!(
                "timeout 4s ping -c2 -W1 {gateway} >/dev/null 2>&1"
            ))
            .0
        {
            findings.push(
                Finding::new(
                    "network.gateway_unreachable",
                    Severity::Info,
                    "默认网关没有响应 ICMP",
                    format!("默认网关 {gateway} 没有响应；可能是路由器过滤 ICMP 或 Wi-Fi 省电。如果同时 DNS 失败，才是真问题。"),
                )
                .tag("network")
                .evidence(format!("default route: {}", route.trim()))
                .fix(
                    Fix::new(
                        "检查接口与路由器",
                        vec![
                            "ip -br addr".into(),
                            format!("ping -c3 {gateway}"),
                            "systemctl status NetworkManager --no-pager".into(),
                        ],
                        Risk::Low,
                    )
                    .manual(),
                ),
            );
        }
    }

    if !sh("timeout 3s getent hosts archlinux.org >/dev/null 2>&1").0 {
        let resolv = sh_ok("head -5 /etc/resolv.conf 2>/dev/null").unwrap_or_default();
        findings.push(
            Finding::new(
                "network.dns_failure",
                Severity::Watch,
                "DNS 解析失败",
                "默认路由存在，但无法解析 archlinux.org。常见原因是 resolv.conf、systemd-resolved 或 NetworkManager 的 DNS 配置。",
            )
            .tag("network")
            .evidence("getent hosts archlinux.org: 失败")
            .evidence_many(resolv.lines().take(5).map(ToOwned::to_owned))
            .fix(
                Fix::new(
                    "检查 DNS 配置",
                    vec![
                        "resolvectl status --no-pager".into(),
                        "cat /etc/resolv.conf".into(),
                        "systemctl status systemd-resolved --no-pager".into(),
                    ],
                    Risk::Low,
                )
                .manual(),
            ),
        );
    }
    findings
}

pub fn wifi_errors(ctx: &Context) -> Vec<Finding> {
    let needles = [
        "wpa_supplicant",
        "iwlwifi",
        "ath10k",
        "ath11k",
        "ath12k",
        "mt76",
        "brcmfmac",
        "networkmanager",
        "dhcp",
        "wlan",
        "wifi",
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
    let severity = if total >= 20 || (chronic && total >= 10) {
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
        "network.wifi_errors",
        severity,
        format!("Wi-Fi/NetworkManager 错误 {total} 条（7 天）"),
        "如果表现为断流、重连或速度异常，先看驱动/固件与 NetworkManager 日志；不要在网络正常时盲目重启。",
    )
    .tag("network")
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
            "查看网络日志",
            vec![
                "journalctl -b -g 'wpa_supplicant|iwlwifi|NetworkManager|dhcp' --no-pager -n 80".into(),
                "nmcli device status".into(),
            ],
            Risk::Low,
        )
        .manual(),
    )]
}
