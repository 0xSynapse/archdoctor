use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::context::Context;
use crate::finding::{Finding, Fix, Risk, Severity};
use crate::util::sh;

pub fn ssl_private(_ctx: &Context) -> Vec<Finding> {
    let path = "/etc/ssl/private";
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        return Vec::new();
    }
    vec![Finding::new(
        "security.ssl_private",
        Severity::Watch,
        format!("/etc/ssl/private 权限是 {mode:o}（应为 700）"),
        "这个目录用于存放私钥；其他用户可读会扩大私钥泄露面。Arch 软件包也期望 700。",
    )
    .tag("security")
    .evidence(format!("{path}: {mode:o}（期望 700）"))
    .fix(Fix::new(
        "收紧目录权限",
        vec![format!("sudo chmod 700 {path}")],
        Risk::Low,
    ))]
}

pub fn firewall(_ctx: &Context) -> Vec<Finding> {
    let mut statuses = Vec::new();
    let mut active = false;
    for service in ["nftables", "firewalld", "ufw"] {
        let status = sh(&format!("systemctl is-active {service} 2>/dev/null"))
            .1
            .trim()
            .to_string();
        if status == "active" {
            active = true;
        }
        statuses.push(format!("{service}: {status}"));
    }
    if active {
        return Vec::new();
    }
    vec![Finding::new(
        "security.firewall",
        Severity::Info,
        "未检测到启用的防火墙服务",
        "nftables/firewalld/ufw 都没有 active。桌面在路由器 NAT 后通常可接受；如果经常连公共 Wi-Fi，建议启用一个。",
    )
    .tag("security")
    .tag("network")
    .evidence_many(statuses)
    .fix(
        Fix::new(
            "确认是否需要防火墙（不要盲目套用规则）",
            vec![
                "systemctl status nftables firewalld ufw --no-pager".into(),
                "sudo nft list ruleset".into(),
            ],
            Risk::Low,
        )
        .manual(),
    )]
}
