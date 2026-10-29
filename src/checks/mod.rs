use crate::context::Context;
use crate::finding::Finding;

pub mod audio;
pub mod boot;
pub mod desktop;
pub mod disk;
pub mod logs;
pub mod network;
pub mod pacman;
pub mod security;
pub mod sleep;

#[derive(Clone, Copy)]
pub struct CheckDef {
    pub id: &'static str,
    pub description: &'static str,
    pub run: fn(&Context) -> Vec<Finding>,
}

pub struct CheckResult {
    pub id: &'static str,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
}

pub fn all() -> Vec<CheckDef> {
    vec![
        CheckDef {
            id: "boot.kernel_pending",
            description: "运行内核与已安装内核是否一致",
            run: boot::kernel_pending,
        },
        CheckDef {
            id: "boot.failed_units",
            description: "systemd 系统/用户失败单元",
            run: boot::failed_units,
        },
        CheckDef {
            id: "boot.initramfs_stale",
            description: "initramfs 是否落后于内核镜像",
            run: boot::initramfs_stale,
        },
        CheckDef {
            id: "boot.boot_time",
            description: "启动耗时与回归",
            run: boot::boot_time,
        },
        CheckDef {
            id: "boot.efi_space",
            description: "EFI / boot 分区空间",
            run: boot::efi_space,
        },
        CheckDef {
            id: "boot.tainted",
            description: "内核 taint 标记",
            run: boot::tainted,
        },
        CheckDef {
            id: "audio.stack",
            description: "PipeWire / WirePlumber / Bluetooth 服务状态",
            run: audio::stack,
        },
        CheckDef {
            id: "audio.bluetooth_errors",
            description: "蓝牙与无线音频错误聚类",
            run: audio::bluetooth_errors,
        },
        CheckDef {
            id: "disk.usage",
            description: "磁盘与 inode 使用率",
            run: disk::usage,
        },
        CheckDef {
            id: "disk.pacman_cache",
            description: "pacman 包缓存体积",
            run: disk::pacman_cache,
        },
        CheckDef {
            id: "disk.journal_size",
            description: "systemd journal 体积",
            run: disk::journal_size,
        },
        CheckDef {
            id: "disk.user_cache",
            description: "用户缓存目录体积",
            run: disk::user_cache,
        },
        CheckDef {
            id: "disk.orphans",
            description: "孤儿包数量与体积",
            run: disk::orphans,
        },
        CheckDef {
            id: "disk.baloo",
            description: "KDE baloo 索引体积",
            run: disk::baloo,
        },
        CheckDef {
            id: "disk.trim",
            description: "SSD TRIM 配置",
            run: disk::trim,
        },
        CheckDef {
            id: "disk.docker",
            description: "Docker 可回收空间",
            run: disk::docker,
        },
        CheckDef {
            id: "desktop.kde_errors",
            description: "KDE / Plasma 错误日志",
            run: desktop::kde_errors,
        },
        CheckDef {
            id: "network.connectivity",
            description: "默认路由、网关与 DNS",
            run: network::connectivity,
        },
        CheckDef {
            id: "network.wifi_errors",
            description: "Wi-Fi / NetworkManager 错误聚类",
            run: network::wifi_errors,
        },
        CheckDef {
            id: "sleep.suspend_errors",
            description: "挂起 / 唤醒错误",
            run: sleep::suspend_errors,
        },
        CheckDef {
            id: "logs.error_signatures",
            description: "通用错误日志聚类",
            run: logs::error_signatures,
        },
        CheckDef {
            id: "logs.oom",
            description: "OOM kill",
            run: logs::oom,
        },
        CheckDef {
            id: "logs.coredumps",
            description: "用户态核心转储",
            run: logs::coredumps,
        },
        CheckDef {
            id: "pacman.pacnew",
            description: "未合并的 .pacnew / .pacsave",
            run: pacman::pacnew,
        },
        CheckDef {
            id: "pacman.mirrorlist",
            description: "镜像列表新鲜度",
            run: pacman::mirrorlist,
        },
        CheckDef {
            id: "pacman.keyring",
            description: "keyring / 签名信任错误",
            run: pacman::keyring,
        },
        CheckDef {
            id: "security.ssl_private",
            description: "/etc/ssl/private 权限",
            run: security::ssl_private,
        },
        CheckDef {
            id: "security.firewall",
            description: "防火墙状态",
            run: security::firewall,
        },
    ]
}

pub fn run_all(ctx: &Context) -> Vec<CheckResult> {
    let checks = all();
    let mut results = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for check in checks {
            handles.push((check, scope.spawn(move || (check.run)(ctx))));
        }
        for (check, handle) in handles {
            match handle.join() {
                Ok(findings) => results.push(CheckResult {
                    id: check.id,
                    findings,
                    error: None,
                }),
                Err(_) => results.push(CheckResult {
                    id: check.id,
                    findings: Vec::new(),
                    error: Some("检查线程崩溃".to_string()),
                }),
            }
        }
    });
    results.sort_by_key(|result| result.id);
    results
}
