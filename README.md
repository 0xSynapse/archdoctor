# archdoctor

Arch Linux 的体检、病历和分诊工具。

不是又一个“清理脚本”。它把散落在 pacman、systemd、journal、`/etc` 和桌面环境里的证据串起来，回答三个问题：

1. 现在哪里不对？
2. 这是**一次性爆发**、**持续出现**，还是**这次新出现**？
3. 先修哪个，命令是什么，风险多大？

```text
$ archdoctor
archdoctor 0.1.0 · jz-workstation · 2026-10-29 14:40 · 2.4s
需要处理 1   值得关注 8   提示 5   通过 14

需要处理
  ● 内核已更新，尚未重启
    运行 7.2.9-zen1-1-zen，已安装 linux-zen 7.2.11.zen1-1。升级后尚未重启，内核模块与用户空间可能不匹配。
    → sudo reboot（手动）
    风险 中 · 重启进入新内核（先保存工作）

值得关注
  ● 蓝牙/无线音频错误 241 条（7 天）
    241 条 · 持续出现 · 10-25 19:52 → 10-29 14:38 · 跨 5 天 · 3 次启动
    · Bluetooth: hci0: corrupted SCO packet ×92
    · Bluetooth: hci0: SCO packet for unknown connection handle 3584 ×26
    → systemctl --user restart wireplumber
    风险 中 · 重启音频栈（会短暂中断声音）
```

## 为什么不是“数错误”

同一个错误刷 500 次，可能只是某次启动时 2 秒内的竞态；另一个只出现 20 次的错误，可能每天都会让你的耳机断连。

`archdoctor` 会为每条日志生成归一化签名，并记录首次/末次时间、跨几天、跨几次启动，标记：

- `一次性爆发`：短窗口内大量重复，通常是一个 boot 内的一次性事件
- `持续出现`：跨天/跨启动反复出现，才是“慢性病”
- `新出现`：和上次快照相比第一次出现，优先看

## 安装

需要 Rust 1.82+（本机 1.92 已验证）。

```bash
cd archdoctor
cargo build --release
sudo install -Dm755 target/release/archdoctor /usr/local/bin/archdoctor
```

或者：

```bash
cargo install --path .
```

## 用法

```bash
archdoctor                 # 体检（默认 scan）
archdoctor scan            # 同上
archdoctor scan --json     # 机器可读输出
archdoctor scan --no-save  # 不写入历史快照
archdoctor diff            # 和上一次快照比较
archdoctor explain 蓝牙     # 按关键词查体检项 + 日志签名 + 原始日志
archdoctor explain kernel
archdoctor fix             # 交互式逐项修复
archdoctor fix --dry-run   # 只打印命令
archdoctor fix disk.trim   # 只处理指定检查
archdoctor ignore audio.bluetooth_errors --reason "耳机已知问题" --days 30
archdoctor ignore --list
archdoctor ignore --clear
archdoctor checks          # 列出所有检查
```

退出码：`0` 健康/仅提示，`1` 有值得关注项，`2` 有需要处理项，`3` 工具自身错误。适合放进脚本或 timer。

## 修复边界

- `scan` 永远只读：不 sudo、不联网写入、不删东西。
- `fix` 对每一项先展示完整命令、风险和说明，确认后才执行。
- 高风险项要求输入 `yes`，不是按一下 `y`。
- `sudo` 命令由终端里的 sudo 自己询问密码；工具不保存密码。
- 所有执行写入 `~/.local/state/archdoctor/audit.jsonl`。
- 删除孤儿包、合并 `.pacnew`、重启等操作都不会静默执行。

## 历史与 diff

每次 `scan` 默认写入：

```text
~/.local/state/archdoctor/
├── latest.json
├── snapshots/20261029T144053123.json
└── audit.jsonl
```

`archdoctor diff` 比较最近两次快照，输出：

- 新出现 / 已解决的体检项
- 严重度变化
- 新错误签名
- 指标变化：磁盘、启动耗时、pacman 缓存、孤儿包、baloo、journal 等

## 检查目录（v0.1）

| 领域 | 检查 |
| --- | --- |
| 启动/内核 | 内核待重启、失败单元、initramfs 落后、启动耗时、EFI 空间、内核 taint |
| 音频/蓝牙 | PipeWire/WirePlumber/Bluetooth 服务状态、SCO/BlueZ/RAOP 错误聚类 |
| 磁盘/缓存 | 磁盘与 inode、pacman 缓存、journal、`~/.cache`、孤儿包、baloo、TRIM、Docker |
| 桌面 | KDE/Plasma 错误日志 |
| 网络 | 默认路由、网关、DNS、Wi-Fi/NetworkManager 错误 |
| 睡眠 | 挂起/唤醒/休眠错误 |
| 包管理 | `.pacnew`/`.pacsave`、mirrorlist 新鲜度、keyring/签名信任 |
| 安全 | `/etc/ssl/private` 权限、防火墙状态 |
| 日志 | 通用错误签名、OOM、coredump |

v0.1 不包含：SMART、`pacman -Qkk` 文件完整性、AUR 过期检查、TUI、自动修复、systemd timer。这些是下一阶段。

## 开发

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

代码结构：

```text
src/
├── cli.rs          # clap 子命令与流程
├── context.rs      # 一次性采集系统事实与指标
├── checks/         # 每条检查一个函数，可并行
├── journal.rs      # journal 采集、归一化、时间分布
├── diff.rs         # 快照比较
├── state.rs        # 快照/忽略规则/审计日志
├── render.rs       # 人类可读输出
└── fix.rs          # 交互式修复
```

新增检查：在 `src/checks/` 里写一个 `fn(&Context) -> Vec<Finding>`，然后在 `checks/mod.rs` 注册即可。检查之间并行执行，单条 panic 不会拖垮整个体检。

## 设计原则

1. **只读默认**：诊断和执行分开。
2. **Arch 原生**：优先 Arch 特有的故障模式，而不是通用 Linux 优化建议。
3. **证据优先**：每条发现都有命令输出、路径、时间或计数。
4. **时间分布**：区分爆发、慢性、新出现。
5. **有记忆**：快照 + diff，回答“这周变坏了什么”。
6. **不做虚假健康分**：按可行动性排序。

## License

MIT
