# 🚀 WeChatVault (微信聊天记录极速解密与导出工具)

**WeChatVault** 是一款基于 **Rust** 编写的高性能、轻量级微信 4.x / 3.x 本地数据库解密与聊天记录导出工具。

支持将指定好友/群聊的聊天记录导出为结构化 **JSON** 与排版优美的 **TXT** 文本，并内置 SQLite 引擎（单可执行文件，无需安装任何额外依赖）。

---

## ✨ 核心特性

- ⚡ **极致性能**：Rust 原生开发，支持 AES-NI 指令集与多线程并发解密，数万条聊天记录毫秒级极速导出。
- 📦 **单文件零依赖分发**：使用 `rusqlite[bundled]` 将 SQLite3 静态内嵌，编译出的 `wechatvault.exe` 单文件即可在任意 Windows 电脑运行，无需 Python 或 VC++ 运行库。
- 🔑 **自动内存提密**：支持跨进程扫描 `Weixin.exe` 进程内存获取 SQLCipher 4 数据库密钥，并自动本地安全缓存。
- 🔥 **WCDB WAL 热数据合并**：实时解析并覆盖 WAL 日志帧，提取刚刚发送或接收的最新消息。
- 👥 **多账号与多开支持**：自动探测本地微信数据目录，支持在多个登录账号之间灵活切换与指定。
- 📝 **双格式导出**：
  - **JSON 格式**：结构化数据，适合大模型微调、RAG 知识库与数据分析。
  - **TXT 格式**：排版清晰的聊天文本视图，带时间戳、发送者区分与内容缩进。

---

## 🛠️ 快速上手

### 1. 编译构建

确保已安装 Rust 工具链（1.75+）：

```bash
cd C:\Users\Administrator\Documents\Project\Github\WeChatVault

# 编译生成 Release 单文件可执行程序
cargo build --release
```

编译产物位于 `target\release\wechatvault.exe`。

---

### 2. 配置文件说明 (`config.json`)

项目根目录的 `config.json` 提供了简单直观的配置方式：

```json
{
  "my_account": null,
  "target_users": {
    "张三": "wxid_example_001",
    "李四": "wx_custom_alias",
    "王五": "wxid_example_003",
    "文件传输助手": "filehelper"
  },
  "output_dir": "exports",
  "custom_db_dir": null
}
```

- **`my_account`**：当前登录的本人微信账号（`null` 为自动选择最近活跃的账号，多开时可指定微信号或 wxid，如 `"wxid_myaccount"`）。
- **`target_users`**：需要导出的目标列表（支持 `{"备注/昵称": "微信号/wxid"}` 键值对，或字符串数组 `["微信号1", "微信号2"]`）。
- **`output_dir`**：导出产物保存目录（默认 `exports`）。
- **`custom_db_dir`**：微信数据目录（`null` 为自动检测）。

---

### 3. 运行使用

> ⚠️ **注意**：运行前请确保 **微信客户端已打开并登录**（首次提取数据库密钥需要微信进程运行）。

#### ① 直接导出聊天记录（读取 `config.json`）
```bash
wechatvault.exe
# 或
cargo run --release
```

#### ② 命令行指定参数导出
```bash
# 导出指定微信号/备注，保存到 output 目录
wechatvault.exe export --targets "wxid_example_001,李四,filehelper" --output "my_exports"

# 多开时指定本人微信账号
wechatvault.exe export --account "wxid_myaccount" --targets "wxid_example_001"
```

#### ③ 查看本地所有微信账号
```bash
wechatvault.exe list-accounts
```

#### ④ 搜索好友微信号 / wxid
```bash
wechatvault.exe search "张三"
```

#### ⑤ 查看最近活跃会话
```bash
wechatvault.exe sessions
```

---

## 📂 导出产物结构

导出的文件按格式分文件夹清晰归类，保存在 `exports/` 目录下：

```text
exports/
├── json/                                # 结构化 JSON 文件夹
│   ├── 张三_wxid_example_001.json
│   ├── 李四_wx_custom_alias.json
│   ├── 王五_wxid_example_003.json
│   ├── 文件传输助手_filehelper.json
│   └── 导出统计摘要.json                # 各会话消息量、时间跨度的汇总摘要
└── txt/                                 # 可读聊天排版 TXT 文件夹
    ├── 张三_wxid_example_001.txt
    ├── 李四_wx_custom_alias.txt
    ├── 王五_wxid_example_003.txt
    └── 文件传输助手_filehelper.txt
```

---

## 📄 导出格式示例

### TXT 排版效果
```text
================================================================================
微信聊天记录导出
导出对象: 张三 (账号: wxid_example_001, 微信号: wx_custom_alias)
当前用户: 小明 (wxid_myaccount)
消息总数: 1520 条
时间范围: 2024-01-01 10:00:00 至 2026-08-29 12:00:00
导出时间: 2026-08-29 12:45:00
================================================================================

[2026-08-29 10:01:23] 张三:
  早上好！

[2026-08-29 10:02:15] 我:
  早上好，方案已经发你邮箱了。
```

---

## 🏗️ 架构与源码结构

```text
src/
├── main.rs              # CLI 入口与多子命令交互
├── config.rs            # 配置解析与默认值管理
├── crypto/
│   ├── cipher.rs        # PBKDF2 派生、AES-256-CBC 逐页解密、SQLCipher4 与 HMAC 校验
│   └── wal.rs           # WCDB 24 字节 WAL 帧头解析与增量覆盖热合并
├── scanner/
│   ├── process.rs       # Win32 进程枚举与内存读写 (OpenProcess / VirtualQueryEx)
│   └── memory.rs        # com.Tencent.WCDB.Config.Cipher 内存模式扫描与密钥验证
├── db/
│   ├── locator.rs       # 微信 4.x/3.x 数据目录自动探测与多账号扫描
│   ├── models.rs        # 消息、联系人、会话等结构体定义
│   └── query.rs         # 多分片 message_*.db (Msg_<md5>) 跨库查询与 SenderID 映射
└── exporter/
    ├── json.rs          # 结构化 JSON 导出 (单人 / 摘要)
    └── txt.rs           # 优雅排版 TXT 文本导出
```

---

## ⚖️ 开源协议

本项目基于 [Apache-2.0 License](LICENSE) 开源。
