#![allow(dead_code)]

mod config;
mod crypto;
mod db;
mod exporter;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use config::AppConfig;
use db::locator::list_accounts;
use db::models::TargetExportResult;
use db::query::WeChatDbSession;
use exporter::{
    export_combined_json, export_combined_txt, export_single_json, export_single_txt,
    export_summary_json,
};
use regex::Regex;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "WeChatVault",
    version = "0.1.0",
    author = "WeChatVault Team",
    about = "🚀 微信本地数据库聊天记录极速解密与导出工具 (Rust 实现)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 指定配置文件路径 (默认: config.json)
    #[arg(short, long, default_value = "config.json")]
    config: String,

    /// 指定本人微信账号 (多开时指定，例如: bad-boy945)
    #[arg(short, long)]
    account: Option<String>,

    /// 指定要导出的目标微信号/昵称/备注 (英文逗号分隔)
    #[arg(short, long, value_delimiter = ',')]
    targets: Option<Vec<String>>,

    /// 导出输出目录 (默认: exports)
    #[arg(short, long)]
    output: Option<String>,

    /// 自定义微信数据存储路径
    #[arg(long)]
    db_dir: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 导出指定目标的聊天记录为 JSON 与 TXT 格式 (默认操作)
    Export {
        /// 指定本人微信账号
        #[arg(short, long)]
        account: Option<String>,

        /// 指定要导出的目标微信号/昵称/备注 (英文逗号分隔)
        #[arg(short, long, value_delimiter = ',')]
        targets: Option<Vec<String>>,

        /// 导出输出目录
        #[arg(short, long)]
        output: Option<String>,
    },

    /// 列出本地检测到的所有微信账号
    ListAccounts,

    /// 搜索联系人与微信号 (方便获取准确 wxid)
    Search {
        /// 搜索关键词 (昵称 / 备注 / 微信号)
        keyword: String,

        /// 指定要查询的本人微信账号
        #[arg(short, long)]
        account: Option<String>,
    },

    /// 查看最近活跃会话列表
    Sessions {
        /// 显示条数限制
        #[arg(short, long, default_value_t = 30)]
        limit: usize,

        /// 指定要查询的本人微信账号
        #[arg(short, long)]
        account: Option<String>,
    },
}

fn clean_filename(name: &str) -> String {
    let re = Regex::new(r#"[\\/:*?"<>|\r\n\t]+"#).unwrap();
    let clean = re.replace_all(name, "_").trim().trim_matches('.').to_string();
    if clean.is_empty() {
        "chat".to_string()
    } else {
        clean
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load_or_default(&cli.config);

    match &cli.command {
        Some(Commands::ListAccounts) => cmd_list_accounts(&cli, &config),
        Some(Commands::Search { keyword, account }) => {
            cmd_search(&cli, &config, keyword, account.as_deref())
        }
        Some(Commands::Sessions { limit, account }) => {
            cmd_sessions(&cli, &config, *limit, account.as_deref())
        }
        Some(Commands::Export {
            account,
            targets,
            output,
        }) => {
            let acc = account.as_deref().or(cli.account.as_deref());
            let tg = targets.as_ref().or(cli.targets.as_ref());
            let out = output.as_deref().or(cli.output.as_deref());
            cmd_export(&cli, &config, acc, tg, out)
        }
        None => {
            // 默认直接执行 export
            cmd_export(
                &cli,
                &config,
                cli.account.as_deref(),
                cli.targets.as_ref(),
                cli.output.as_deref(),
            )
        }
    }
}

fn cmd_list_accounts(cli: &Cli, config: &AppConfig) -> Result<()> {
    println!("{}", "============================================================".bright_blue());
    println!("{}", "  微信本地已登录账号列表".bold().bright_white());
    println!("{}", "============================================================".bright_blue());

    let db_dir = cli.db_dir.as_deref().or(config.custom_db_dir.as_deref());
    let accounts = list_accounts(db_dir);

    if accounts.is_empty() {
        println!("{}", "[X] 未检测到任何微信数据目录。请确认微信已登录。".red());
        return Ok(());
    }

    for (idx, acc) in accounts.iter().enumerate() {
        println!(
            "  [{}] 账号目录: {}",
            (idx + 1).to_string().bold(),
            acc.account.bright_green()
        );
        println!("      微信号/wxid: {}", acc.wxid.yellow());
        println!("      存储路径: {}", acc.path.dimmed());
        println!();
    }
    Ok(())
}

fn cmd_search(
    cli: &Cli,
    config: &AppConfig,
    keyword: &str,
    override_account: Option<&str>,
) -> Result<()> {
    println!("{}", "============================================================".bright_blue());
    println!("{}", "  微信联系人查找".bold().bright_white());
    println!("{}", "============================================================".bright_blue());

    let db_dir = cli.db_dir.as_deref().or(config.custom_db_dir.as_deref());
    let account = override_account
        .or(cli.account.as_deref())
        .or(config.my_account.as_deref());

    let session = WeChatDbSession::new(db_dir, account)?;
    let self_info = session.get_self_info();
    println!(
        "[*] 当前微信: {} ({})\n",
        self_info.display_name().green(),
        session.wxid().yellow()
    );

    println!("[*] 正在搜索关键词: '{}'...", keyword.cyan());
    let hits = session.search_contacts(keyword);

    if hits.is_empty() {
        println!("{}", "  未找到匹配联系人。".yellow());
    } else {
        println!("找到 {} 个匹配联系人:\n", hits.len().to_string().green());
        for (idx, c) in hits.iter().enumerate() {
            println!(
                "  [{}] 显示名: {}",
                (idx + 1).to_string().bold(),
                c.display_name().bright_white()
            );
            println!("      username/wxid: {}", c.username.yellow());
            if !c.remark.is_empty() {
                println!("      备注名: {}", c.remark);
            }
            if !c.nick_name.is_empty() {
                println!("      微信昵称: {}", c.nick_name);
            }
            println!();
        }
    }
    Ok(())
}

fn cmd_sessions(
    cli: &Cli,
    config: &AppConfig,
    limit: usize,
    override_account: Option<&str>,
) -> Result<()> {
    println!("{}", "============================================================".bright_blue());
    println!("{}", "  微信最近活跃会话".bold().bright_white());
    println!("{}", "============================================================".bright_blue());

    let db_dir = cli.db_dir.as_deref().or(config.custom_db_dir.as_deref());
    let account = override_account
        .or(cli.account.as_deref())
        .or(config.my_account.as_deref());

    let session = WeChatDbSession::new(db_dir, account)?;
    let self_info = session.get_self_info();
    println!(
        "[*] 当前微信: {} ({})\n",
        self_info.display_name().green(),
        session.wxid().yellow()
    );

    let sessions = session.get_sessions(limit);
    for (idx, s) in sessions.iter().enumerate() {
        println!(
            "  [{:2}] {} ({})",
            idx + 1,
            s.display_name.bright_white(),
            s.username.dimmed()
        );
        if !s.summary.is_empty() {
            let summary_clean = s.summary.replace(['\r', '\n'], " ");
            println!(
                "       最新消息: [{}] {}",
                s.last_sender.cyan(),
                summary_clean.chars().take(40).collect::<String>()
            );
        }
        println!();
    }
    Ok(())
}

fn cmd_export(
    cli: &Cli,
    config: &AppConfig,
    override_account: Option<&str>,
    override_targets: Option<&Vec<String>>,
    override_output: Option<&str>,
) -> Result<()> {
    println!("{}", "======================================================================".bright_blue());
    println!("{}", "  🚀 WeChatVault - 微信聊天记录极速导出工具 (Rust 版)".bold().bright_cyan());
    println!("{}", "======================================================================".bright_blue());

    let db_dir = cli.db_dir.as_deref().or(config.custom_db_dir.as_deref());
    let account = override_account
        .or(cli.account.as_deref())
        .or(config.my_account.as_deref());

    let targets: Vec<config::TargetItem> = match override_targets {
        Some(tg_strs) => tg_strs.iter().map(|s| config::TargetItem::from_raw(s)).collect(),
        None => config.target_users.clone(),
    };

    let output_str = override_output
        .unwrap_or(&config.output_dir);
    let output_dir = PathBuf::from(output_str);

    if targets.is_empty() {
        println!("{}", "[!] 提示：未配置任何导出目标。请在 config.json 的 target_users 中添加微信号。".yellow());
        return Ok(());
    }

    std::fs::create_dir_all(&output_dir)?;
    println!("[*] 输出目录: {}", output_dir.display().to_string().cyan());

    println!("[*] 正在连接微信数据库并获取解密密钥...");
    let mut session = match WeChatDbSession::new(db_dir, account) {
        Ok(s) => s,
        Err(e) => {
            println!("\n{} {}", "[X] 连接微信数据库失败:".red().bold(), e);
            println!("\n排查建议:");
            println!("  1. 请确认微信桌面端 (Weixin.exe) 已启动并处于登录状态；");
            println!("  2. 若微信以管理员权限运行，请以管理员身份打开终端运行本工具；");
            println!("  3. 若登录了多个微信，请通过 --account 参数或在 config.json 中指定账号。");
            return Ok(());
        }
    };

    let self_info = session.get_self_info();
    println!(
        "[+] 当前微信: {} (账号/wxid: {})",
        self_info.display_name().green().bold(),
        session.wxid().yellow()
    );
    println!("[+] 数据目录: {}", session.account_dir.display().to_string().dimmed());
    println!();

    println!("[*] 开始导出配置的 {} 个目标会话...", targets.len().to_string().green());
    println!("{}", "----------------------------------------------------------------------".dimmed());

    let mut summary_targets: Vec<TargetExportResult> = Vec::new();
    let mut all_combined_messages: Vec<(String, String, db::models::Message)> = Vec::new();
    let mut all_json_messages: Vec<serde_json::Value> = Vec::new();

    for (idx, target_item) in targets.iter().enumerate() {
        let meta = session.resolve_target(&target_item.user, Some(&target_item.label));
        print!(
            "[{}/{}] 正在导出: {} ({}) [配置: {}]...",
            idx + 1,
            targets.len(),
            meta.display_name.bright_white(),
            meta.username.yellow(),
            target_item.label.cyan()
        );

        let messages = session.fetch_chat_messages(&meta.username)?;
        let msg_count = messages.len();
        println!(" {} 条记录", msg_count.to_string().green().bold());

        let start_time = messages.first().map(|m| m.time_str.clone()).unwrap_or_default();
        let end_time = messages.last().map(|m| m.time_str.clone()).unwrap_or_default();

        let display_for_file = if !meta.label.is_empty() && meta.label != meta.username {
            &meta.label
        } else {
            &meta.display_name
        };

        let prefix = clean_filename(&format!(
            "{}_{}",
            display_for_file,
            if !meta.alias.is_empty() { &meta.alias } else { &meta.username }
        ));

        let json_name = format!("{}.json", prefix);
        let txt_name = format!("{}.txt", prefix);
        let json_path = output_dir.join(&json_name);
        let txt_path = output_dir.join(&txt_name);

        // 1. 写入单人 JSON
        export_single_json(&json_path, &meta, &self_info, &messages)?;

        // 2. 写入单人 TXT
        export_single_txt(&txt_path, &meta, &self_info, &messages)?;

        summary_targets.push(TargetExportResult {
            target: format!("{}: {}", target_item.label, target_item.user),
            name: meta.display_name.clone(),
            username: meta.username.clone(),
            alias: meta.alias.clone(),
            message_count: msg_count,
            start_time,
            end_time,
            json_file: json_name,
            txt_file: txt_name,
        });

        for m in messages {
            all_combined_messages.push((meta.display_name.clone(), meta.username.clone(), m.clone()));
            all_json_messages.push(serde_json::json!({
                "chat_name": meta.display_name,
                "chat_username": meta.username,
                "local_id": m.local_id,
                "sort_seq": m.sort_seq,
                "type": m.msg_type,
                "type_code": m.type_code,
                "is_self": m.is_self,
                "sender_name": m.sender_name,
                "create_time": m.create_time,
                "time_str": m.time_str,
                "content": m.content,
            }));
        }
    }

    // 写入合并文件
    if targets.len() > 1 && !all_combined_messages.is_empty() {
        all_combined_messages.sort_by_key(|(_, _, m)| (m.create_time, m.local_id));

        let combined_json_path = output_dir.join("全部目标合并_聊天记录.json");
        export_combined_json(
            &combined_json_path,
            &self_info,
            &summary_targets,
            &all_json_messages,
        )?;

        let combined_txt_path = output_dir.join("全部目标合并_聊天记录.txt");
        export_combined_txt(
            &combined_txt_path,
            &self_info,
            summary_targets.len(),
            all_combined_messages.len(),
            &all_combined_messages,
        )?;
    }

    // 写入汇总摘要
    let summary_path = output_dir.join("导出统计摘要.json");
    export_summary_json(
        &summary_path,
        &self_info,
        &summary_targets,
        all_combined_messages.len(),
    )?;

    println!("{}", "----------------------------------------------------------------------".dimmed());
    println!("{}", "🎉 导出完成！".green().bold());
    println!("[+] 导出目标数: {} 个", summary_targets.len().to_string().cyan());
    println!("[+] 导出总消息: {} 条", all_combined_messages.len().to_string().cyan());
    println!("[+] 文件保存在: {}\n", output_dir.canonicalize().unwrap_or(output_dir).display().to_string().bright_yellow());

    for st in &summary_targets {
        println!(
            "  * {} ({}): {} 条 -> {}, {}",
            st.name.bright_white(),
            st.username.dimmed(),
            st.message_count.to_string().green(),
            st.json_file.cyan(),
            st.txt_file.cyan()
        );
    }
    println!("{}", "======================================================================".bright_blue());

    Ok(())
}
