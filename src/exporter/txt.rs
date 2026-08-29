use crate::db::models::{Contact, Message, TargetMeta};
use anyhow::Result;
use chrono::Local;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn format_txt_chat(
    target: &TargetMeta,
    self_info: &Contact,
    messages: &[Message],
) -> String {
    let mut lines = Vec::new();
    lines.push("=".repeat(80));
    lines.push("微信聊天记录导出".to_string());
    
    let alias_info = if !target.alias.is_empty() && target.alias != target.username {
        format!(", 微信号: {}", target.alias)
    } else {
        String::new()
    };
    lines.push(format!(
        "导出对象: {} (账号: {}{})",
        target.display_name, target.username, alias_info
    ));

    let self_display = self_info.display_name();
    lines.push(format!(
        "当前用户: {} ({})",
        self_display, self_info.username
    ));
    lines.push(format!("消息总数: {} 条", messages.len()));

    if let (Some(first), Some(last)) = (messages.first(), messages.last()) {
        if !first.time_str.is_empty() && !last.time_str.is_empty() {
            lines.push(format!("时间范围: {} 至 {}", first.time_str, last.time_str));
        }
    }

    lines.push(format!(
        "导出时间: {}",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    lines.push("=".repeat(80));
    lines.push(String::new());

    for msg in messages {
        let sender = if msg.is_self {
            "我".to_string()
        } else if !msg.sender_name.is_empty() {
            msg.sender_name.clone()
        } else {
            "对方".to_string()
        };

        lines.push(format!("[{}] {}:", msg.time_str, sender));
        if !msg.content.is_empty() {
            for line in msg.content.lines() {
                lines.push(format!("  {}", line));
            }
        } else {
            lines.push(format!("  [{}]", msg.msg_type));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

pub fn export_single_txt<P: AsRef<Path>>(
    path: P,
    target: &TargetMeta,
    self_info: &Contact,
    messages: &[Message],
) -> Result<()> {
    let content = format_txt_chat(target, self_info, messages);
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}

pub fn export_combined_txt<P: AsRef<Path>>(
    path: P,
    self_info: &Contact,
    total_targets: usize,
    total_messages: usize,
    messages: &[(String, String, Message)], // (chat_name, chat_username, message)
) -> Result<()> {
    let mut lines = Vec::new();
    lines.push("=".repeat(80));
    lines.push("微信聊天记录多会话合并导出".to_string());
    lines.push(format!(
        "当前用户: {} ({})",
        self_info.display_name(),
        self_info.username
    ));
    lines.push(format!(
        "导出时间: {}",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    lines.push(format!("包含会话数: {} 个", total_targets));
    lines.push(format!("总消息数: {} 条", total_messages));
    lines.push("=".repeat(80));
    lines.push(String::new());

    for (chat_name, _, m) in messages {
        let sender = if m.is_self {
            "我".to_string()
        } else if !m.sender_name.is_empty() {
            m.sender_name.clone()
        } else {
            "对方".to_string()
        };

        lines.push(format!("[{}] 【{}】 {}:", m.time_str, chat_name, sender));
        if !m.content.is_empty() {
            for line in m.content.lines() {
                lines.push(format!("  {}", line));
            }
        } else {
            lines.push(format!("  [{}]", m.msg_type));
        }
        lines.push(String::new());
    }

    let content = lines.join("\n");
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}
