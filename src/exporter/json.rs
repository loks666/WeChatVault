use crate::db::models::{Contact, Message, TargetExportResult, TargetMeta};
use anyhow::Result;
use chrono::Local;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn export_single_json<P: AsRef<Path>>(
    path: P,
    target: &TargetMeta,
    self_info: &Contact,
    messages: &[Message],
) -> Result<()> {
    let start_time = messages.first().map(|m| m.time_str.clone()).unwrap_or_default();
    let end_time = messages.last().map(|m| m.time_str.clone()).unwrap_or_default();

    let payload = json!({
        "meta": {
            "target_name": target.display_name,
            "target_username": target.username,
            "target_alias": target.alias,
            "label": target.label,
            "message_count": messages.len(),
            "start_time": start_time,
            "end_time": end_time,
            "exported_at": Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            "self_info": self_info,
        },
        "messages": messages,
    });

    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, &payload)?;
    file.flush()?;
    Ok(())
}

pub fn export_combined_json<P: AsRef<Path>>(
    path: P,
    self_info: &Contact,
    summary_targets: &[TargetExportResult],
    all_messages: &[serde_json::Value],
) -> Result<()> {
    let payload = json!({
        "meta": {
            "self_info": self_info,
            "exported_at": Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            "total_messages": all_messages.len(),
            "targets": summary_targets,
        },
        "messages": all_messages,
    });

    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, &payload)?;
    file.flush()?;
    Ok(())
}

pub fn export_summary_json<P: AsRef<Path>>(
    path: P,
    self_info: &Contact,
    summary_targets: &[TargetExportResult],
    total_messages: usize,
) -> Result<()> {
    let payload = json!({
        "exported_at": Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "self_info": self_info,
        "total_targets": summary_targets.len(),
        "total_messages": total_messages,
        "targets": summary_targets,
    });

    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, &payload)?;
    file.flush()?;
    Ok(())
}
