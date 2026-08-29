use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account: String,
    pub wxid: String,
    pub path: String,
    pub last_activity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Contact {
    pub username: String,
    pub nick_name: String,
    pub remark: String,
    pub alias: String,
}

impl Contact {
    pub fn display_name(&self) -> String {
        if !self.remark.is_empty() {
            self.remark.clone()
        } else if !self.nick_name.is_empty() {
            self.nick_name.clone()
        } else {
            self.username.clone()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub username: String,
    pub display_name: String,
    pub unread: i32,
    pub summary: String,
    pub last_time: i64,
    pub last_sender: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub local_id: i64,
    pub sort_seq: i64,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub type_code: i32,
    pub is_self: bool,
    pub sender_name: String,
    pub sender_id: String,
    pub create_time: i64,
    pub time_str: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetMeta {
    pub query: String,
    pub label: String,
    pub username: String,
    pub display_name: String,
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetExportResult {
    pub target: String,
    pub name: String,
    pub username: String,
    pub alias: String,
    pub message_count: usize,
    pub start_time: String,
    pub end_time: String,
    pub json_file: String,
    pub txt_file: String,
}
