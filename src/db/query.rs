use crate::crypto::cipher::{decrypt_file, verify_enc_key};
use crate::crypto::wal::merge_wal;
use crate::db::locator::{auto_detect_db_dir, list_accounts};
use crate::db::models::{Contact, Message, Session, TargetMeta};
use crate::scanner::memory::{scan_and_extract_keys, DbFileTarget};
use anyhow::{bail, Result};
use chrono::{Local, TimeZone};
use md5::{Digest, Md5};
use regex::Regex;
use rusqlite::{Connection, OpenFlags};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const STAMP_VERSION: i32 = 2;

pub struct WeChatDbSession {
    pub db_dir: PathBuf,
    pub account: String,
    pub account_dir: PathBuf,
    pub workdir: PathBuf,
    pub keys_file: PathBuf,
    keys: HashMap<String, Vec<u8>>,
    db_files: Vec<(String, PathBuf, u64)>, // (rel_path, full_path, size)
    sender_id_cache: Option<HashMap<i64, String>>,
}

impl WeChatDbSession {
    pub fn new(custom_db_dir: Option<&str>, specified_account: Option<&str>) -> Result<Self> {
        let db_dir = match custom_db_dir {
            Some(d) => PathBuf::from(d),
            None => match auto_detect_db_dir() {
                Some(d) => d,
                None => bail!("未自动检测到微信数据目录，请通过 --db-dir 手动指定。"),
            },
        };

        let accounts = list_accounts(Some(&db_dir));
        if accounts.is_empty() {
            bail!("在目录 {} 下未找到任何微信账号数据目录。", db_dir.display());
        }

        let account = Self::resolve_account(&accounts, specified_account)?;
        let account_dir = db_dir.join(&account);
        let workdir = std::env::temp_dir()
            .join("wechatvault_cache")
            .join(&account);
        let keys_file = workdir.join("keys.json");

        let db_files = Self::collect_db_files(&account_dir);

        let mut session = Self {
            db_dir,
            account,
            account_dir,
            workdir,
            keys_file,
            keys: HashMap::new(),
            db_files,
            sender_id_cache: None,
        };

        session.load_or_extract_keys()?;
        Ok(session)
    }

    fn resolve_account(
        accounts: &[crate::db::models::AccountInfo],
        specified: Option<&str>,
    ) -> Result<String> {
        if let Some(spec) = specified {
            let spec_clean = spec.trim().to_lowercase();
            for acc in accounts {
                if acc.account.to_lowercase() == spec_clean
                    || acc.wxid.to_lowercase() == spec_clean
                    || acc.account.to_lowercase().starts_with(&spec_clean)
                {
                    return Ok(acc.account.clone());
                }
            }
            bail!(
                "未找到指定的微信账号 '{}'。本地检测到的账号有: {}",
                spec,
                accounts
                    .iter()
                    .map(|a| format!("{} (wxid: {})", a.account, a.wxid))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        // 默认选择最近活跃的账号
        Ok(accounts[0].account.clone())
    }

    fn collect_db_files(account_dir: &Path) -> Vec<(String, PathBuf, u64)> {
        let mut files = Vec::new();
        let base = account_dir.join("db_storage");
        if !base.is_dir() {
            return files;
        }

        for entry in WalkDir::new(&base).into_iter().flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.ends_with(".db") && !name.ends_with("-wal") && !name.ends_with("-shm") {
                    if let Ok(rel) = path.strip_prefix(&base) {
                        let rel_str = rel.to_string_lossy().replace('\\', "/");
                        if rel_str.starts_with("migrate") {
                            continue;
                        }
                        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                        files.push((rel_str, path.to_path_buf(), size));
                    }
                }
            }
        }
        files
    }

    pub fn wxid(&self) -> String {
        let re = Regex::new(r#"_\w{4}$"#).unwrap();
        re.replace(&self.account, "").to_string()
    }

    fn load_or_extract_keys(&mut self) -> Result<()> {
        // 1. 尝试从本地 keys.json 加载缓存
        if self.keys_file.exists() {
            if let Ok(content) = fs::read_to_string(&self.keys_file) {
                if let Ok(saved) = serde_json::from_str::<HashMap<String, String>>(&content) {
                    for (rel, hexkey) in saved {
                        if let Ok(key_bytes) = hex::decode(hexkey) {
                            self.keys.insert(rel, key_bytes);
                        }
                    }
                }
            }
        }

        // 检查是否有缺失密钥的数据库
        let missing_targets: Vec<DbFileTarget> = self
            .db_files
            .iter()
            .filter(|(rel, path, _)| {
                if let Some(key) = self.keys.get(rel) {
                    let mut page1 = vec![0u8; crate::crypto::cipher::PAGE_SZ];
                    if let Ok(mut f) = fs::File::open(path) {
                        use std::io::Read;
                        if f.read_exact(&mut page1).is_ok() {
                            return !verify_enc_key(key, &page1, None);
                        }
                    }
                }
                true
            })
            .filter_map(|(rel, path, _)| DbFileTarget::new(rel, path))
            .collect();

        if !missing_targets.is_empty() {
            let extracted = scan_and_extract_keys(&missing_targets)?;
            self.keys.extend(extracted);
            self.save_keys()?;
        }

        Ok(())
    }

    fn save_keys(&self) -> Result<()> {
        if let Some(p) = self.keys_file.parent() {
            fs::create_dir_all(p)?;
        }
        let map: HashMap<String, String> = self
            .keys
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect();
        let json = serde_json::to_string_pretty(&map)?;
        fs::write(&self.keys_file, json)?;
        Ok(())
    }

    fn open_db(&self, rel_path: &str) -> Result<Connection> {
        let key = match self.keys.get(rel_path) {
            Some(k) => k,
            None => bail!("数据库无可用密钥: {}", rel_path),
        };

        let src = self
            .db_files
            .iter()
            .find(|(r, _, _)| r == rel_path)
            .map(|(_, p, _)| p.clone())
            .ok_or_else(|| anyhow::anyhow!("未找到库路径: {}", rel_path))?;

        let safe_name = rel_path.replace(['/', '\\'], "__");
        let dst = self.workdir.join(&safe_name);
        let stamp_path = self.workdir.join(format!("{}.stamp", safe_name));

        let src_meta = fs::metadata(&src)?;
        let src_mtime = src_meta
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs_f64();
        let src_size = src_meta.len();

        let wal_path = PathBuf::from(format!("{}-wal", src.display()));
        let (wal_mtime, wal_size) = if wal_path.exists() {
            let m = fs::metadata(&wal_path)?;
            let t = m
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs_f64();
            (t, m.len() as usize)
        } else {
            (0.0, 0)
        };

        let mut old_stamp = None;
        if stamp_path.exists() {
            if let Ok(txt) = fs::read_to_string(&stamp_path) {
                let parts: Vec<&str> = txt.split(',').collect();
                if parts.len() == 6 {
                    if let (Ok(ver), Ok(mtime), Ok(sz), Ok(wmtime), Ok(wsz), Ok(applied)) = (
                        parts[0].parse::<i32>(),
                        parts[1].parse::<f64>(),
                        parts[2].parse::<u64>(),
                        parts[3].parse::<f64>(),
                        parts[4].parse::<usize>(),
                        parts[5].parse::<usize>(),
                    ) {
                        if ver == STAMP_VERSION {
                            old_stamp = Some((mtime, sz, wmtime, wsz, applied));
                        }
                    }
                }
            }
        }

        let need_build = match old_stamp {
            Some((mtime, sz, wmtime, wsz, _)) => {
                (mtime - src_mtime).abs() > 0.001
                    || sz != src_size
                    || (wmtime - wal_mtime).abs() > 0.001
                    || wsz != wal_size
            }
            None => true,
        };

        if need_build {
            let full_rebuild = match old_stamp {
                Some((mtime, sz, _, wsz, _)) => {
                    (mtime - src_mtime).abs() > 0.001 || sz != src_size || wal_size < wsz || wal_size == 0
                }
                None => true,
            };

            let mut applied = 0;
            if full_rebuild {
                decrypt_file(&src, &dst, key)?;
            } else if let Some((_, _, _, _, a)) = old_stamp {
                applied = a;
            }

            if wal_path.exists() && wal_size > crate::crypto::wal::WAL_HEADER_SZ {
                applied = merge_wal(&dst, &wal_path, key, applied)?;
            }

            // 写入 stamp 标记
            if let Some(p) = stamp_path.parent() {
                fs::create_dir_all(p)?;
            }
            let stamp_content = format!(
                "{},{},{},{},{},{}",
                STAMP_VERSION, src_mtime, src_size, wal_mtime, wal_size, applied
            );
            let _ = fs::write(&stamp_path, stamp_content);
        }

        let conn = Connection::open_with_flags(
            &dst,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        Ok(conn)
    }

    fn message_dbs(&self) -> Vec<String> {
        let msg_re = Regex::new(r#"^message/message_\d+\.db$"#).unwrap();
        let mut list: Vec<String> = self
            .db_files
            .iter()
            .filter(|(rel, _, _)| msg_re.is_match(rel))
            .map(|(rel, _, _)| rel.clone())
            .collect();
        list.sort();
        list
    }

    pub fn get_self_info(&self) -> Contact {
        for (rel, _, _) in &self.db_files {
            if rel.ends_with("contact.db") {
                if let Ok(conn) = self.open_db(rel) {
                    let stmt = conn
                        .prepare("SELECT username, nick_name, remark FROM contact WHERE username=? LIMIT 1")
                        .ok();
                    if let Some(mut s) = stmt {
                        let row = s.query_row([self.wxid()], |r| {
                            Ok(Contact {
                                username: r.get(0)?,
                                nick_name: r.get(1)?,
                                remark: r.get(2)?,
                                alias: String::new(),
                            })
                        });
                        if let Ok(c) = row {
                            return c;
                        }
                    }
                }
            }
        }
        Contact {
            username: self.wxid(),
            nick_name: String::new(),
            remark: String::new(),
            alias: String::new(),
        }
    }

    pub fn search_contacts(&self, keyword: &str) -> Vec<Contact> {
        let mut results = Vec::new();
        for (rel, _, _) in &self.db_files {
            if rel.ends_with("contact.db") {
                if let Ok(conn) = self.open_db(rel) {
                    let query_str = format!("%{}%", keyword);
                    let mut stmt = match conn.prepare(
                        "SELECT username, nick_name, remark FROM contact \
                         WHERE nick_name LIKE ? OR remark LIKE ? OR username LIKE ? OR alias LIKE ? \
                         LIMIT 50",
                    ) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    let rows = stmt.query_map(
                        [&query_str, &query_str, &query_str, &query_str],
                        |r| {
                            Ok(Contact {
                                username: r.get(0)?,
                                nick_name: r.get(1)?,
                                remark: r.get(2)?,
                                alias: String::new(),
                            })
                        },
                    );

                    if let Ok(iter) = rows {
                        for c in iter.flatten() {
                            results.push(c);
                        }
                    }
                }
                break;
            }
        }
        results
    }

    pub fn get_contact_by_username(&self, user: &str) -> Option<Contact> {
        for (rel, _, _) in &self.db_files {
            if rel.ends_with("contact.db") {
                if let Ok(conn) = self.open_db(rel) {
                    let mut stmt = conn
                        .prepare(
                            "SELECT username, nick_name, remark FROM contact \
                             WHERE username=? OR alias=? LIMIT 1",
                        )
                        .ok()?;
                    let res = stmt.query_row([user, user], |r| {
                        Ok(Contact {
                            username: r.get(0)?,
                            nick_name: r.get(1)?,
                            remark: r.get(2)?,
                            alias: String::new(),
                        })
                    });
                    if let Ok(c) = res {
                        return Some(c);
                    }
                }
                break;
            }
        }
        None
    }

    pub fn get_sessions(&self, limit: usize) -> Vec<Session> {
        let mut sessions = Vec::new();
        for (rel, _, _) in &self.db_files {
            if rel.ends_with("session.db") {
                if let Ok(conn) = self.open_db(rel) {
                    let mut stmt = match conn.prepare(
                        "SELECT username, unread_count, summary, last_timestamp, \
                         last_msg_sender, last_sender_display_name \
                         FROM SessionTable WHERE is_hidden=0 \
                         ORDER BY sort_timestamp DESC LIMIT ?",
                    ) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    let rows = stmt.query_map([limit as i64], |r| {
                        let u: String = r.get(0)?;
                        let unread: i32 = r.get(1)?;
                        let summary: String = r.get(2).unwrap_or_default();
                        let last_time: i64 = r.get(3).unwrap_or_default();
                        let sender: String = r.get(4).unwrap_or_default();
                        let display: String = r.get(5).unwrap_or_default();
                        let final_sender = if !display.is_empty() { display } else { sender };
                        Ok(Session {
                            username: u.clone(),
                            display_name: u,
                            unread,
                            summary,
                            last_time,
                            last_sender: final_sender,
                        })
                    });

                    if let Ok(iter) = rows {
                        for mut s in iter.flatten() {
                            if let Some(c) = self.get_contact_by_username(&s.username) {
                                s.display_name = c.display_name();
                            }
                            sessions.push(s);
                        }
                    }
                }
                break;
            }
        }
        sessions
    }

    fn sender_id_index(&mut self) -> HashMap<i64, String> {
        if let Some(ref cache) = self.sender_id_cache {
            return cache.clone();
        }

        let mut map = HashMap::new();
        for (rel, _, _) in &self.db_files {
            if rel.ends_with("message_resource.db") {
                if let Ok(conn) = self.open_db(rel) {
                    if let Ok(mut stmt) = conn.prepare("SELECT rowid, user_name FROM SenderName2Id") {
                        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) {
                            for row in rows.flatten() {
                                let (rid, uname): (i64, String) = row;
                                map.insert(rid, uname);
                            }
                        }
                    }
                }
                break;
            }
        }

        self.sender_id_cache = Some(map.clone());
        map
    }

    pub fn resolve_target(&self, target_input: &str) -> TargetMeta {
        let query = target_input.trim();
        if query.is_empty() {
            return TargetMeta {
                query: String::new(),
                label: String::new(),
                username: String::new(),
                display_name: String::new(),
                alias: String::new(),
            };
        }

        // 1. 精确匹配
        if let Some(c) = self.get_contact_by_username(query) {
            return TargetMeta {
                query: query.to_string(),
                label: query.to_string(),
                username: c.username.clone(),
                display_name: c.display_name(),
                alias: c.alias,
            };
        }

        // 2. 特殊内置会话
        let low = query.to_lowercase();
        if matches!(low.as_str(), "filehelper" | "fmessage" | "medianote" | "newsapp") {
            return TargetMeta {
                query: query.to_string(),
                label: query.to_string(),
                username: query.to_string(),
                display_name: query.to_string(),
                alias: query.to_string(),
            };
        }

        // 3. 搜索匹配
        let hits = self.search_contacts(query);
        if let Some(first) = hits.first() {
            return TargetMeta {
                query: query.to_string(),
                label: query.to_string(),
                username: first.username.clone(),
                display_name: first.display_name(),
                alias: first.alias.clone(),
            };
        }

        // 4. 原样返回
        TargetMeta {
            query: query.to_string(),
            label: query.to_string(),
            username: query.to_string(),
            display_name: query.to_string(),
            alias: String::new(),
        }
    }

    pub fn fetch_chat_messages(&mut self, user_or_wxid: &str) -> Result<Vec<Message>> {
        let is_md5 = user_or_wxid.len() == 32 && user_or_wxid.chars().all(|c| c.is_ascii_hexdigit());
        let target_md5 = if is_md5 {
            user_or_wxid.to_string()
        } else {
            let mut hasher = Md5::new();
            hasher.update(user_or_wxid.as_bytes());
            hex::encode(hasher.finalize())
        };

        let target_table = format!("Msg_{}", target_md5);
        let self_info = self.get_self_info();
        let self_nick = if !self_info.nick_name.is_empty() {
            self_info.nick_name
        } else {
            "我".to_string()
        };

        let sender_map = self.sender_id_index();

        struct RawRow {
            local_id: i64,
            local_type: i32,
            real_sender_id: i64,
            create_time: i64,
            content_bytes: Option<Vec<u8>>,
            content_str: Option<String>,
            sort_seq: i64,
        }

        let mut all_rows: Vec<RawRow> = Vec::new();

        for rel in self.message_dbs() {
            let conn = match self.open_db(&rel) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let has_table: bool = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    [&target_table],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if !has_table {
                continue;
            }

            let sql = format!(
                "SELECT local_id, local_type, real_sender_id, create_time, message_content, sort_seq FROM {}",
                target_table
            );

            let extracted_rows: Vec<RawRow> = {
                let mut stmt = match conn.prepare(&sql) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let rows = stmt.query_map([], |r| {
                    let local_id: i64 = r.get(0)?;
                    let local_type: i32 = r.get(1)?;
                    let real_sender_id: i64 = r.get(2).unwrap_or(0);
                    let create_time: i64 = r.get(3).unwrap_or(0);
                    let sort_seq: i64 = r.get(5).unwrap_or(0);

                    let (content_bytes, content_str) = match r.get_ref(4)? {
                        rusqlite::types::ValueRef::Blob(b) => (Some(b.to_vec()), None),
                        rusqlite::types::ValueRef::Text(t) => {
                            (None, Some(String::from_utf8_lossy(t).to_string()))
                        }
                        _ => (None, None),
                    };

                    Ok(RawRow {
                        local_id,
                        local_type,
                        real_sender_id,
                        create_time,
                        content_bytes,
                        content_str,
                        sort_seq,
                    })
                });

                match rows {
                    Ok(iter) => iter.flatten().collect(),
                    Err(_) => Vec::new(),
                }
            };

            all_rows.extend(extracted_rows);
        }

        if all_rows.is_empty() {
            return Ok(Vec::new());
        }

        all_rows.sort_by_key(|r| (r.sort_seq, r.local_id));

        let mut messages = Vec::with_capacity(all_rows.len());

        for r in all_rows {
            let msg_type_name = get_msg_type_name(r.local_type);

            let content = if let Some(s) = r.content_str {
                s
            } else if let Some(b) = r.content_bytes {
                decode_friendly_content(&b, &msg_type_name)
            } else {
                format!("[{}]", msg_type_name)
            };

            let is_self = r.real_sender_id == 2;
            let sender_name = if is_self {
                self_nick.clone()
            } else {
                sender_map
                    .get(&r.real_sender_id)
                    .cloned()
                    .unwrap_or_else(|| "对方".to_string())
            };

            let time_str = if r.create_time > 0 {
                if let Some(dt) = Local.timestamp_opt(r.create_time, 0).single() {
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            messages.push(Message {
                local_id: r.local_id,
                sort_seq: r.sort_seq,
                msg_type: msg_type_name,
                type_code: r.local_type,
                is_self,
                sender_name,
                sender_id: r.real_sender_id.to_string(),
                create_time: r.create_time,
                time_str,
                content,
            });
        }

        Ok(messages)
    }
}

fn get_msg_type_name(t: i32) -> String {
    let actual_type = if t > 0xFFFF { t & 0xFF } else { t };
    match actual_type {
        1 => "文本".into(),
        3 => "图片".into(),
        34 => "语音".into(),
        43 => "视频".into(),
        47 => "动画表情".into(),
        48 => "位置".into(),
        49 => "文件/链接/卡片".into(),
        10000 => "系统消息".into(),
        _ => format!("未知({})", t),
    }
}

fn decode_friendly_content(data: &[u8], mtype: &str) -> String {
    if let Ok(s) = std::str::from_utf8(data) {
        let clean = s.trim();
        if !clean.is_empty() {
            if let Some(pos) = clean.find('\u{0001}') {
                return clean[..pos].trim().to_string();
            }
            return clean.to_string();
        }
    }

    if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        if let Some(txt) = extract_text_from_blob(data) {
            return txt;
        }
    }

    if mtype == "图片" {
        let re = regex::bytes::Regex::new(r#"md5="([0-9a-fA-F]{32})""#).unwrap();
        if let Some(cap) = re.captures(data) {
            if let Some(m) = cap.get(1) {
                return format!("[图片 md5={}]", String::from_utf8_lossy(m.as_bytes()));
            }
        }
    }

    format!("[{}]", mtype)
}

fn extract_text_from_blob(content: &[u8]) -> Option<String> {
    let try_offset = |off: usize| -> Option<String> {
        if off >= content.len() {
            return None;
        }
        let chunk = &content[off..];
        let sub = if let Some(pos) = chunk.windows(2).position(|w| w == [0x01, 0x00]) {
            &chunk[..pos]
        } else {
            chunk
        };
        let s = std::str::from_utf8(sub).ok()?;
        let clean: String = s
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\r')
            .collect();
        let trimmed = clean.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(trimmed.to_string())
    };

    if let Some(t) = try_offset(10) {
        return Some(t);
    }
    for off in 0..16.min(content.len()) {
        if off == 10 {
            continue;
        }
        if let Some(t) = try_offset(off) {
            return Some(t);
        }
    }
    None
}
