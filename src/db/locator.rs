use crate::db::models::AccountInfo;
use regex::Regex;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

pub fn auto_detect_db_dir() -> Option<PathBuf> {
    // 1. 扫描配置文件
    for cfg_dir in config_candidates() {
        if !cfg_dir.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&cfg_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(raw) = fs::read_to_string(&path) {
                        if let Some(extracted) = extract_path_from_config(&raw) {
                            if let Some(hit) = locate_account_root(&extracted) {
                                return Some(hit);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. 扫描注册表
    for reg_path in registry_data_dirs() {
        if let Some(hit) = locate_account_root(&reg_path) {
            return Some(hit);
        }
    }

    // 3. 常见默认目录兜底
    if let Ok(userprofile) = env::var("USERPROFILE") {
        let docs = PathBuf::from(&userprofile).join("Documents");
        for base in &[docs, PathBuf::from(&userprofile)] {
            if let Some(hit) = locate_account_root(base) {
                return Some(hit);
            }
        }
    }

    None
}

fn config_candidates() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for env_var in &["APPDATA", "LOCALAPPDATA"] {
        if let Ok(base) = env::var(env_var) {
            let base_path = PathBuf::from(base);
            dirs.push(base_path.join("Tencent").join("xwechat"));
            dirs.push(base_path.join("Tencent").join("xwechat").join("config"));
            dirs.push(base_path.join("Tencent").join("WeChat"));
        }
    }
    dirs
}

fn registry_data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    for sub in &[
        r"Software\Tencent\xwechat",
        r"Software\Tencent\xwechat\config",
        r"Software\Tencent\WeChat",
    ] {
        if let Ok(key) = hkcu.open_subkey(sub) {
            for val in key.enum_values().flatten() {
                let (name, data) = val;
                let low = name.to_lowercase();
                if (low.contains("path") || low.contains("dir") || low.contains("save"))
                    && !data.to_string().trim().is_empty()
                {
                    dirs.push(PathBuf::from(data.to_string().trim()));
                }
            }
        }
    }

    dirs
}

fn extract_path_from_config(content: &str) -> Option<PathBuf> {
    let text = content.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return None;
    }

    // 尝试 JSON 解析
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(obj) = v.as_object() {
            for key in &[
                "dataDir",
                "data_dir",
                "fileSavePath",
                "savePath",
                "path",
                "defaultFileSavePath",
            ] {
                if let Some(s) = obj.get(*key).and_then(|v| v.as_str()) {
                    if !s.trim().is_empty() {
                        return Some(PathBuf::from(s.trim()));
                    }
                }
            }
        }
    }

    // 正则提取类似 C:\xxx 格式的 Windows 绝对路径
    let path_re = Regex::new(r#"[A-Za-z]:[\\/][^\s\x00-\x1f"']+"#).ok()?;
    if let Some(mat) = path_re.find(text) {
        let p = mat.as_str().trim_end_matches(&['\\', '/'][..]);
        return Some(PathBuf::from(p));
    }

    None
}

fn locate_account_root<P: AsRef<Path>>(root: P) -> Option<PathBuf> {
    let r = root.as_ref();
    if !r.is_dir() {
        return None;
    }

    let mut candidates = vec![r.to_path_buf()];
    for sub in &["xwechat_files", "WeChat Files", "xwechat_files_data"] {
        candidates.push(r.join(sub));
    }

    for cand in candidates {
        if !cand.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&cand) {
            for entry in entries.flatten() {
                let sub_path = entry.path();
                if sub_path.is_dir() && sub_path.join("db_storage").is_dir() {
                    return Some(cand);
                }
            }
        }
    }

    None
}

pub fn list_accounts<P: AsRef<Path>>(db_dir: Option<P>) -> Vec<AccountInfo> {
    let root = match db_dir {
        Some(d) => d.as_ref().to_path_buf(),
        None => match auto_detect_db_dir() {
            Some(d) => d,
            None => return Vec::new(),
        },
    };

    let mut accounts = Vec::new();
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let db_storage = path.join("db_storage");
            if path.is_dir() && db_storage.is_dir() {
                let mut latest_mtime = 0u64;

                for entry in WalkDir::new(&db_storage).into_iter().flatten() {
                    let file_path = entry.path();
                    let name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.ends_with(".db") && !name.ends_with("-wal") && !name.ends_with("-shm") {
                        if let Ok(meta) = file_path.metadata() {
                            if let Ok(mtime) = meta.modified() {
                                let duration = mtime
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default();
                                let ts = duration.as_secs();
                                if ts > latest_mtime {
                                    latest_mtime = ts;
                                }
                            }
                        }
                    }
                }

                let folder_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();

                let re = Regex::new(r#"_\w{4}$"#).unwrap();
                let wxid = re.replace(&folder_name, "").to_string();

                accounts.push(AccountInfo {
                    account: folder_name,
                    wxid,
                    path: path.to_string_lossy().to_string(),
                    last_activity: latest_mtime,
                });
            }
        }
    }

    accounts.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
    accounts
}
