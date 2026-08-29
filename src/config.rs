use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetItem {
    pub label: String,
    pub user: String,
}

impl TargetItem {
    pub fn new(label: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            user: user.into(),
        }
    }

    pub fn from_raw(query: &str) -> Self {
        let trimmed = query.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            Self::new(k.trim(), v.trim())
        } else if let Some((k, v)) = trimmed.split_once('=') {
            Self::new(k.trim(), v.trim())
        } else {
            Self::new(trimmed, trimmed)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// 当前登录的微信账号（多微信登录时指定，None 为自动识别）
    #[serde(default)]
    pub my_account: Option<String>,

    /// 需要导出的目标列表（支持 Key-Value 对象、字符串数组或对象数组）
    #[serde(default, deserialize_with = "deserialize_target_users")]
    pub target_users: Vec<TargetItem>,

    /// 导出输出目录
    #[serde(default = "default_output_dir")]
    pub output_dir: String,

    /// 自定义微信数据目录（None 为自动检测）
    #[serde(default)]
    pub custom_db_dir: Option<String>,
}

fn default_output_dir() -> String {
    "exports".to_string()
}

fn deserialize_target_users<'de, D>(deserializer: D) -> Result<Vec<TargetItem>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    let mut items = Vec::new();

    match value {
        serde_json::Value::Object(map) => {
            // 支持 {"树苗": "mcx720126", "麦麦": "Mli_baby"} 格式
            for (label, user_val) in map {
                if let Some(user_str) = user_val.as_str() {
                    items.push(TargetItem::new(label, user_str));
                } else if user_val.is_number() {
                    items.push(TargetItem::new(label, user_val.to_string()));
                }
            }
        }
        serde_json::Value::Array(arr) => {
            // 支持 ["mcx720126", "Mli_baby"] 或 [{"label": "树苗", "user": "mcx720126"}] 格式
            for item in arr {
                match item {
                    serde_json::Value::String(s) => {
                        items.push(TargetItem::from_raw(&s));
                    }
                    serde_json::Value::Object(obj) => {
                        let user = obj
                            .get("user")
                            .or_else(|| obj.get("username"))
                            .or_else(|| obj.get("wechat_id"))
                            .or_else(|| obj.get("wxid"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let label = obj
                            .get("label")
                            .or_else(|| obj.get("name"))
                            .or_else(|| obj.get("nickname"))
                            .or_else(|| obj.get("remark"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&user)
                            .to_string();

                        if !user.is_empty() {
                            items.push(TargetItem::new(label, user));
                        }
                    }
                    _ => {}
                }
            }
        }
        serde_json::Value::String(s) => {
            items.push(TargetItem::from_raw(&s));
        }
        _ => {}
    }

    Ok(items)
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            my_account: None,
            target_users: vec![
                TargetItem::new("树苗", "mcx720126"),
                TargetItem::new("麦麦", "Mli_baby"),
                TargetItem::new("马哥", "mxyxyy20200506"),
                TargetItem::new("羊缸子", "Jessica_yangyang_"),
            ],
            output_dir: default_output_dir(),
            custom_db_dir: None,
        }
    }
}

impl AppConfig {
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        if let Ok(content) = std::fs::read_to_string(path.as_ref()) {
            if let Ok(config) = serde_json::from_str::<AppConfig>(&content) {
                return config;
            }
        }
        Self::default()
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn resolved_output_path(&self) -> PathBuf {
        PathBuf::from(&self.output_dir)
    }
}
