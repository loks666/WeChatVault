use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// 当前登录的微信账号（多微信登录时指定，None 为自动识别）
    #[serde(default)]
    pub my_account: Option<String>,

    /// 需要导出的目标列表（微信号 / wxid / 微信昵称 / 好友备注）
    #[serde(default)]
    pub target_users: Vec<String>,

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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            my_account: None,
            target_users: vec![
                "mcx720126".into(),
                "wxid_iwmc135grv5n22".into(),
                "马哥".into(),
                "filehelper".into(),
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
