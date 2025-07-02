use crate::common::update_file_permission;

use anyhow::{Context, Result};
use log::warn;
use serde::{Deserialize, Serialize};
use tokio::fs::{read_to_string, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;

const CONFIG_DAT: &str = "config.dat";

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RegisterInfo {
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub register_code: String,
    #[serde(default)]
    pub register_value: String,
    #[serde(default)]
    pub machine_id: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub instance_id: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Url {
    #[serde(default)]
    pub invoke_url: Option<String>,
    #[serde(default)]
    pub ws_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Config {
    // Run as register instance
    #[serde(default)]
    register: Option<RegisterInfo>,

    // Set server URLs
    #[serde(default)]
    url: Option<Url>,
}

async fn load_config() -> &'static Config {
    static ONCE: OnceCell<Config> = OnceCell::const_new();
    ONCE.get_or_init(|| async {
        read_to_string(CONFIG_DAT)
            .await
            .context("read config file failed")
            .and_then(|s| serde_json::from_str::<Config>(&s).context("serde_json failed"))
            .map_err(|e| warn!("load config: {e:#}"))
            .unwrap_or_default()
    })
    .await
}

pub async fn get_invoke_url() -> Option<&'static str> {
    let url = load_config().await.url.as_ref()?;
    url.invoke_url.as_deref()
}

pub async fn get_ws_url() -> Option<&'static str> {
    let url = load_config().await.url.as_ref()?;
    url.ws_url.as_deref()
}

pub async fn get_register_info() -> Option<&'static RegisterInfo> {
    load_config().await.register.as_ref()
}

pub async fn save_register_info(info: RegisterInfo) -> Result<()> {
    let mut config = load_config().await.clone();
    config.register = Some(info);
    save_config(&config).await
}

async fn save_config(config: &Config) -> Result<()> {
    let json_str = serde_json::to_string(config)?;
    let mut file = File::create(CONFIG_DAT).await?;
    file.write_all(json_str.as_bytes()).await?;
    update_file_permission(CONFIG_DAT);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{save_register_info, RegisterInfo};
    #[tokio::test]
    async fn test_save_config() {
        let config = RegisterInfo {
            machine_id: "xxxx".to_string(),
            ..Default::default()
        };
        let _ = save_register_info(config).await;
    }
}
