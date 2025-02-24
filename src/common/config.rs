use crate::common::update_file_permission;

use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use tokio::fs::{self, read_to_string, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CONFIG_DAT: &str = "config.dat";
const REGISTER_FILE: &str = "register.dat";

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

#[derive(Serialize, Deserialize, Debug, Default)]
struct Config {
    // Run as register instance
    #[serde(default)]
    register: Option<RegisterInfo>,

    // Set server URLs
    #[serde(default)]
    url: Option<Url>,
}

pub async fn get_invoke_url() -> Option<String> {
    load_config()
        .await
        .ok()
        .and_then(|config| config.url.and_then(|url| url.invoke_url))
}

pub async fn get_ws_url() -> Option<String> {
    load_config()
        .await
        .ok()
        .and_then(|config| config.url.and_then(|url| url.ws_url))
}

pub async fn get_register_info() -> Option<RegisterInfo> {
    static NEED_CHECK: AtomicBool = AtomicBool::new(true);
    let mut ret = load_config().await.ok().and_then(|cfg| cfg.register);
    if ret.is_none() {
        ret = get_register_info_old().await;
    }
    if let Some(info) = ret.as_ref() {
        if save_register_info(info.clone()).await.is_ok() {
            let _ = fs::remove_file(REGISTER_FILE);
        }
    }
    if ret.is_some() && NEED_CHECK.fetch_and(false, Ordering::SeqCst) {
        update_file_permission(CONFIG_DAT)
    }
    ret
}

pub async fn save_register_info(info: RegisterInfo) -> Result<()> {
    let mut config = load_config().await?;
    config.register = Some(info);
    save_config(&config).await
}

async fn get_register_info_old() -> Option<RegisterInfo> {
    let b64_data = read_to_string(REGISTER_FILE).await.ok()?;
    let json_data = STANDARD.decode(b64_data).ok()?;
    let record = serde_json::from_slice::<RegisterInfo>(&json_data[..]).ok()?;
    return Some(record);
}

async fn load_config() -> Result<Config> {
    let mut file = match File::open(CONFIG_DAT).await {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Config::default()),
        e => e?,
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let config: Config = serde_json::from_str(&contents)?;
    Ok(config)
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
    #[test]
    fn test_save_config() {
        let mut config = RegisterInfo::default();
        config.machine_id = "xxxx".to_string();
        let _ = save_register_info(config);
    }
}
