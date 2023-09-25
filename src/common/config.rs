use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};

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
    #[serde(default)]
    register: Option<RegisterInfo>,
    #[serde(default)]
    url: Option<Url>,
}

pub fn get_invoke_url() -> Option<String> {
    load_config()
        .ok()
        .and_then(|config| config.url.and_then(|url| url.invoke_url))
}

pub fn get_ws_url() -> Option<String> {
    load_config()
        .ok()
        .and_then(|config| config.url.and_then(|url| url.ws_url))
}

pub fn get_register_info() -> Option<RegisterInfo> {
    match load_config().ok().and_then(|config| config.register) {
        Some(info) => Some(info),
        None => match get_register_info_old() {
            Some(info) => {
                let _ = save_register_info(info.clone());
                Some(info)
            }
            None => None,
        },
    }
}

pub fn save_register_info(info: RegisterInfo) -> Result<(), Box<dyn Error>> {
    let mut config = load_config()?;
    config.register = Some(info);
    save_config(&config)
}

fn get_register_info_old() -> Option<RegisterInfo> {
    let b64_data = std::fs::read_to_string(REGISTER_FILE).ok()?;
    let json_data = STANDARD.decode(b64_data).ok()?;
    let record = serde_json::from_slice::<RegisterInfo>(&json_data[..]).ok()?;
    return Some(record);
}

fn load_config() -> Result<Config, Box<dyn Error>> {
    let mut file = match File::open(CONFIG_DAT) {
        Ok(file) => file,
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                return Ok(Config::default());
            } else {
                return Err(Box::new(e));
            }
        }
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: Config = serde_json::from_str(&contents)?;
    Ok(config)
}

fn save_config(config: &Config) -> Result<(), Box<dyn Error>> {
    let json_str = serde_json::to_string(config)?;
    let mut file = File::create(CONFIG_DAT)?;
    file.write_all(json_str.as_bytes())?;
    Ok(())
}


#[cfg(test)]
mod tests {        
    use super::{RegisterInfo, save_register_info};
    #[test]
    fn test_save_config() {
        let mut config = RegisterInfo::default();
        config.machine_id = "xxxx".to_string();
        let _ = save_register_info(config);
    }
}