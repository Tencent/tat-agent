use crate::common::utils::{gen_rand_str_with, get_now_secs};
use crate::sysinfo::{get_hostname, get_local_ip, Uname};
use std::env;

use base64::{engine::general_purpose::STANDARD, Engine};
use log::{error, info};
use reqwest::header::HeaderValue;
use reqwest::header::{self, HeaderMap};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

pub mod cos;
pub mod types;
pub mod urls;
pub mod ws;

mod invoke_adapter;
mod metadata_adapter;
mod requester;

pub use invoke_adapter::InvokeAPIAdapter;
pub use metadata_adapter::MetadataAPIAdapter;
pub use requester::HttpRequester;

const VPCID_HEADER: &str = "Tat-Vpcid";
const VIP_HEADER: &str = "Tat-Vip";
const REGISTER_FILE: &str = "register.dat";
const WS_VERSION_HEADER: &str = "Tat-Version";
const WS_KERNEL_NAME_HEADER: &str = "Tat-KernelName";
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize, Deserialize, Debug, Default)]
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
    #[serde(default)]
    pub available: bool,
}

fn mock_enabled() -> bool {
    return env::var("MOCK_ENABLE").map(|_| true).unwrap_or(false);
}

fn mock_vpcid() -> String {
    return env::var("MOCK_VPCID").unwrap_or("123456".to_string());
}

fn mock_vip() -> String {
    return env::var("MOCK_VIP").unwrap_or("192.168.0.1".to_string());
}

impl RegisterInfo {
    fn save(&self) -> Result<(), String> {
        let json_data = serde_json::to_string(self).map_err(|e| e.to_string())?;
        let ba64_data = STANDARD.encode(json_data);
        std::fs::write(REGISTER_FILE, ba64_data).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn load() -> Option<Self> {
        let b64_data = std::fs::read_to_string(REGISTER_FILE).ok()?;
        let json_data = STANDARD.decode(b64_data).ok()?;
        let record = serde_json::from_slice::<RegisterInfo>(&json_data[..]).ok()?;
        return Some(record);
    }
}

fn build_extra_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        WS_VERSION_HEADER,
        header::HeaderValue::from_str(AGENT_VERSION).expect("build head failed"),
    );
    if let Ok(uname) = Uname::new() {
        headers.insert(
            WS_KERNEL_NAME_HEADER,
            header::HeaderValue::from_str(&uname.sys_name).expect("build head failed"),
        );
    }

    if mock_enabled() {
        headers.insert(
            VPCID_HEADER,
            header::HeaderValue::from_str(&mock_vpcid()).expect("build head failed"),
        );
        headers.insert(
            VIP_HEADER,
            header::HeaderValue::from_str(&mock_vip()).expect("build head failed"),
        );
    }

    let record: RegisterInfo = match RegisterInfo::load() {
        Some(record) => record,
        None => return headers,
    };

    if !record.available {
        return headers;
    }

    let private_key = match RsaPrivateKey::from_pkcs1_pem(&record.private_key) {
        Ok(v) => v,
        Err(_) => return headers,
    };

    headers.insert(
        "MachineId",
        HeaderValue::from_str(&record.machine_id).expect("build head failed"),
    );
    headers.insert(
        "InstanceId",
        HeaderValue::from_str(&record.instance_id).expect("build head failed"),
    );

    let rand_key: String = gen_rand_str_with(32);
    headers.insert(
        "RandomKey",
        HeaderValue::from_str(&rand_key).expect("build head failed"),
    );

    let timestamp = get_now_secs().to_string();
    headers.insert(
        "Timestamp",
        HeaderValue::from_str(&timestamp).expect("build head failed"),
    );

    //signature
    let data = format!(
        "{}{}{}{}",
        record.machine_id, record.instance_id, rand_key, timestamp
    );
    let digest: Vec<u8> = Sha1::digest(data.as_bytes()).to_vec();
    let sigvec = private_key
        .sign(Pkcs1v15Sign::new::<Sha1>(), &digest[..])
        .expect("rsa sign failed");

    let signature = STANDARD.encode(sigvec);
    headers.insert(
        "Signature",
        HeaderValue::from_str(&signature).expect("build head failed"),
    );

    headers
}

pub fn register(
    region: &String,
    register_id: &String,
    register_value: &String,
) -> Result<(), String> {
    //temp runtime in current thread
    // tokio::runtime::Builder::new_current_thread()
    tokio::runtime::Builder::new().basic_scheduler()
        .enable_all()
        .build()
        .expect("register runtime failed")
        .block_on(async move {
            let adapter = InvokeAPIAdapter::new();
            adapter
                .register_instance(region, register_id, register_value)
                .await
        })
        .and_then(|record| record.save())
}

pub fn check() {
    // tokio::runtime::Builder::new_current_thread()
    tokio::runtime::Builder::new().basic_scheduler()
        .enable_all()
        .build()
        .expect("check runtime failed")
        .block_on(async move {
            if let Some(mut record) = RegisterInfo::load() {
                info!("find register info, try validate");
                let adapter = InvokeAPIAdapter::new();
                let local_ip = get_local_ip().expect("get_local_ip failed");
                let hostname = get_hostname().expect("get_hostname failed");
                if let Err(err) = adapter.validate_instance(hostname, local_ip).await {
                    error!("validate_instance failed: {err:?}, work as normal instance");
                    record.available = false;
                } else {
                    record.available = true;
                    info!("validate_instance success, work as register instance");
                };
                let _ = record.save();
            }
        });
}
