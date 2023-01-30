pub mod cos;
mod invoke_adapter;
mod metadata_adapter;
mod requester;
pub mod types;
pub mod urls;
pub mod ws;
pub use invoke_adapter::InvokeAPIAdapter;
use log::error;
use log::info;
pub use metadata_adapter::MetadataAPIAdapter;
pub use requester::HttpRequester;

use crate::common::consts::AGENT_VERSION;
use crate::common::consts::REGISTER_FILE;
use crate::common::consts::WS_KERNEL_NAME_HEADER;
use crate::common::consts::WS_VERSION_HEADER;

use crate::sysinfo::get_hostname;
use crate::sysinfo::get_local_ip;
use crate::sysinfo::Uname;
use std::env;

use serde::Deserialize;
use serde::Serialize;

use crate::common::consts::{VIP_HEADER, VPCID_HEADER};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use reqwest::header::HeaderValue;
use reqwest::header::{self, HeaderMap};
use rsa::{pkcs1::DecodeRsaPrivateKey, PaddingScheme, RsaPrivateKey};
use sha1::{Digest, Sha1};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RegisterInfo {
    #[serde(default)]
    pub(crate) region: String,
    #[serde(default)]
    pub(crate) register_code: String,
    #[serde(default)]
    pub(crate) register_value: String,
    #[serde(default)]
    pub(crate) machine_id: String,
    #[serde(default)]
    pub(crate) private_key: String,
    #[serde(default)]
    pub(crate) instance_id: String,
    #[serde(default)]
    pub(crate) available: bool,
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
        let ba64_data = base64::encode(json_data);
        std::fs::write(REGISTER_FILE, ba64_data).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn load() -> Option<Self> {
        let b64_data = std::fs::read_to_string(REGISTER_FILE).ok()?;
        let json_data = base64::decode(b64_data).ok()?;
        let record = serde_json::from_slice::<RegisterInfo>(&json_data[..]).ok()?;
        return Some(record);
    }
}

fn build_extra_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        WS_VERSION_HEADER,
        header::HeaderValue::from_str(AGENT_VERSION).expect("build head fail"),
    );
    if let Ok(uname) = Uname::new() {
        headers.insert(
            WS_KERNEL_NAME_HEADER,
            header::HeaderValue::from_str(&uname.sys_name).expect("build head fail"),
        );
    }

    if mock_enabled() {
        headers.insert(
            VPCID_HEADER,
            header::HeaderValue::from_str(&mock_vpcid()).expect("build head fail"),
        );
        headers.insert(
            VIP_HEADER,
            header::HeaderValue::from_str(&mock_vip()).expect("build head fail"),
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
        HeaderValue::from_str(&record.machine_id).expect("build head fail"),
    );
    headers.insert(
        "InstanceId",
        HeaderValue::from_str(&record.instance_id).expect("build head fail"),
    );

    let rand_key: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    headers.insert(
        "RandomKey",
        HeaderValue::from_str(&rand_key).expect("build head fail"),
    );

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    headers.insert(
        "Timestamp",
        HeaderValue::from_str(&timestamp).expect("build head fail"),
    );

    //signature
    let data = format!(
        "{}{}{}{}",
        record.machine_id, record.instance_id, rand_key, timestamp
    );
    let digest: Vec<u8> = Sha1::digest(data.as_bytes()).to_vec();
    let sigvec = private_key
        .sign(PaddingScheme::new_pkcs1v15_sign::<Sha1>(), &digest[..])
        .expect("rsa sign fail");

    let signature = base64::encode(sigvec);
    headers.insert(
        "Signature",
        HeaderValue::from_str(&signature).expect("build head fail"),
    );

    headers
}

pub fn register(
    region: &String,
    register_code: &String,
    register_value: &String,
) -> Result<(), String> {
    //temp runtime in current thread
    match tokio::runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .expect("register runtime fail")
        .block_on(async move {
            let adapter = InvokeAPIAdapter::new();
            adapter
                .register_instance(region, register_code, register_value)
                .await
        }) {
        Ok(record) => record.save(),
        Err(err) => Err(err),
    }
}

pub fn check() {
    tokio::runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .expect("check runtime fail")
        .block_on(async move {
            if let Some(mut record) = RegisterInfo::load() {
                info!("find register info,try validate");
                let adapter = InvokeAPIAdapter::new();
                let local_ip = get_local_ip().expect("get_local_ip fail");
                let hostname = get_hostname().expect("get_hostname fail");
                if let Err(err) = adapter.validate_instance(hostname, local_ip).await {
                    error!("validate_instance fail {:?},work as normal instance", err);
                    record.available = false;
                } else {
                    record.available = true;
                    info!("validate_instance success,work as register instance");
                };
                let _ = record.save();
            }
        });
}
