mod requester;
mod types {
    pub mod http_msg;
    pub mod ws_msg;
}
pub mod urls;
pub mod ws;
mod adapter {
    pub mod cos_adapter;
    pub mod invoke_adapter;
    pub mod metadata_adapter;
}

pub use self::adapter::cos_adapter::COSAdapter;
pub use self::adapter::invoke_adapter::{Invoke, InvokeAdapter};
pub use self::adapter::metadata_adapter::MetadataAdapter;
pub use self::requester::HttpRequester;
pub use self::types::http_msg::*;
pub use self::types::ws_msg::*;
use crate::common::config::{get_register_info, save_register_info};
use crate::common::sysinfo::{get_hostname, get_local_ip, Uname};
use crate::common::{gen_rand_str_with, get_now_secs};

use std::{env, process};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use log::{error, info};
use reqwest::header::{HeaderMap, HeaderValue};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1v15::Pkcs1v15Sign, RsaPrivateKey};
use sha1::{Digest, Sha1};

const VPCID_HEADER: &str = "Tat-Vpcid";
const VIP_HEADER: &str = "Tat-Vip";
const PID_HEADER: &str = "Tat-Pid";
const WS_VERSION_HEADER: &str = "Tat-Version";
const WS_KERNEL_NAME_HEADER: &str = "Tat-KernelName";
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn mock_enabled() -> bool {
    env::var("MOCK_ENABLE").is_ok()
}

fn mock_vpcid() -> String {
    env::var("MOCK_VPCID").unwrap_or("123456".to_string())
}

fn mock_vip() -> String {
    env::var("MOCK_VIP").unwrap_or("192.168.0.1".to_string())
}

fn build_extra_headers() -> HeaderMap {
    fn value(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).expect("build head failed")
    }

    let mut headers = HeaderMap::new();
    headers.insert(WS_VERSION_HEADER, HeaderValue::from_static(AGENT_VERSION));
    headers.insert(PID_HEADER, HeaderValue::from(process::id()));

    if let Ok(uname) = Uname::new() {
        headers.insert(WS_KERNEL_NAME_HEADER, value(&uname.sys_name));
    }

    if mock_enabled() {
        headers.insert(VPCID_HEADER, value(&mock_vpcid()));
        headers.insert(VIP_HEADER, value(&mock_vip()));
    }

    let Some(record) = get_register_info() else {
        return headers;
    };
    let Ok(private_key) = RsaPrivateKey::from_pkcs1_pem(&record.private_key) else {
        return headers;
    };
    headers.insert("MachineId", value(&record.machine_id));
    headers.insert("InstanceId", value(&record.instance_id));

    let rand_key = gen_rand_str_with(32);
    headers.insert("RandomKey", value(&rand_key));

    let timestamp = get_now_secs().to_string();
    headers.insert("Timestamp", value(&timestamp));

    //signature
    let data = format!(
        "{}{}{}{}",
        record.machine_id, record.instance_id, rand_key, timestamp
    );
    let digest = Sha1::digest(data.as_bytes());
    let sigvec = private_key.sign(Pkcs1v15Sign::new::<Sha1>(), &digest);
    let signature = STANDARD.encode(sigvec.expect("rsa sign failed"));
    headers.insert("Signature", value(&signature));

    headers
}

#[tokio::main(flavor = "current_thread")]
pub async fn register(region: &str, register_id: &str, register_value: &str) -> Result<()> {
    let record = InvokeAdapter::register_instance(region, register_id, register_value).await?;
    save_register_info(record).context("save_register_info failed")
}

#[tokio::main(flavor = "current_thread")]
pub async fn check() {
    if let Some(record) = get_register_info() {
        info!("find register info, try validate");
        let local_ip = get_local_ip().expect("get_local_ip failed");
        let hostname = get_hostname().expect("get_hostname failed");
        match InvokeAdapter::validate_instance(&hostname, &local_ip).await {
            Ok(_) => info!("validate_instance success, work as register instance"),
            Err(e) => error!("validate_instance failed: {e:#}, work as normal instance"),
        }
        let _ = save_register_info(record);
    }
}
