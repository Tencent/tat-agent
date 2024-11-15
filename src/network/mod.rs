use crate::common::config::{self, RegisterInfo};
use crate::common::utils::{gen_rand_str_with, get_now_secs};
use crate::sysinfo::{get_hostname, get_local_ip, Uname};
use std::env;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use log::{error, info};
use reqwest::header::HeaderValue;
use reqwest::header::{self, HeaderMap};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use sha1::{Digest, Sha1};

pub mod cos_adapter;
pub mod types;
pub mod urls;
pub mod ws;

mod invoke_adapter;
mod metadata_adapter;
mod requester;

pub use invoke_adapter::InvokeAdapter;
pub use metadata_adapter::MetadataAdapter;
pub use requester::HttpRequester;

const VPCID_HEADER: &str = "Tat-Vpcid";
const VIP_HEADER: &str = "Tat-Vip";
const WS_VERSION_HEADER: &str = "Tat-Version";
const WS_KERNEL_NAME_HEADER: &str = "Tat-KernelName";
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn mock_enabled() -> bool {
    return env::var("MOCK_ENABLE").map(|_| true).unwrap_or(false);
}

fn mock_vpcid() -> String {
    return env::var("MOCK_VPCID").unwrap_or("123456".to_string());
}

fn mock_vip() -> String {
    return env::var("MOCK_VIP").unwrap_or("192.168.0.1".to_string());
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

    let record: RegisterInfo = match config::get_register_info() {
        Some(record) => record,
        None => return headers,
    };

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

    let rand_key = gen_rand_str_with(32);
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

pub fn register(region: &str, register_id: &str, register_value: &str) -> Result<()> {
    //temp runtime in current thread
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("register runtime failed")
        .block_on(async move {
            let adapter = InvokeAdapter::new();
            adapter
                .register_instance(region, register_id, register_value)
                .await
        })
        .and_then(|record| config::save_register_info(record).context("save_register_info failed"))
}

pub fn check() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("check runtime failed")
        .block_on(async move {
            if let Some(record) = config::get_register_info() {
                info!("find register info, try validate");
                let adapter = InvokeAdapter::new();
                let local_ip = get_local_ip().expect("get_local_ip failed");
                let hostname = get_hostname().expect("get_hostname failed");
                match adapter.validate_instance(&hostname, &local_ip).await {
                    Ok(_) => info!("validate_instance success, work as register instance"),
                    Err(e) => error!("validate_instance failed: {e}, work as normal instance"),
                }
                let _ = config::save_register_info(record);
            }
        });
}
