use crate::common::config;
use crate::network::mock_enabled;
use std::net::ToSocketAddrs;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;

use log::info;
use url::Url;

const METADATA_API_MOCK: &str = "http://mock-server:8000";
const METADATA_API: &str = "http://metadata.tencentyun.com";
const WS_URL_MOCK: &str = "ws://proxy:8086/ws";
const WS_URLS: [&'static str; 4] = [
    "wss://notify.tat-tc.tencent.cn:8186/ws",
    "wss://notify.tat-tc.tencent.com.cn:8186/ws",
    "wss://notify.tat-tc.tencentyun.com:8186/ws",
    "wss://notify.tat.tencent-cloud.com:8186/ws",
];
const INVOKE_API_MOCK: &str = "http://proxy-invoke";
const INVOKE_APIS: [&'static str; 4] = [
    "https://invoke.tat-tc.tencent.cn",
    "https://invoke.tat-tc.tencent.com.cn",
    "https://invoke.tat-tc.tencentyun.com",
    "https://invoke.tat.tencent-cloud.com",
];

pub fn get_ws_url() -> String {
    let result = if let Some(url) = config::get_ws_url() {
        url
    } else if mock_enabled() {
        WS_URL_MOCK.to_string()
    } else if let Some(region) = get_register_region() {
        format!("wss://{}.notify.tat-tc.tencent.cn:8186/ws", region)
    } else {
        find_available_url(Vec::from(WS_URLS), dns_resolve)
    };
    info!("get_ws_url {}", result);
    return result;
}

pub fn get_invoke_url() -> String {
    let result = if let Some(url) = config::get_invoke_url() {
        url
    } else if mock_enabled() {
        INVOKE_API_MOCK.to_string()
    } else if let Some(region) = get_register_region() {
        format!("https://{}.invoke.tat-tc.tencent.cn", region)
    } else {
        find_available_url(Vec::from(INVOKE_APIS), dns_resolve)
    };
    info!("get_invoke_url {}", result);
    return result;
}

fn dns_resolve(url: &str) -> Result<(), ()> {
    let url = Url::parse(url).expect("parse fail");
    let host = url.host().expect("host fail").to_string();
    return match format!("{}:{}", host, 80).to_socket_addrs() {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    };
}

fn find_available_url<F>(urls: Vec<&str>, resolver: F) -> String
where
    F: Fn(&str) -> Result<(), ()>,
{
    static IDX: AtomicUsize = AtomicUsize::new(0);
    let idx = IDX.load(SeqCst);
    let mut cur = idx;
    for _ in 0..urls.len() {
        if resolver(urls[cur]).is_ok() {
            if cur != idx && cur != IDX.swap(cur, SeqCst) {
                info!("cache index was changed to {}", cur);
            }
            return urls[cur].to_string();
        }
        cur = (cur + 1) % urls.len();
    }
    urls[idx].to_string()
}

fn get_register_region() -> Option<String> {
    if let Some(info) = config::get_register_info() {
        return Some(info.region);
    }
    None
}

pub fn get_meta_url() -> String {
    if mock_enabled() {
        return METADATA_API_MOCK.to_string();
    } else {
        return METADATA_API.to_string();
    }
}

pub fn get_register_url(region: &str) -> String {
    let result = if let Some(url) = config::get_invoke_url() {
        url
    } else if mock_enabled() {
        INVOKE_API_MOCK.to_string()
    } else {
        format!("https://{}.invoke.tat-tc.tencent.cn", region)
    };
    info!("get_register_url {}", result);
    return result;
}

#[cfg(test)]
mod test {
    use super::{INVOKE_APIS, WS_URLS};
    use crate::network::urls::find_available_url;
    use std::sync::atomic::AtomicU8;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;

    #[test]
    fn test_find_available_url() {
        let resolve_1_cnt = Arc::new(AtomicU8::new(0));
        let count_1 = resolve_1_cnt.clone();
        let resolve_1 = |url: &str| {
            count_1.fetch_add(1, SeqCst);
            if url.contains("tencentyun.com") {
                return Ok(());
            } else {
                Err(())
            }
        };

        let resolve_2_cnt = Arc::new(AtomicU8::new(0));
        let count_2 = resolve_2_cnt.clone();
        let resolve_2 = |url: &str| {
            count_2.fetch_add(1, SeqCst);
            if url.contains("tencent.com.cn") {
                return Ok(());
            } else {
                Err(())
            }
        };

        let resolve_3_cnt = Arc::new(AtomicU8::new(0));
        let count_3 = resolve_3_cnt.clone();
        let resolve_3 = |_url: &str| {
            count_3.fetch_add(1, SeqCst);
            Err(())
        };

        let url = find_available_url(Vec::from(WS_URLS), resolve_1);
        assert_eq!(url, "wss://notify.tat-tc.tencentyun.com:8186/ws");
        assert_eq!(resolve_1_cnt.load(SeqCst), 3);

        let url = find_available_url(Vec::from(INVOKE_APIS), resolve_2);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_2_cnt.load(SeqCst), 4);

        //use last ok, count eq urls len
        let url = find_available_url(Vec::from(INVOKE_APIS), resolve_3);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_3_cnt.load(SeqCst), 4);
    }
}
