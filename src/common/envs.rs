use log::info;
use std::env;
use std::net::ToSocketAddrs;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use url::Url;

use crate::common::consts::{INVOKE_APIS, INVOKE_API_DEBUG, WS_URLS, WS_URL_DEBUG};

pub fn enable_test() -> bool {
    cfg_if::cfg_if! {
        if #[cfg(debug_assertions)] {
           return true
        } else {
           return false
        }
    }
}

pub fn test_vpcid() -> String {
    return env::var("MOCK_VPCID").unwrap_or("123456".to_string());
}

pub fn test_vip() -> String {
    return env::var("MOCK_VIP").unwrap_or("192.168.0.1".to_string());
}

fn dns_resolve(url: &str) -> Result<(), ()> {
    let url = Url::parse(url).unwrap();
    let host = url.host().unwrap().to_string();
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
            if cur != idx && cur != IDX.swap(cur,SeqCst){
                info!("cache index was changed to {}", cur);
            }
            return urls[cur].to_string();
        }
        cur = (cur + 1) % urls.len();
    }
    urls[idx].to_string()
}

pub fn get_ws_url() -> String {
    let result;
    if enable_test() {
        result = WS_URL_DEBUG.to_string();
    } else {
        result = find_available_url(Vec::from(WS_URLS), dns_resolve);
    }
    info!("get_ws_url {}", result);
    return result;
}

pub fn get_invoke_url() -> String {
    let result;
    if enable_test() {
        result = INVOKE_API_DEBUG.to_string();
    } else {
        result = find_available_url(Vec::from(INVOKE_APIS), dns_resolve);
    }
    info!("get_invoke_url {}", result);
    return result;
}

#[cfg(test)]
mod test {
    use crate::common::consts::{INVOKE_APIS, WS_URLS};
    use crate::common::envs::find_available_url;
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
        assert_eq!(url, "ws://notify.tat-tc.tencentyun.com:8086/ws");
        assert_eq!(resolve_1_cnt.load(SeqCst), 3);

        let url = find_available_url(Vec::from(INVOKE_APIS), resolve_2);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_2_cnt.load(SeqCst), 4);

        //use last ok,count eq urls len
        let url = find_available_url(Vec::from(INVOKE_APIS), resolve_3);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_3_cnt.load(SeqCst), 4);
    }
}
