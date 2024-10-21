use self::UrlType::{Invoke, Ws};
use super::MetadataAdapter;
use crate::common::config;
use crate::network::mock_enabled;

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Condvar, LazyLock, Mutex};
use std::{net::ToSocketAddrs, sync::Arc};

use log::info;
use tokio::runtime::Builder;
use url::Url;

const WS_URL_MOCK: &str = "ws://notify:8086/ws";
const WS_URLS: [&'static str; 4] = [
    "wss://notify.tat-tc.tencent.cn:8186/ws",
    "wss://notify.tat-tc.tencent.com.cn:8186/ws",
    "wss://notify.tat-tc.tencentyun.com:8186/ws",
    "wss://notify.tat.tencent-cloud.com:8186/ws",
];
const INVOKE_URL_MOCK: &str = "http://invoke";
const INVOKE_URLS: [&'static str; 4] = [
    "https://invoke.tat-tc.tencent.cn",
    "https://invoke.tat-tc.tencent.com.cn",
    "https://invoke.tat-tc.tencentyun.com",
    "https://invoke.tat.tencent-cloud.com",
];
const METADATA_URL_MOCK: &str = "http://mock-server:8000";
const METADATA_URL: &str = "http://metadata.tencentyun.com";

enum UrlType {
    Ws,
    Invoke,
}

impl UrlType {
    fn get_available_url(&self, region: Option<String>) -> String {
        self.config_url()
            .or_else(|| self.mock_url())
            .unwrap_or_else(|| {
                let rg = region.or_else(get_register_region).unwrap_or_default();
                if rg.is_empty() || rg == get_current_region() {
                    // Prioritize internal network for the same region
                    return find_available(self.intranet_urls(), dns_resolve);
                }
                self.public_url(&rg)
            })
    }

    fn intranet_urls(&self) -> &[&str] {
        match self {
            Ws => &WS_URLS,
            Invoke => &INVOKE_URLS,
        }
    }

    fn public_url(&self, region: &str) -> String {
        match self {
            Ws => format!("wss://{}.notify.tat-tc.tencent.cn:8186/ws", region),
            Invoke => format!("https://{}.invoke.tat-tc.tencent.cn", region),
        }
    }

    fn mock_url(&self) -> Option<String> {
        match self {
            _ if !mock_enabled() => None,
            Ws => Some(WS_URL_MOCK.to_owned()),
            Invoke => Some(INVOKE_URL_MOCK.to_owned()),
        }
    }

    fn config_url(&self) -> Option<String> {
        match self {
            Ws => config::get_ws_url(),
            Invoke => config::get_invoke_url(),
        }
    }
}

pub fn get_ws_url() -> String {
    let url = Ws.get_available_url(None);
    info!("get_ws_url: {}", url);
    url
}

pub fn get_invoke_url() -> String {
    let url = Invoke.get_available_url(None);
    info!("get_invoke_url: {}", url);
    url
}

pub fn get_register_url(region: &str) -> String {
    let url = Invoke.get_available_url(Some(region.to_owned()));
    info!("get_register_url: {}", url);
    return url;
}

pub fn get_meta_url() -> String {
    if mock_enabled() {
        return METADATA_URL_MOCK.to_string();
    }
    METADATA_URL.to_string()
}

fn dns_resolve(url: &str) -> bool {
    let url = Url::parse(url).expect("parse failed");
    let host = url.host().expect("host failed").to_string();
    format!("{}:{}", host, 80).to_socket_addrs().is_ok()
}

fn find_available(urls: &[&str], resolver: impl Fn(&str) -> bool) -> String {
    static IDX: AtomicUsize = AtomicUsize::new(0);
    let idx = IDX.load(SeqCst);
    // starts from the current idx, wraps around to the beginning of urls
    let mut iter = urls.iter().enumerate().cycle().skip(idx).take(urls.len());
    match iter.find(|(_, url)| resolver(url)) {
        Some((cur, url)) if cur != idx && cur != IDX.swap(cur, SeqCst) => {
            info!("cache index was changed to {}", cur);
            url.to_string()
        }
        _ => urls[idx].to_string(),
    }
}

fn get_register_region() -> Option<String> {
    config::get_register_info().map(|info| info.region)
}

fn get_current_region() -> String {
    static REGION: LazyLock<String> = LazyLock::new(|| {
        let region: Arc<Mutex<String>> = Arc::new(Mutex::new("".to_string()));
        let convar: Arc<Condvar> = Arc::new(Condvar::new());

        // Run the following code in a new thread, as it may be called inside or outside the tokio runtime.
        // Creating a tokio runtime multiple times will result in an error due to multiple runtime creation.
        std::thread::spawn({
            let region = region.clone();
            let convar = convar.clone();
            move || {
                *region.lock().expect("lock failed") = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("register runtime failed")
                    .block_on(async {
                        MetadataAdapter::build(&get_meta_url())
                            .region()
                            .await
                            .unwrap_or_default()
                    });

                convar.notify_one()
            }
        });

        let mut guard = region.lock().expect("lock failed");
        guard = convar.wait(guard).expect("wait failed");
        guard.clone()
    });

    info!("=>get_current_region: {}", *REGION);
    REGION.clone()
}

#[cfg(test)]
mod test {
    use super::{INVOKE_URLS, WS_URLS};
    use crate::network::urls::find_available;
    use std::sync::atomic::AtomicU8;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;

    #[test]
    fn test_find_available_url() {
        let resolve_1_cnt = Arc::new(AtomicU8::new(0));
        let count_1 = resolve_1_cnt.clone();
        let resolve_1 = |url: &str| {
            count_1.fetch_add(1, SeqCst);
            url.contains("tencentyun.com")
        };

        let resolve_2_cnt = Arc::new(AtomicU8::new(0));
        let count_2 = resolve_2_cnt.clone();
        let resolve_2 = |url: &str| {
            count_2.fetch_add(1, SeqCst);
            url.contains("tencent.com.cn")
        };

        let resolve_3_cnt = Arc::new(AtomicU8::new(0));
        let count_3 = resolve_3_cnt.clone();
        let resolve_3 = |_url: &str| {
            count_3.fetch_add(1, SeqCst);
            false
        };

        let url = find_available(&WS_URLS, resolve_1);
        assert_eq!(url, "wss://notify.tat-tc.tencentyun.com:8186/ws");
        assert_eq!(resolve_1_cnt.load(SeqCst), 3);

        let url = find_available(&INVOKE_URLS, resolve_2);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_2_cnt.load(SeqCst), 4);

        //use last ok, count eq urls len
        let url = find_available(&INVOKE_URLS, resolve_3);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_3_cnt.load(SeqCst), 4);
    }
}
