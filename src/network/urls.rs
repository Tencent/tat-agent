use self::UrlType::{Invoke, Ws};
use super::MetadataAdapter;
use crate::common::config;
use crate::network::mock_enabled;

use std::borrow::Cow;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::info;
use tokio::sync::OnceCell;
use url::Url;

const WS_URL_MOCK: &str = "ws://notify:8086/ws";
const WS_URLS: [&str; 4] = [
    "wss://notify.tat-tc.tencent.cn:8186/ws",
    "wss://notify.tat-tc.tencent.com.cn:8186/ws",
    "wss://notify.tat-tc.tencentyun.com:8186/ws",
    "wss://notify.tat.tencent-cloud.com:8186/ws",
];
const INVOKE_URL_MOCK: &str = "http://invoke";
const INVOKE_URLS: [&str; 4] = [
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
    async fn get_available_url(&self, register_region: Option<String>) -> Cow<'static, str> {
        if let Some(url) = self.config_url().await.or_else(|| self.mock_url()) {
            return url.into();
        }
        let rins_rg = match register_region.as_deref() {
            Some(rg) => rg,
            None => get_register_region().await.unwrap_or_default(),
        };
        if rins_rg.is_empty() || rins_rg == get_current_region().await {
            // Prioritize internal network for the same region
            return find_available(self.intranet_urls(), dns_resolve).into();
        }
        self.public_url(rins_rg).into()
    }

    fn intranet_urls(&self) -> &[&'static str] {
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

    fn mock_url(&self) -> Option<&'static str> {
        match self {
            _ if !mock_enabled() => None,
            Ws => Some(WS_URL_MOCK),
            Invoke => Some(INVOKE_URL_MOCK),
        }
    }

    async fn config_url(&self) -> Option<&'static str> {
        match self {
            Ws => config::get_ws_url().await,
            Invoke => config::get_invoke_url().await,
        }
    }
}

pub async fn get_ws_url() -> Cow<'static, str> {
    let url = Ws.get_available_url(None).await;
    info!("get_ws_url: {}", url);
    url
}

pub async fn get_invoke_url() -> Cow<'static, str> {
    let url = Invoke.get_available_url(None).await;
    info!("get_invoke_url: {}", url);
    url
}

pub async fn get_register_url(region: &str) -> Cow<'static, str> {
    let url = Invoke.get_available_url(Some(region.to_owned())).await;
    info!("get_register_url: {}", url);
    url
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

fn find_available<'a>(urls: &[&'a str], resolver: impl Fn(&str) -> bool) -> &'a str {
    static IDX: AtomicUsize = AtomicUsize::new(0);
    let idx = IDX.load(Ordering::Relaxed);
    // starts from the current idx, wraps around to the beginning of urls
    let mut iter = urls.iter().enumerate().cycle().skip(idx).take(urls.len());
    match iter.find(|(_, url)| resolver(url)) {
        Some((cur, url)) if cur != idx && cur != IDX.swap(cur, Ordering::Relaxed) => {
            info!("cache index was changed to {}", cur);
            url
        }
        _ => urls[idx],
    }
}

async fn get_register_region() -> Option<&'static str> {
    config::get_register_info().await.map(|i| i.region.as_str())
}

async fn get_current_region() -> &'static str {
    static ONCE: OnceCell<String> = OnceCell::const_new();
    ONCE.get_or_init(|| async {
        let ma = MetadataAdapter::build(&get_meta_url());
        let rg = ma.region().await.unwrap_or_default();
        info!("=>get_current_region: {}", rg);
        rg
    })
    .await
}

#[cfg(test)]
mod test {
    use super::{INVOKE_URLS, WS_URLS};
    use crate::network::urls::find_available;
    use std::sync::atomic::AtomicU8;
    use std::sync::atomic::Ordering::Relaxed;
    use std::sync::Arc;

    #[test]
    fn test_find_available_url() {
        let resolve_1_cnt = Arc::new(AtomicU8::new(0));
        let count_1 = resolve_1_cnt.clone();
        let resolve_1 = |url: &str| {
            count_1.fetch_add(1, Relaxed);
            url.contains("tencentyun.com")
        };

        let resolve_2_cnt = Arc::new(AtomicU8::new(0));
        let count_2 = resolve_2_cnt.clone();
        let resolve_2 = |url: &str| {
            count_2.fetch_add(1, Relaxed);
            url.contains("tencent.com.cn")
        };

        let resolve_3_cnt = Arc::new(AtomicU8::new(0));
        let count_3 = resolve_3_cnt.clone();
        let resolve_3 = |_url: &str| {
            count_3.fetch_add(1, Relaxed);
            false
        };

        let url = find_available(&WS_URLS, resolve_1);
        assert_eq!(url, "wss://notify.tat-tc.tencentyun.com:8186/ws");
        assert_eq!(resolve_1_cnt.load(Relaxed), 3);

        let url = find_available(&INVOKE_URLS, resolve_2);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_2_cnt.load(Relaxed), 4);

        //use last ok, count eq urls len
        let url = find_available(&INVOKE_URLS, resolve_3);
        assert_eq!(url, "https://invoke.tat-tc.tencent.com.cn");
        assert_eq!(resolve_3_cnt.load(Relaxed), 4);
    }
}
