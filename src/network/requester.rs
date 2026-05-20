use std::sync::LazyLock;
use std::time::Duration;

use anyhow::Result;
use log::{error, info, warn};
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Client, ClientBuilder, RequestBuilder, Response};
use serde::Serialize;

const HTTP_REQUEST_TIMEOUT: u64 = 5;

static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    ClientBuilder::new()
        .pool_max_idle_per_host(1)
        .timeout(Duration::from_secs(HTTP_REQUEST_TIMEOUT))
        .build()
        .expect("network: failed to create http client")
});

pub struct HttpRequester {
    rb: RequestBuilder,
    retries: u64,
    interval: Duration,
}

impl HttpRequester {
    pub fn get(url: &str) -> Self {
        info!("send request to: {}", url);
        Self::new(HTTP_CLIENT.get(url))
    }

    pub fn post<T: Serialize>(url: &str, body: &T) -> Self {
        let body = serde_json::to_string(body).expect("body serde_json failed");
        info!("send request to {}, request body: {}", url, body);
        Self::new(HTTP_CLIENT.post(url).body(body))
    }

    pub fn timeout(self, timeout: u64) -> Self {
        let rb = self.rb.timeout(Duration::from_secs(timeout));
        Self { rb, ..self }
    }

    pub fn headers(self, headers: HeaderMap<HeaderValue>) -> Self {
        let rb = self.rb.headers(headers);
        Self { rb, ..self }
    }

    pub fn retries(self, retries: u64) -> Self {
        Self { retries, ..self }
    }

    pub fn retry_interval(self, interval: Duration) -> Self {
        Self { interval, ..self }
    }

    pub async fn send(self) -> Result<Response> {
        let rb = self.rb.header(header::CONNECTION, "close");
        let total = self.retries + 1;

        for i in 1..total {
            let Some(cloned) = rb.try_clone() else {
                warn!("request body try_clone failed, only 1 attempt made");
                break;
            };
            match cloned.send().await.map_err(anyhow::Error::from) {
                Ok(resp) => return Ok(resp),
                Err(e) => warn!("request error: {e:#}, attempt {} of {}", i, total),
            }
            tokio::time::sleep(self.interval).await;
        }

        rb.send()
            .await
            .map_err(anyhow::Error::from)
            .inspect_err(|e| error!("request error: {e:#}, attempt {total} of {total}"))
    }

    fn new(rb: RequestBuilder) -> Self {
        Self {
            rb,
            retries: 0,
            interval: Duration::from_millis(500),
        }
    }
}
