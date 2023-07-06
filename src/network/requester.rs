use crate::network::types::{AgentError, AgentErrorCode, HttpMethod};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use log::{debug, error, info};
use once_cell::sync::Lazy;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Client, ClientBuilder, Response};
use serde::Serialize;
use serde_json::to_string;

const HTTP_REQUEST_TIME_OUT: u64 = 5;

static HTTP_CLIENT: Lazy<Arc<Client>> = Lazy::new(|| {
    Arc::new({
        ClientBuilder::new()
            .pool_max_idle_per_host(1)
            .build()
            .expect("failed to create http client")
    })
});

pub struct HttpRequester {
    url: String,
    time_out: AtomicU64,
}

impl HttpRequester {
    pub fn new(url: &str) -> HttpRequester {
        HttpRequester {
            url: url.to_string(),
            time_out: AtomicU64::new(HTTP_REQUEST_TIME_OUT),
        }
    }

    pub fn with_time_out(&self, time_out: u64) -> &Self {
        self.time_out.store(time_out, Ordering::SeqCst);
        self
    }

    pub async fn send_request<T: Serialize + fmt::Debug>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&T>,
        extra_headers: Option<HeaderMap<HeaderValue>>,
    ) -> Result<Response, AgentError<String>> {
        let extra_headers = match extra_headers {
            Some(headers) => headers,
            None => HeaderMap::new(),
        };
        match (method, body) {
            (HttpMethod::POST, Some(b)) => self.call_post(path, b, extra_headers).await,
            (HttpMethod::POST, None) => Err(AgentError::new(
                AgentErrorCode::RequestEmptyError,
                "empty request body",
            )),
            (HttpMethod::GET, _) => self.call_get(path, extra_headers).await,
        }
    }

    async fn call_get(
        &self,
        path: &str,
        extra_headers: HeaderMap<HeaderValue>,
    ) -> Result<Response, AgentError<String>> {
        let url = format!("{}{}", self.url, path);
        info!("send request to: {}", url);
        let time_out = self.time_out.load(Ordering::SeqCst);
        let request_builder = HTTP_CLIENT
            .get(&url)
            .header(header::CONNECTION, "close")
            .headers(extra_headers)
            .timeout(std::time::Duration::from_secs(time_out));
        let resp_res = request_builder.send().await;
        match resp_res {
            Ok(resp) => {
                debug!("recv response: {:?}", resp);
                Ok(resp)
            }
            Err(err) => {
                let agent_err = AgentError::wrap(
                    AgentErrorCode::ResponseEmptyError,
                    &format!("request error: {}", err),
                    format!("{:?}", err),
                );
                error!("{:?}", agent_err);
                Err(agent_err)
            }
        }
    }

    async fn call_post<T: Serialize + fmt::Debug>(
        &self,
        path: &str,
        body: &T,
        extra_headers: HeaderMap<HeaderValue>,
    ) -> Result<Response, AgentError<String>> {
        let url = format!("{}{}", self.url, path);
        info!("send request to {}, request body: {:?}", url, body);

        let time_out = self.time_out.load(Ordering::SeqCst);
        let request_builder = HTTP_CLIENT
            .post(&url)
            .header(header::CONNECTION, "close")
            .headers(extra_headers)
            .timeout(std::time::Duration::from_secs(time_out));

        let resp_res = request_builder.body(to_string(&body).unwrap()).send().await;
        match resp_res {
            Ok(resp) => {
                debug!("recv response: {:?}", resp);
                Ok(resp)
            }
            Err(err) => {
                let agent_err = AgentError::wrap(
                    AgentErrorCode::ResponseEmptyError,
                    &format!("request error: {}", err),
                    format!("{:?}", err),
                );
                error!("{:?}", agent_err);
                Err(agent_err)
            }
        }
    }
}
