use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_std::task;
use log::{debug, error, info};
use reqwest::{header, Client, ClientBuilder, Response};
use serde::Serialize;
use serde_json::to_string;
use url::Url;

use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{
    HTTP_REQUEST_RETRY_INTERVAL, HTTP_REQUEST_TIME_OUT, VIP_HEADER, VPCID_HEADER,
};
use crate::common::envs;
use crate::types::{AgentError, AgentErrorCode, HttpMethod};

pub trait Requester: std::marker::Sized {
    fn initialize(&mut self, url: &str) -> Option<&Self>;
}

pub struct HttpRequester {
    url: String,
    time_out: AtomicU64,
    retries: AtomicU64,
    client: Option<Client>,
}

impl Requester for HttpRequester {
    fn initialize(&mut self, url: &str) -> Option<&Self> {
        match Url::parse(url) {
            Ok(_) => {
                let cli_builder = ClientBuilder::new();
                // use for e2e test.
                let mut headers = header::HeaderMap::new();
                if envs::enable_test() {
                    headers.insert(
                        VPCID_HEADER,
                        header::HeaderValue::from_str(&*envs::test_vpcid()).unwrap(),
                    );
                    headers.insert(
                        VIP_HEADER,
                        header::HeaderValue::from_str(&*envs::test_vip()).unwrap(),
                    );
                }

                let cli = cli_builder
                    .default_headers(headers)
                    .pool_max_idle_per_host(1)
                    .build()
                    .unwrap_or_exit("fail to create http client");
                self.url = url.to_string();
                self.client = Option::from(cli);
                Some(self)
            }
            Err(err) => {
                error!("fail to create http client, error: {}", err);
                None
            }
        }
    }
}

impl HttpRequester {
    pub fn new() -> HttpRequester {
        HttpRequester {
            url: String::from(""),
            client: Option::None,
            time_out: AtomicU64::new(HTTP_REQUEST_TIME_OUT),
            retries: AtomicU64::new(1),
        }
    }

    pub fn with_time_out(&self, time_out: u64) -> &Self {
        self.time_out.store(time_out, Ordering::SeqCst);
        self
    }

    pub fn with_retrying(&self, retries: u64) -> &Self {
        self.retries.store(retries, Ordering::SeqCst);
        self
    }

    pub async fn send_request<T: Serialize>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<T>,
    ) -> Result<Response, AgentError<String>> {
        match method {
            HttpMethod::POST if body.is_none() => Err(AgentError::new(
                AgentErrorCode::RequestEmptyError,
                "empty request body",
            )),
            HttpMethod::POST => self.call_post(path, body.unwrap()).await,
            HttpMethod::GET => self.call_get(path).await,
        }
    }

    async fn call_get(&self, path: &str) -> Result<Response, AgentError<String>> {
        let cli = self.client.as_ref().ok_or(AgentError::new(
            AgentErrorCode::ClientNotInitialized,
            "empty client",
        ))?;

        let url = format!("{}{}", self.url, path);
        info!("send request to :{}", url);
        let time_out = self.time_out.load(Ordering::SeqCst);
        let request_builder = cli
            .get(&url)
            .header(header::CONNECTION, "close")
            .timeout(std::time::Duration::from_secs(time_out));

        let resp = request_builder.send().await.map_err(|err| {
            let agent_err = AgentError::wrap(
                AgentErrorCode::ResponseEmptyError,
                &format!("request error: {}", err),
                format!("{:?}", err),
            );
            error!("{:?}", agent_err);
            agent_err
        })?;

        debug!("recv response: {:?}", resp);
        Ok(resp)
    }

    async fn call_post<T: Serialize>(
        &self,
        path: &str,
        body: T,
    ) -> Result<Response, AgentError<String>> {
        let cli = self.client.as_ref().ok_or(AgentError::new(
            AgentErrorCode::ClientNotInitialized,
            "empty client",
        ))?;

        let url = format!("{}{}", self.url, path);
        info!(
            "send request to {}, request body: {}",
            url,
            to_string(&body).unwrap()
        );
        let time_out = self.time_out.load(Ordering::SeqCst);
        let max_retries = self.retries.load(Ordering::SeqCst);

        for have_retries in 1..=max_retries {
            let request_builder = cli
                .post(&url)
                .header(header::CONNECTION, "close")
                .timeout(std::time::Duration::from_secs(time_out));
            let resp_res = request_builder.body(to_string(&body).unwrap()).send().await;
            match resp_res {
                Ok(resp) => {
                    debug!("recv response: {:?}", resp);
                    return Ok(resp);
                }
                Err(err) => {
                    let agent_err = AgentError::wrap(
                        AgentErrorCode::ResponseEmptyError,
                        &format!("request error: {}", err),
                        format!("{:?}", err),
                    );
                    error!("{:?}", agent_err);
                }
            };

            debug!(
                "have tried for {} times, max retry {} times",
                have_retries, max_retries
            );
            task::sleep(Duration::from_secs(HTTP_REQUEST_RETRY_INTERVAL)).await;
        }

        Err(AgentError::new(
            AgentErrorCode::MaxRetryFailures,
            "retry times exceeded",
        ))
    }
}
