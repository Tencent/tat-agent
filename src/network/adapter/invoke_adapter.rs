use crate::common::sysinfo::{hostname, local_ip, machine_id};
use crate::common::{config::RegisterInfo, generate_rsa_key};
use crate::network::urls::{get_invoke_url, get_register_url};
use crate::network::*;

use std::{fmt::Debug, future::Future, time::Duration};

use anyhow::{Context, Result};
use log::info;
use reqwest::Response;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::from_str;

const RETRIES: u64 = 2;
const NO_RETRY: u64 = 0;

pub struct InvokeAdapter;

impl Invoke for InvokeAdapter {}

pub trait Invoke {
    fn register_instance(
        region: &str,
        register_id: &str,
        register_value: &str,
    ) -> impl Future<Output = Result<RegisterInfo>> + Send {
        async move {
            let machine_id = machine_id().context("get machine_id failed")?.to_owned();
            let local_ip = local_ip().context("get local_ip failed")?;
            let hostname = hostname().context("get hostname failed")?;
            let (public_key, private_key) =
                generate_rsa_key().context("generate_rsa_key failed")?;

            let req = RegisterInstanceRequest::new(
                machine_id.clone(),
                register_id.to_owned(),
                register_value.to_owned(),
                public_key,
                hostname,
                local_ip,
            );

            let url = get_register_url(region).await;
            let resp: RegisterInstanceResponse =
                call_invoke_api("RegisterInstance", &url, req, RETRIES).await?;

            let record = RegisterInfo {
                region: region.to_string(),
                register_code: register_id.to_string(),
                register_value: register_value.to_string(),
                machine_id,
                private_key,
                instance_id: resp.instance_id.clone(),
            };
            Ok(record)
        }
    }

    fn describe_tasks() -> impl Future<Output = Result<DescribeTasksResponse>> + Send {
        async {
            let req = DescribeTasksRequest {};
            call_invoke_api("DescribeTasks", &get_invoke_url().await, req, RETRIES).await
        }
    }

    fn report_task_start(
        invocation_task_id: &str,
        start_timestamp: u64,
    ) -> impl Future<Output = Result<ReportTaskStartResponse>> + Send {
        async move {
            let req = ReportTaskStartRequest {
                invocation_task_id: invocation_task_id.to_string(),
                time_stamp: start_timestamp,
            };
            call_invoke_api("ReportTaskStart", &get_invoke_url().await, req, RETRIES).await
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn report_task_finish(
        invocation_task_id: &str,
        result: &str,
        err_info: &str,
        exit_code: i32,
        final_log_index: Option<u32>,
        finish_timestamp: u64,
        output_url: &str,
        output_err_info: &str,
        _dropped: u64, // only for test
    ) -> impl Future<Output = Result<ReportTaskFinishResponse>> + Send {
        async move {
            let req = ReportTaskFinishRequest {
                invocation_task_id: invocation_task_id.to_string(),
                time_stamp: finish_timestamp,
                result: result.to_string(),
                error_info: err_info.to_string(),
                exit_code,
                final_log_index,
                output_url: output_url.to_string(),
                output_error_info: output_err_info.to_string(),
            };
            call_invoke_api("ReportTaskFinish", &get_invoke_url().await, req, RETRIES).await
        }
    }

    fn upload_task_log(
        task_id: &str,
        idx: u32,
        output: Vec<u8>,
        dropped: u64,
    ) -> impl Future<Output = Result<UploadTaskLogResponse>> + Send {
        async move {
            let req = UploadTaskLogRequest::new(task_id, idx, output, dropped);
            call_invoke_api("UploadTaskLog", &get_invoke_url().await, req, RETRIES).await
        }
    }

    fn check_update() -> impl Future<Output = Result<CheckUpdateResponse>> + Send {
        async move {
            let req = CheckUpdateRequest::new();
            call_invoke_api("CheckUpdate", &get_invoke_url().await, req, NO_RETRY).await
        }
    }

    fn validate_instance(
        hostname: &str,
        local_ip: &str,
    ) -> impl Future<Output = Result<ValidateInstanceResponse>> + Send {
        async move {
            let req = ValidateInstanceRequest::new(hostname, local_ip);
            call_invoke_api("ValidateInstance", &get_invoke_url().await, req, RETRIES).await
        }
    }

    fn get_cos_credential(
        task_id: &str,
    ) -> impl Future<Output = Result<GetTmpCredentialResponse>> + Send {
        async move {
            let req = GetCosCredentialRequest::new(task_id);
            call_invoke_api("GetCosCredential", &get_invoke_url().await, req, RETRIES).await
        }
    }

    fn report_agent_log(
        level: &str,
        log: &str,
    ) -> impl Future<Output = Result<ReportAgentLogResponse>> + Send {
        async move {
            let req = ReportAgentLogRequest::new(level, log);
            call_invoke_api("ReportAgentLog", &get_invoke_url().await, req, RETRIES).await
        }
    }
}

async fn call_invoke_api<T, R>(action: &str, url: &str, request: T, retries: u64) -> Result<R>
where
    T: Serialize + Debug + Send,
    R: DeserializeOwned,
{
    let body = AgentRequest::new(action, request);
    let resp = HttpRequester::post(url, &body)
        .timeout(10)
        .headers(build_extra_headers().await)
        .retries(retries)
        .retry_interval(Duration::from_millis(500))
        .send()
        .await?;
    parse(resp).await
}

// parse standard formatted response to custom type
async fn parse<T: DeserializeOwned>(reqwest_resp: Response) -> Result<T> {
    let txt = reqwest_resp.text().await?;
    info!("response text {}", txt);
    let raw_resp = from_str::<ServerRawResponse<T>>(&txt)?;
    raw_resp.into_response()
}

impl InvokeAdapter {
    pub async fn log(log: &str) {
        let _ = InvokeAdapter::report_agent_log("ERROR", log).await;
        error!("{log}");
    }
}
