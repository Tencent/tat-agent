use crate::common::sysinfo::{get_hostname, get_local_ip, get_machine_id};
use crate::common::{config::RegisterInfo, generate_rsa_key};
use crate::network::urls::{get_invoke_url, get_register_url};
use crate::network::*;

use std::{fmt::Debug, future::Future, time::Duration};

use anyhow::{Context, Result};
use log::info;
use reqwest::Response;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::from_str;

const HTTP_REQUEST_RETRIES: u64 = 2;
const HTTP_REQUEST_NO_RETRIES: u64 = 0;

pub trait Invoke {
    fn call_invoke_api<T: Serialize + Debug + Send, R: DeserializeOwned>(
        action: &str,
        url: &str,
        request: T,
        retries: u64,
    ) -> impl Future<Output = Result<R>> + Send;

    fn register_instance(
        region: &str,
        register_id: &str,
        register_value: &str,
    ) -> impl Future<Output = Result<RegisterInfo>> + Send {
        async move {
            let machine_id = get_machine_id().context("get_machine_id failed")?;
            let local_ip = get_local_ip().context("get_local_ip failed")?;
            let hostname = get_hostname().context("get_hostname failed")?;
            let (publickey, privkey) = generate_rsa_key().context("generate_rsa_key failed")?;

            let body = RegisterInstanceRequest::new(
                machine_id.clone(),
                register_id.to_owned(),
                register_value.to_owned(),
                publickey,
                hostname,
                local_ip,
            );

            let url = get_register_url(region);
            let resp: RegisterInstanceResponse =
                Self::call_invoke_api("RegisterInstance", &url, body, HTTP_REQUEST_RETRIES).await?;

            let record = RegisterInfo {
                region: region.to_string(),
                register_code: register_id.to_string(),
                register_value: register_value.to_string(),
                machine_id,
                private_key: privkey,
                instance_id: resp.instance_id.clone(),
            };
            Ok(record)
        }
    }

    fn describe_tasks() -> impl Future<Output = Result<DescribeTasksResponse>> + Send {
        async {
            let req = DescribeTasksRequest {};
            Self::call_invoke_api(
                "DescribeTasks",
                &get_invoke_url(),
                req,
                HTTP_REQUEST_RETRIES,
            )
            .await
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
            Self::call_invoke_api(
                "ReportTaskStart",
                &get_invoke_url(),
                req,
                HTTP_REQUEST_RETRIES,
            )
            .await
        }
    }

    fn report_task_finish(
        invocation_task_id: &str,
        result: &str,
        err_info: &str,
        exit_code: i32,
        final_log_index: u32,
        finish_timestamp: u64,
        output_url: &str,
        output_err_info: &str,
        _dropped: u64,
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
            Self::call_invoke_api(
                "ReportTaskFinish",
                &get_invoke_url(),
                req,
                HTTP_REQUEST_RETRIES,
            )
            .await
        }
    }

    fn upload_task_log(
        task_id: &str,
        idx: u32,
        output: Vec<u8>,
        dropped: u64,
    ) -> impl Future<Output = Result<UploadTaskLogResponse>> + Send {
        async move {
            let task_log = UploadTaskLogRequest::new(task_id, idx, output, dropped);
            Self::call_invoke_api(
                "UploadTaskLog",
                &get_invoke_url(),
                task_log,
                HTTP_REQUEST_RETRIES,
            )
            .await
        }
    }

    fn check_update() -> impl Future<Output = Result<CheckUpdateResponse>> + Send {
        async move {
            let body = CheckUpdateRequest::new();
            Self::call_invoke_api(
                "CheckUpdate",
                &get_invoke_url(),
                body,
                HTTP_REQUEST_NO_RETRIES,
            )
            .await
        }
    }

    fn report_resource(
        fd_avg: u32,
        mem_avg: u32,
        zp_cnt: u32,
    ) -> impl Future<Output = Result<ReportResourceResponse>> + Send {
        async move {
            let body = ReportResourceRequest::new(fd_avg, mem_avg, zp_cnt);
            Self::call_invoke_api(
                "ReportResource",
                &get_invoke_url(),
                body,
                HTTP_REQUEST_NO_RETRIES,
            )
            .await
        }
    }

    fn validate_instance(
        hostname: &str,
        local_ip: &str,
    ) -> impl Future<Output = Result<ValidateInstanceResponse>> + Send {
        async move {
            let body = ValidateInstanceRequest::new(hostname, local_ip);
            Self::call_invoke_api(
                "ValidateInstance",
                &get_invoke_url(),
                body,
                HTTP_REQUEST_RETRIES,
            )
            .await
        }
    }

    fn get_cos_credential(
        task_id: &str,
    ) -> impl Future<Output = Result<GetTmpCredentialResponse>> + Send {
        async move {
            let body = GetCosCredentialRequest::new(task_id);
            Self::call_invoke_api(
                "GetCosCredential",
                &get_invoke_url(),
                body,
                HTTP_REQUEST_RETRIES,
            )
            .await
        }
    }
}

pub struct InvokeAdapter;

impl Invoke for InvokeAdapter {
    async fn call_invoke_api<T: Serialize + Debug + Send, R: DeserializeOwned>(
        action: &str,
        url: &str,
        request: T,
        retries: u64,
    ) -> Result<R> {
        let body = AgentRequest::new(action, request);
        let resp = HttpRequester::post(url, &body)
            .timeout(10)
            .headers(build_extra_headers())
            .retries(retries)
            .retry_interval(Duration::from_millis(500))
            .send()
            .await?;
        Ok(parse(resp).await?)
    }
}

// parse standard formatted response to custom type
async fn parse<T: DeserializeOwned>(reqwest_resp: Response) -> Result<T> {
    let txt = reqwest_resp.text().await?;
    info!("response text {}", txt);
    let raw_resp = from_str::<ServerRawResponse<T>>(&txt)?;
    Ok(raw_resp.into_response()?)
}
