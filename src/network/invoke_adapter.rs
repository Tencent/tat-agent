use super::build_extra_headers;
use super::urls::{get_invoke_url, get_register_url};
use crate::common::config::RegisterInfo;
use crate::common::utils::generate_rsa_key;
use crate::network::types::{
    AgentRequest, CheckUpdateRequest, CheckUpdateResponse, DescribeTasksRequest,
    DescribeTasksResponse, GetCosCredentialRequest, GetTmpCredentialResponse,
    RegisterInstanceRequest, RegisterInstanceResponse, ReportResourceRequest,
    ReportResourceResponse, ReportTaskFinishRequest, ReportTaskFinishResponse,
    ReportTaskStartRequest, ReportTaskStartResponse, ServerRawResponse, UploadTaskLogRequest,
    UploadTaskLogResponse, ValidateInstanceRequest, ValidateInstanceResponse,
};
use crate::network::HttpRequester;
use crate::sysinfo::{get_hostname, get_local_ip, get_machine_id};

use std::time::Duration;

use anyhow::{Context, Result};
use log::info;
use reqwest::Response;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::from_str;

const HTTP_REQUEST_RETRIES: u64 = 2;
const HTTP_REQUEST_NO_RETRIES: u64 = 0;

#[cfg_attr(test, faux::create)]
pub struct InvokeAdapter;

#[cfg_attr(test, faux::methods)]
impl InvokeAdapter {
    pub fn new() -> Self {
        Self
    }

    pub async fn register_instance(
        &self,
        region: &str,
        register_id: &str,
        register_value: &str,
    ) -> Result<RegisterInfo> {
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
            call_invoke_api("RegisterInstance", &url, body, HTTP_REQUEST_RETRIES).await?;

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

    pub async fn describe_tasks(&self) -> Result<DescribeTasksResponse> {
        let req = DescribeTasksRequest {};
        call_invoke_api(
            "DescribeTasks",
            &get_invoke_url(),
            req,
            HTTP_REQUEST_RETRIES,
        )
        .await
    }

    pub async fn report_task_start(
        &self,
        invocation_task_id: &str,
        start_timestamp: u64,
    ) -> Result<ReportTaskStartResponse> {
        let req = ReportTaskStartRequest {
            invocation_task_id: invocation_task_id.to_string(),
            time_stamp: start_timestamp,
        };
        call_invoke_api(
            "ReportTaskStart",
            &get_invoke_url(),
            req,
            HTTP_REQUEST_RETRIES,
        )
        .await
    }

    pub async fn report_task_finish(
        &self,
        invocation_task_id: &str,
        result: &str,
        err_info: &str,
        exit_code: i32,
        final_log_index: u32,
        finish_timestamp: u64,
        output_url: &str,
        output_err_info: &str,
    ) -> Result<ReportTaskFinishResponse> {
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
        call_invoke_api(
            "ReportTaskFinish",
            &get_invoke_url(),
            req,
            HTTP_REQUEST_RETRIES,
        )
        .await
    }

    pub async fn upload_task_log(
        &self,
        task_id: &str,
        idx: u32,
        output: Vec<u8>,
        dropped: u64,
    ) -> Result<UploadTaskLogResponse> {
        let task_log = UploadTaskLogRequest::new(task_id, idx, output, dropped);
        call_invoke_api(
            "UploadTaskLog",
            &get_invoke_url(),
            task_log,
            HTTP_REQUEST_RETRIES,
        )
        .await
    }

    pub async fn check_update(&self) -> Result<CheckUpdateResponse> {
        let body = CheckUpdateRequest::new();
        call_invoke_api(
            "CheckUpdate",
            &get_invoke_url(),
            body,
            HTTP_REQUEST_NO_RETRIES,
        )
        .await
    }

    pub async fn report_resource(
        &self,
        fd_avg: u32,
        mem_avg: u32,
        zp_cnt: u32,
    ) -> Result<ReportResourceResponse> {
        let body = ReportResourceRequest::new(fd_avg, mem_avg, zp_cnt);
        call_invoke_api(
            "ReportResource",
            &get_invoke_url(),
            body,
            HTTP_REQUEST_NO_RETRIES,
        )
        .await
    }

    pub async fn validate_instance(
        &self,
        hostname: &str,
        local_ip: &str,
    ) -> Result<ValidateInstanceResponse> {
        let body = ValidateInstanceRequest::new(hostname, local_ip);
        call_invoke_api(
            "ValidateInstance",
            &get_invoke_url(),
            body,
            HTTP_REQUEST_RETRIES,
        )
        .await
    }

    pub async fn get_cos_credential(&self, task_id: &str) -> Result<GetTmpCredentialResponse> {
        let body = GetCosCredentialRequest::new(task_id);
        call_invoke_api(
            "GetCosCredential",
            &get_invoke_url(),
            body,
            HTTP_REQUEST_RETRIES,
        )
        .await
    }
}

async fn call_invoke_api<T: Serialize + std::fmt::Debug, R: DeserializeOwned>(
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

// parse standard formatted response to custom type
async fn parse<T: DeserializeOwned>(reqwest_resp: Response) -> Result<T> {
    let txt = reqwest_resp.text().await?;
    info!("response text {}", txt);
    let raw_resp = from_str::<ServerRawResponse<T>>(&txt)?;
    Ok(raw_resp.into_response()?)
}
