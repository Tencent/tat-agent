// 用于封装访问HTTP API的方法

use super::urls::{get_invoke_url, get_register_url};
use super::{build_extra_headers, RegisterInfo};
use crate::common::utils::generate_rsa_key;
use crate::network::types::{
    AgentError, AgentErrorCode, AgentRequest, CheckUpdateRequest, CheckUpdateResponse,
    DescribeTasksRequest, DescribeTasksResponse, HttpMethod, RegisterInstanceRequest,
    RegisterInstanceResponse, ReportResourceRequest, ReportResourceResponse,
    ReportTaskFinishRequest, ReportTaskFinishResponse, ReportTaskStartRequest,
    ReportTaskStartResponse, ServerRawResponse, UploadTaskLogRequest, UploadTaskLogResponse,
    ValidateInstanceRequest, ValidateInstanceResponse,
};
use crate::network::HttpRequester;
use crate::sysinfo::{get_hostname, get_local_ip, get_machine_id};

use log::{error, info};
use reqwest::Response;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::from_str;

const HTTP_REQUEST_RETRIES: u64 = 3;
const HTTP_REQUEST_NO_RETRIES: u64 = 1;

#[cfg_attr(test, faux::create)]
pub struct InvokeAPIAdapter;

#[cfg_attr(test, faux::methods)]
impl InvokeAPIAdapter {
    pub fn new() -> InvokeAPIAdapter {
        InvokeAPIAdapter
    }

    pub async fn register_instance(
        &self,
        region: &String,
        register_id: &String,
        register_value: &String,
    ) -> Result<RegisterInfo, String> {
        let machine_id = get_machine_id().ok_or("get_machine_id failed")?;
        let local_ip = get_local_ip().ok_or("get_local_ip failed")?;
        let hostname = get_hostname().ok_or("get_hostname failed")?;
        let (pubkey, privkey) = generate_rsa_key().ok_or("generate_rsa_key failed")?;

        let body = RegisterInstanceRequest::new(
            machine_id.clone(),
            register_id.clone(),
            register_value.clone(),
            pubkey,
            hostname,
            local_ip,
        );

        let url = get_register_url(region);
        let resp: RegisterInstanceResponse = self
            .send("RegisterInstance", &url, body, HTTP_REQUEST_NO_RETRIES)
            .await
            .map_err(|err| err.message)?;

        let record = RegisterInfo {
            region: region.to_string(),
            register_code: register_id.to_string(),
            register_value: register_value.to_string(),
            machine_id,
            private_key: privkey,
            instance_id: resp.instance_id.clone(),
            available: true,
        };
        Ok(record)
    }

    pub async fn describe_tasks(&self) -> Result<DescribeTasksResponse, AgentError<String>> {
        let req = DescribeTasksRequest {};
        self.send(
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
    ) -> Result<ReportTaskStartResponse, AgentError<String>> {
        let req = ReportTaskStartRequest {
            invocation_task_id: invocation_task_id.to_string(),
            time_stamp: start_timestamp,
        };
        self.send(
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
    ) -> Result<ReportTaskFinishResponse, AgentError<String>> {
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
        self.send(
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
    ) -> Result<UploadTaskLogResponse, AgentError<String>> {
        let task_log = UploadTaskLogRequest::new(task_id, idx, output, dropped);
        self.send(
            "UploadTaskLog",
            &get_invoke_url(),
            task_log,
            HTTP_REQUEST_RETRIES,
        )
        .await
    }

    pub async fn check_update(&self) -> Result<CheckUpdateResponse, AgentError<String>> {
        let body = CheckUpdateRequest::new();
        self.send(
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
    ) -> Result<ReportResourceResponse, AgentError<String>> {
        let body = ReportResourceRequest::new(fd_avg, mem_avg, zp_cnt);
        self.send(
            "ReportResource",
            &get_invoke_url(),
            body,
            HTTP_REQUEST_NO_RETRIES,
        )
        .await
    }

    pub async fn validate_instance(
        &self,
        hostname: String,
        local_ip: String,
    ) -> Result<ValidateInstanceResponse, AgentError<String>> {
        let body = ValidateInstanceRequest::new(hostname, local_ip);
        self.send(
            "ValidateInstance",
            &get_invoke_url(),
            body,
            HTTP_REQUEST_NO_RETRIES,
        )
        .await
    }

    // parse standard formatted response to custom type
    async fn send<T: Serialize + std::fmt::Debug, R: DeserializeOwned>(
        &self,
        action: &str,
        url: &str,
        request: T,
        retries: u64,
    ) -> Result<R, AgentError<String>> {
        let mut retry_cnt = 0;
        let body = AgentRequest::new(action, request);
        loop {
            let reqwest_resp_result = HttpRequester::new(url)
                .with_time_out(10)
                .send_request::<AgentRequest<T>>(
                    HttpMethod::POST,
                    "/",
                    Some(&body),
                    Some(build_extra_headers()),
                )
                .await;

            match reqwest_resp_result {
                Ok(reqwest_resp) => return self.parse(reqwest_resp).await,
                Err(ref e) => {
                    if retry_cnt < retries {
                        retry_cnt = retry_cnt + 1;
                        info!("request error: {:?}, retry {}", e, retry_cnt);
                        continue;
                    }
                    error!("request error reached {} times", retry_cnt);
                    return Err(e.clone());
                }
            }
        }
    }

    async fn parse<T: DeserializeOwned>(
        &self,
        reqwest_resp: Response,
    ) -> Result<T, AgentError<String>> {
        let txt = reqwest_resp.text().await.map_err(|e| {
            AgentError::new(
                AgentErrorCode::ResponseReadError,
                &format!("failed to read response: {:?}", e),
            )
        })?;

        info!("response text {:?}", txt);
        let raw_resp = from_str::<'_, ServerRawResponse<T>>(&txt).map_err(|e| {
            AgentError::new(
                AgentErrorCode::JsonDecodeError,
                &format!("failed to parse json response: {:?}", e),
            )
        })?;

        raw_resp.into_response().map_err(|e| {
            AgentError::wrap(
                AgentErrorCode::ResponseEmptyError,
                "empty response content",
                format!("response error: {:?}", e),
            )
        })
    }
}
