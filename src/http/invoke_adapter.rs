// 用于封装访问HTTP API的方法
use log::{error, info};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::from_str;

use crate::common::consts::{HTTP_REQUEST_NO_RETRIES, HTTP_REQUEST_RETRIES};
use crate::http::{HttpRequester, Requester};
use crate::types::{
    AgentError, AgentErrorCode, AgentRequest, CheckUpdateRequest, CheckUpdateResponse,
    DescribeTasksRequest, DescribeTasksResponse, HttpMethod, ReportResourceRequest,
    ReportResourceResponse, ReportTaskFinishRequest, ReportTaskFinishResponse,
    ReportTaskStartRequest, ReportTaskStartResponse, ServerRawResponse, UploadTaskLogRequest,
    UploadTaskLogResponse,
};

#[cfg_attr(test, faux::create)]
pub struct InvokeAPIAdapter {
    requester: HttpRequester,
}

#[cfg_attr(test, faux::methods)]
impl InvokeAPIAdapter {
    pub fn build(url: &str) -> Self {
        let mut req = HttpRequester::new();
        req.initialize(url);
        InvokeAPIAdapter { requester: req }
    }

    pub async fn describe_tasks(&self) -> Result<DescribeTasksResponse, AgentError<String>> {
        let req = DescribeTasksRequest {};
        self.send("DescribeTasks", req, HTTP_REQUEST_RETRIES).await
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
        self.send("ReportTaskStart", req, HTTP_REQUEST_RETRIES)
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
        self.send("ReportTaskFinish", req, HTTP_REQUEST_RETRIES)
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
        self.send("UploadTaskLog", task_log, HTTP_REQUEST_RETRIES)
            .await
    }

    pub async fn check_update(&self) -> Result<CheckUpdateResponse, AgentError<String>> {
        let body = CheckUpdateRequest::new();
        self.send("CheckUpdate", body, HTTP_REQUEST_NO_RETRIES)
            .await
    }

    pub async fn report_resource(
        &self,
        fd_avg: u32,
        mem_avg: u32,
        zp_cnt: u32,
    ) -> Result<ReportResourceResponse, AgentError<String>> {
        let body = ReportResourceRequest::new(fd_avg, mem_avg, zp_cnt);
        self.send("ReportResource", body, HTTP_REQUEST_NO_RETRIES)
            .await
    }

    // parse standard formatted response to custom type
    async fn send<T: Serialize, R: DeserializeOwned>(
        &self,
        action: &str,
        request: T,
        retries: u64,
    ) -> Result<R, AgentError<String>> {
        let body = AgentRequest::new(action, request);
        let reqwest_resp = self
            .requester
            .with_time_out(10)
            .with_retrying(retries)
            .send_request::<AgentRequest<T>>(HttpMethod::POST, "/", Some(body))
            .await
            .map_err(|e| {
                error!("request error: {:?}", e);
                e
            })?;

        let txt = reqwest_resp.text().await.map_err(|e| {
            error!("failed to read response {:?}", e);
            AgentError::new(
                AgentErrorCode::ResponseReadError,
                &format!("failed to read response {:?}", e),
            )
        })?;

        info!("response text {:?}", txt);

        let raw_resp = from_str::<'_, ServerRawResponse<R>>(&txt).map_err(|e| {
            let agent_err = AgentError::new(
                AgentErrorCode::JsonDecodeError,
                &format!("failed to parse json response {:?}", e),
            );
            error!("{:?}", agent_err);
            agent_err
        })?;

        let resp_content = raw_resp.into_response().map_err(|resp_err| {
            let agent_err = AgentError::wrap(
                AgentErrorCode::ResponseEmptyError,
                "empty response content",
                format!("response error {:?}", resp_err),
            );
            error!("{:?}", agent_err);
            agent_err
        })?;

        Ok(resp_content)
    }
}
