extern crate tat_agent;

use tat_agent::types::*;
use hyper::Body;
use hyper::Response;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;

// general parameters in request
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GeneralParameters {
    pub action: String,
}

// standard http request format
// combined general parameters with custom parameters
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct AgentRequest<T> {
    // general parameters for all kind of request, such as Action, etc.
    #[serde(flatten)]
    pub general_params: GeneralParameters,
    // user self defined parameters
    #[serde(flatten)]
    pub custom_params: T,
}

// general parameters in response, encapsulated in ServerRawResponse
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GeneralResponse<T> {
    // request id is always required
    request_id: String,
    // error is not None when some error happened
    error: Option<ResponseError>,
    // content is not None in most cases
    #[serde(flatten)]
    content: Option<T>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseError {
    code: String,
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Empty {}

pub type UploadTaskLogResponse = Empty;

// standard response format
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ServerRawResponse<T> {
    response: GeneralResponse<T>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct CheckUpdateResponse {
    need_update: bool,
    #[serde(default)]
    download_url: Option<String>,
    #[serde(default)]
    md5: Option<String>,
}

pub fn tasks_response() -> Response<Body> {
    let task_number = 10000000;
    let tasks = InvocationNormalTask {
        invocation_task_id: String::from(format!("invt-{}", task_number)),
        time_out: 3600,
        username: String::from("root"),
        command: base64::encode("ls -l".as_bytes()),
        command_type: format!("SHELL"),
        working_directory: String::from("/root/"),
    };
    let resp = DescribeTasksResponse {
        invocation_normal_task_set: vec![tasks],
        invocation_cancel_task_set: vec![],
    };
    let general_resp = GeneralResponse::<DescribeTasksResponse> {
        request_id: String::from("a0ed3f7a-ef51-4393-80b2-a3415c28c783"),
        error: None,
        content: Some(resp),
    };
    let raw_resp = ServerRawResponse::<DescribeTasksResponse> {
        response: general_resp,
    };
    Response::new(to_string_pretty(&raw_resp).unwrap().into())
}

pub fn start_response() -> Response<Body> {
    let resp = ReportTaskStartResponse {};
    let general_resp = GeneralResponse::<ReportTaskStartResponse> {
        request_id: String::from("a0ed3f7a-ef51-4393-80b2-a3415c28c783"),
        error: None,
        content: Some(resp),
    };
    let raw_resp = ServerRawResponse::<ReportTaskStartResponse> {
        response: general_resp,
    };
    Response::new(to_string_pretty(&raw_resp).unwrap().into())
}

pub fn upload_response() -> Response<Body> {
    let resp = UploadTaskLogResponse {};
    let general_resp = GeneralResponse::<UploadTaskLogResponse> {
        request_id: String::from("a0ed3f7a-ef51-4393-80b2-a3415c28c783"),
        error: None,
        content: Some(resp),
    };
    let raw_resp = ServerRawResponse::<UploadTaskLogResponse> {
        response: general_resp,
    };
    Response::new(to_string_pretty(&raw_resp).unwrap().into())
}

pub fn check_update_response() -> Response<Body> {
    let resp = CheckUpdateResponse{
        need_update: true,
        download_url: Some(String::from("http://example.com")),
        md5: Some(String::from("eeb0248363b2e9b66f975abd4f092db8"))
    };
    let general_resp = GeneralResponse::<CheckUpdateResponse> {
        request_id: String::from("a0ed3f7a-ef51-4393-80b2-a3415c28c783"),
        error: None,
        content: Some(resp),
    };
    let raw_resp = ServerRawResponse::<CheckUpdateResponse> {
        response: general_resp,
    };
    Response::new(to_string_pretty(&raw_resp).unwrap().into())
}
