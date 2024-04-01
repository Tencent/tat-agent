mod error;
mod http_req;
pub mod ws_msg;

pub use error::AgentError;
pub use error::AgentErrorCode;
pub use http_req::{
    AgentRequest, CheckUpdateRequest, CheckUpdateResponse, DescribeTasksRequest,
    DescribeTasksResponse, GetCosCredentialRequest, GetTmpCredentialResponse, InvocationCancelTask,
    InvocationNormalTask, RegisterInstanceRequest, RegisterInstanceResponse, ReportResourceRequest,
    ReportResourceResponse, ReportTaskFinishRequest, ReportTaskFinishResponse,
    ReportTaskStartRequest, ReportTaskStartResponse, ServerRawResponse, UploadTaskLogRequest,
    UploadTaskLogResponse, ValidateInstanceRequest, ValidateInstanceResponse,
};

pub enum HttpMethod {
    GET,
    POST,
}

pub const UTF8_BOM_HEADER: [u8; 3] = [0xEF, 0xBB, 0xBF];
