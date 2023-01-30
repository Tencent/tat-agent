/* 声明内部模块 */
mod error;
mod http_req;
pub mod ws_msg;

/* 导出基础类型 */
pub use error::AgentError;
pub use error::AgentErrorCode;
pub use http_req::{
    AgentRequest, CheckUpdateRequest, CheckUpdateResponse, DescribeTasksRequest,
    DescribeTasksResponse, GetTmpCredentialResponse, InvocationCancelTask, InvocationNormalTask,
    RegisterInstanceRequest, RegisterInstanceResponse, ReportResourceRequest,
    ReportResourceResponse, ReportTaskFinishRequest, ReportTaskFinishResponse,
    ReportTaskStartRequest, ReportTaskStartResponse, ServerRawResponse, UploadTaskLogRequest,
    UploadTaskLogResponse, ValidateInstanceRequest, ValidateInstanceResponse,
};

pub enum HttpMethod {
    GET,
    POST,
}
