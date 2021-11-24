/* 声明内部模块 */
mod common;
mod error;
mod task;

pub mod inner_msg;
pub mod ws_msg;

/* 导出基础类型 */
pub use common::HttpMethod;
pub use error::AgentError;
pub use error::AgentErrorCode;
pub use task::{
    AgentRequest, CheckUpdateRequest, CheckUpdateResponse, DescribeTasksRequest,
    DescribeTasksResponse, ReportTaskFinishRequest, ReportTaskFinishResponse,
    ReportTaskStartRequest, ReportTaskStartResponse, ServerRawResponse, UploadTaskLogRequest,
    UploadTaskLogResponse,
};

pub use task::{InvocationCancelTask, InvocationNormalTask};
