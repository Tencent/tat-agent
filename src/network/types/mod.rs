mod http_msg;
pub mod ws_msg;

pub use http_msg::{
    AgentRequest, CheckUpdateRequest, CheckUpdateResponse, DescribeTasksRequest,
    DescribeTasksResponse, GetCosCredentialRequest, GetTmpCredentialResponse, InvocationCancelTask,
    InvocationNormalTask, RegisterInstanceRequest, RegisterInstanceResponse, ReportResourceRequest,
    ReportResourceResponse, ReportTaskFinishRequest, ReportTaskFinishResponse,
    ReportTaskStartRequest, ReportTaskStartResponse, ServerRawResponse, UploadTaskLogRequest,
    UploadTaskLogResponse, ValidateInstanceRequest, ValidateInstanceResponse,
};

pub const UTF8_BOM_HEADER: [u8; 3] = [0xEF, 0xBB, 0xBF];
