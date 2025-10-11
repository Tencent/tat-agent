use crate::common::sysinfo::{cpu_arch, kernel_name, kernel_version, os_version};
#[cfg(windows)]
use crate::executor::windows::{CMD_TYPE_POWERSHELL, UTF8_BOM_HEADER};
use crate::network::AGENT_VERSION;

use std::fmt;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

//==============================================================================
// Declare standard request and response format for C/S communication
// general parameters in reqeust
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GeneralParameters {
    action: String,
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

// general parameters in response, encapsuled in ServerRawResponse
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

// standard response format
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ServerRawResponse<T> {
    response: GeneralResponse<T>,
}

impl<T> AgentRequest<T> {
    pub fn new(action: &str, custom_params: T) -> Self {
        let g = GeneralParameters {
            action: action.to_string(),
        };
        AgentRequest {
            general_params: g,
            custom_params,
        }
    }
}

impl<T> GeneralResponse<T> {
    pub fn content(self) -> Option<T> {
        self.content
    }

    pub fn error(self) -> Option<ResponseError> {
        self.error
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }

    pub fn _request_id(&self) -> String {
        self.request_id.clone()
    }
}

impl<T> ServerRawResponse<T> {
    pub fn into_response(self) -> Result<T> {
        if !self.response.is_ok() {
            let e = self.response.error().context("cannot get response error")?;
            bail!("{}: {}", e.code, e.message);
        }
        let resp = self
            .response
            .content()
            .context("cannot get response content")?;
        Ok(resp)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Empty {}

//==============================================================================
// DescribeTasks API
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct InvocationNormalTask {
    #[serde(default)]
    pub invocation_task_id: String,
    #[serde(default)]
    pub time_out: u64,
    #[serde(alias = "Cmd")]
    #[serde(default)]
    pub command: String,
    #[serde(alias = "CmdType")]
    #[serde(default)]
    pub command_type: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub working_directory: String,
    #[serde(alias = "OutputCOSBucketUrl")]
    #[serde(default)]
    pub cos_bucket_url: String,
    #[serde(alias = "OutputCOSKeyPrefix")]
    #[serde(default)]
    pub cos_bucket_prefix: String,
}

impl InvocationNormalTask {
    pub fn decode_command(&self) -> Result<Vec<u8>> {
        #[allow(unused_mut)] // Windows needs MUT, Unix does not.
        let mut command = STANDARD.decode(&self.command)?;

        #[cfg(windows)]
        if self.command_type == CMD_TYPE_POWERSHELL {
            // powershell dont support utf8, but support utf8 with bom.
            // utf8 bom start with 0xEF, 0xBB, 0xBF,
            command.splice(0..0, UTF8_BOM_HEADER);
        }

        Ok(command)
    }
}

impl fmt::Debug for InvocationNormalTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvocationNormalTask")
            .field("invocation_task_id", &self.invocation_task_id)
            .field("time_out", &self.time_out)
            .field("command_len", &self.command.len())
            .field("command_type", &self.command_type)
            .field("username", &self.username)
            .field("working_directory", &self.working_directory)
            .field("cos_bucket_url", &self.cos_bucket_url)
            .field("cos_bucket_prefix", &self.cos_bucket_prefix)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct InvocationCancelTask {
    #[serde(default)]
    pub invocation_task_id: String,
}

// request and response
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DescribeTasksResponse {
    pub invocation_normal_task_set: Vec<InvocationNormalTask>,
    pub invocation_cancel_task_set: Vec<InvocationCancelTask>,
}

pub type DescribeTasksRequest = Empty;

//==============================================================================
// ReportTaskStart API
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ReportTaskStartRequest {
    #[serde(default)]
    pub invocation_task_id: String,
    #[serde(default)]
    pub time_stamp: u64,
}

pub type ReportTaskStartResponse = Empty;

//==============================================================================
// ReportTaskFinish API
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ReportTaskFinishRequest {
    #[serde(default)]
    pub invocation_task_id: String,
    #[serde(default)]
    pub time_stamp: u64,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub error_info: String,
    #[serde(default)]
    pub exit_code: i32,
    #[serde(default)]
    pub final_log_index: Option<u32>,
    #[serde(default)]
    pub output_url: String,
    #[serde(rename = "OutputUploadCOSErrorInfo")]
    #[serde(default)]
    pub output_error_info: String,
}

pub type ReportTaskFinishResponse = Empty;

//==============================================================================
// UploadTaskLog API
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct UploadTaskLogRequest {
    #[serde(default)]
    invocation_task_id: String,
    #[serde(default)]
    index: u32,
    #[serde(default)]
    output: String,
    #[serde(default)]
    dropped: u64,
}

impl UploadTaskLogRequest {
    pub fn new(invocation_task_id: &str, index: u32, output: Vec<u8>, dropped: u64) -> Self {
        UploadTaskLogRequest {
            invocation_task_id: String::from(invocation_task_id),
            index,
            output: STANDARD.encode(&output),
            dropped,
        }
    }
}

impl fmt::Debug for UploadTaskLogRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadTaskLogRequest")
            .field("invocation_task_id", &self.invocation_task_id)
            .field("index", &self.index)
            .field("output_len", &self.output.len())
            .field("dropped", &self.dropped)
            .finish()
    }
}

pub type UploadTaskLogResponse = Empty;

//==============================================================================
// CheckUpdate API
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct CheckUpdateRequest {
    kernel_name: String,
    kernel_release: String,
    kernel_version: String,
    machine: String,
    version: String,
}

impl CheckUpdateRequest {
    pub fn new() -> Self {
        CheckUpdateRequest {
            kernel_name: kernel_name(),
            kernel_release: kernel_version(),
            kernel_version: os_version(),
            machine: cpu_arch(),
            version: AGENT_VERSION.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct CheckUpdateResponse {
    pub need_update: bool,
    #[serde(default)]
    pub download_url: Option<String>,
    #[serde(default)]
    pub md5: Option<String>,
}

//==============================================================================
// registration related
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterInstanceRequest {
    #[serde(default)]
    machine_id: String,
    #[serde(default)]
    active_code: String,
    #[serde(default)]
    active_value: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    local_ip: String,
    #[serde(default)]
    system_name: String,
}

impl RegisterInstanceRequest {
    pub fn new(
        machine_id: String,
        active_code: String,
        active_value: String,
        public_key: String,
        hostname: String,
        local_ip: String,
    ) -> Self {
        RegisterInstanceRequest {
            machine_id,
            active_code,
            active_value,
            public_key,
            hostname,
            local_ip,
            #[cfg(windows)]
            system_name: "Windows".to_string(),
            #[cfg(unix)]
            system_name: "Linux".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterInstanceResponse {
    #[serde(default)]
    pub instance_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ValidateInstanceRequest {
    #[serde(default)]
    sys_name: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    local_ip: String,
}

impl ValidateInstanceRequest {
    pub fn new(hostname: &str, local_ip: &str) -> Self {
        Self {
            hostname: hostname.to_owned(),
            local_ip: local_ip.to_owned(),
            #[cfg(windows)]
            sys_name: "Windows".to_string(),
            #[cfg(unix)]
            sys_name: "Linux".to_string(),
        }
    }
}

pub type ValidateInstanceResponse = Empty;

//==============================================================================
// metadata related
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct GetTmpCredentialResponse {
    #[serde(alias = "TmpSecretId")]
    #[serde(default)]
    pub secret_id: String,
    #[serde(alias = "TmpSecretKey")]
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub expire_time: i64,
    #[serde(default)]
    pub expiration: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub code: String,
    #[serde(alias = "InvocationID")]
    #[serde(default)]
    pub invocation_id: String,
}

//==============================================================================
// get cos credential
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct GetCosCredentialRequest {
    invocation_task_id: String,
}

impl GetCosCredentialRequest {
    pub fn new(invocation_task_id: &str) -> Self {
        Self {
            invocation_task_id: invocation_task_id.to_owned(),
        }
    }
}

//==============================================================================
// report agent log
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ReportAgentLogRequest {
    agent_version: String,
    log_level: String,
    log_info: String,
}

impl ReportAgentLogRequest {
    pub fn new(level: &str, log: &str) -> Self {
        Self {
            agent_version: AGENT_VERSION.to_owned(),
            log_level: level.to_owned(),
            log_info: log.to_owned(),
        }
    }
}

pub type ReportAgentLogResponse = Empty;

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use crate::executor::windows::UTF8_BOM_HEADER;
    use crate::network::{InvocationNormalTask, ServerRawResponse};

    #[test]
    fn serialize_agent_request() {
        use serde::Serialize;
        #[derive(Serialize)]
        struct Inner {
            count: u8,
        }
        #[derive(Serialize)]
        struct Foo {
            #[serde(flatten)]
            inner: Inner,
            bar: String,
            names: Vec<String>,
        }
        let i = Inner { count: 3 };
        let f = Foo {
            inner: i,
            bar: String::from("woo"),
            names: vec!["jack".to_string(), "john".to_string(), "ken".to_string()],
        };
        let res = serde_json::to_string(&f).unwrap();
        assert_eq!(
            res,
            "{\"count\":3,\"bar\":\"woo\",\"names\":[\"jack\",\"john\",\"ken\"]}"
        );
    }

    #[test]
    fn deserialize_server_response_error() {
        let error_str = "
        {
            \"Response\": {
                \"Error\": {
                    \"Code\": \"ExampleCode\",
                    \"Message\": \"Some message\"
                },
                \"RequestId\": \"e8fc76bf-ed90-4f38-a871-4f344d35d5ff\"
            }
        }";
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct MyResp {
            _name: String,
        }
        let raw_resp = serde_json::from_str::<ServerRawResponse<MyResp>>(error_str).unwrap();
        let general_resp = &raw_resp.response;
        assert_eq!(
            &general_resp.request_id,
            "e8fc76bf-ed90-4f38-a871-4f344d35d5ff"
        );
        let error = &general_resp.error.as_ref().unwrap();
        assert_eq!(&error.code, "ExampleCode");
        assert_eq!(&error.message, "Some message");
        // assert_eq!(general_resp.content.as_ref().unwrap(), None);
        assert!(general_resp.content.is_none());
    }

    #[test]
    fn deserialize_server_response_content() {
        let resp_str = "
            {
                \"Response\": {
                    \"RequestId\": \"aee1c4f7-c782-45b7-b81b-9cea73448a31\",
                    \"UserSet\": [
                        {
                            \"Name\": \"Foo\",
                            \"Age\": 20
                        },
                        {
                            \"Name\": \"Bar\",
                            \"Age\": 30
                        }
                    ]
                }
            }
        ";
        use serde::{Deserialize, Serialize};
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct MyUser {
            name: String,
            age: u64,
        }
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct MyResp {
            user_set: Vec<MyUser>,
        }
        let raw_resp = serde_json::from_str::<ServerRawResponse<MyResp>>(resp_str).unwrap();
        let general_resp = &raw_resp.response;
        assert_eq!(
            &general_resp.request_id,
            "aee1c4f7-c782-45b7-b81b-9cea73448a31"
        );
        let content = general_resp.content.as_ref().unwrap();
        assert_eq!(content.user_set.len(), 2);
        assert_eq!(&content.user_set[0].name, "Foo");
        assert_eq!(content.user_set[1].age, 30);
    }

    #[test]
    fn test_decode_normal_command() {
        let tasks1 = InvocationNormalTask {
            invocation_task_id: String::new(),
            #[cfg(unix)]
            command_type: "SHELL".to_string(),
            #[cfg(windows)]
            command_type: "POWERSHELL".to_string(),
            time_out: 0,
            command: String::from("bHMgLWw7CmVjaG8gIkhlbGxvIFdvcmxkIg=="),
            username: "root".to_string(),
            working_directory: String::new(),
            cos_bucket_url: String::new(),
            cos_bucket_prefix: String::new(),
        };

        #[cfg(unix)]
        let contents = tasks1.decode_command().unwrap();
        #[cfg(windows)]
        let mut contents = tasks1.decode_command().unwrap();
        #[cfg(windows)]
        {
            //check utf8 bom, start with 0xEF 0xBB 0xBF
            assert_eq!(contents[0..=2], UTF8_BOM_HEADER);
            contents = Vec::from(&contents[3..]);
        }
        assert_eq!(
            String::from_utf8_lossy(&contents),
            String::from("ls -l;\necho \"Hello World\"")
        );
    }

    #[test]
    fn test_decode_invalid_command() {
        let tasks1 = InvocationNormalTask {
            invocation_task_id: String::new(),
            command_type: "SHELL".to_string(),
            time_out: 0,
            command: String::from("ls -l;\necho \"Hello World\""),
            username: "root".to_string(),
            working_directory: String::new(),
            cos_bucket_url: String::new(),
            cos_bucket_prefix: String::new(),
        };
        assert!(tasks1.decode_command().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_encode_log() {
        use std::fs::{remove_file, File};
        use std::{io::Read, process::Command};

        use crate::network::UploadTaskLogRequest;
        let _ = Command::new("time")
            .arg("dd")
            .arg("if=/dev/urandom")
            .arg("of=/tmp/random-file")
            .arg("bs=1")
            .arg("count=1024")
            .output()
            .expect("failed to generate random binary file");
        // read binary file
        let mut f = File::open("/tmp/random-file").expect("/tmp/random-file not found");
        let mut buf = Vec::new();
        // read the whole file
        f.read_to_end(&mut buf).expect("random-file read failed");
        assert!(remove_file("/tmp/random-file").is_ok());
        let _ = UploadTaskLogRequest::new("invk-123123", 0, buf, 0);
    }
}
