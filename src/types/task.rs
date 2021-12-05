use crate::common::consts::AGENT_VERSION;
use crate::types::AgentErrorCode;
use serde::{Deserialize, Serialize};

use crate::uname::common::UnameExt;
use crate::uname::Uname;
#[cfg(windows)]
use winapi::um::winnls::GetOEMCP;
#[cfg(windows)]
use codepage_strings::Coding;
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
            custom_params: custom_params,
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
    pub fn into_response(self) -> Result<T, ResponseError> {
        if self.response.is_ok() {
            match self.response.content() {
                Some(content) => Ok(content),
                None => Err(ResponseError {
                    code: format!("{:?}", AgentErrorCode::UnexpectedResponseFormat),
                    message: format!("cannot get response content"),
                }),
            }
        } else {
            match self.response.error() {
                Some(err) => Err(err),
                None => Err(ResponseError {
                    code: format!("{:?}", AgentErrorCode::UnexpectedResponseFormat),
                    message: format!("cannot get response error"),
                }),
            }
        }
    }

    pub fn _into_request_id(&self) -> String {
        self.response._request_id()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Empty {}

//==============================================================================
// DescribeTasks API
#[derive(Serialize, Deserialize, Debug, Clone)]
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

impl InvocationNormalTask {
    pub fn decode_command(&self) -> Result<Vec<u8>, String> {
        match base64::decode(&self.command) {
            Ok(command) => {
                #[cfg(windows)]
                let command = Coding::new(unsafe { GetOEMCP() } as u16)
                    .map_err(|e| e.to_string())?
                    .encode(String::from_utf8_lossy(&command))
                    .map_err(|e|e.to_string())?;
                Ok(command)
            }
            Err(e) => Err(format!("decode error: {:?}", e)),
        }
    }
}
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
    pub final_log_index: u32,
    #[serde(default)]
    pub output_url: String,
    #[serde(rename = "OutputUploadCOSErrorInfo")]
    #[serde(default)]
    pub output_error_info: String,
}

pub type ReportTaskFinishResponse = Empty;

//==============================================================================
// UploadTaskLog API
#[derive(Serialize, Deserialize, Debug, Clone)]
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
            index: index,
            output: base64::encode(&output),
            dropped: dropped,
        }
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
        let uname = Uname::new().unwrap();
        CheckUpdateRequest {
            kernel_name: uname.sys_name(),
            kernel_release: uname.release(),
            kernel_version: uname.version(),
            machine: uname.machine(),
            version: AGENT_VERSION.to_string(),
        }
    }
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

impl CheckUpdateResponse {
    pub fn need_update(&self) -> bool {
        self.need_update
    }

    pub fn download_url(&self) -> &Option<String> {
        &self.download_url
    }

    pub fn md5(&self) -> &Option<String> {
        &self.md5
    }
}

// Unit Tests
#[cfg(test)]
mod tests {
    use crate::types::{InvocationNormalTask, ServerRawResponse};

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
        let raw_resp = serde_json::from_str::<ServerRawResponse<MyResp>>(&error_str).unwrap();
        let general_resp = &raw_resp.response;
        assert_eq!(
            &general_resp.request_id,
            "e8fc76bf-ed90-4f38-a871-4f344d35d5ff"
        );
        let error = &general_resp.error.as_ref().unwrap();
        assert_eq!(&error.code, "ExampleCode");
        assert_eq!(&error.message, "Some message");
        // assert_eq!(general_resp.content.as_ref().unwrap(), None);
        assert_eq!(general_resp.content.is_none(), true);
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
        let raw_resp = serde_json::from_str::<ServerRawResponse<MyResp>>(&resp_str).unwrap();
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
            invocation_task_id: format!(""),
            command_type: format!("SHELL"),
            time_out: 0,
            command: String::from("bHMgLWw7CmVjaG8gIkhlbGxvIFdvcmxkIg=="),
            username: format!("root"),
            working_directory: format!(""),
            cos_bucket_url: format!(""),
            cos_bucket_prefix: format!(""),
        };
        assert_eq!(
            String::from_utf8_lossy(&tasks1.decode_command().unwrap()),
            String::from("ls -l;\necho \"Hello World\"")
        );
    }

    #[test]
    fn test_decode_invalid_command() {
        let tasks1 = InvocationNormalTask {
            invocation_task_id: format!(""),
            command_type: format!("SHELL"),
            time_out: 0,
            command: String::from("ls -l;\necho \"Hello World\""),
            username: format!("root"),
            working_directory: format!(""),
            cos_bucket_url: format!(""),
            cos_bucket_prefix: format!(""),
        };
        assert_eq!(tasks1.decode_command().is_err(), true);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_encode_log() {
        use std::fs::remove_file;
        use std::fs::File;
        use std::io::Read;
        use std::process::Command;

        use crate::types::UploadTaskLogRequest;
        let _cmd = Command::new("time")
            .arg("dd")
            .arg("if=/dev/urandom")
            .arg("of=random-file")
            .arg("bs=1")
            .arg("count=1024")
            .output()
            .expect("failed to generate random binary file");
        // read binary file
        let mut f = File::open("./random-file").unwrap();
        let mut buffer = Vec::new();
        // read the whole file
        f.read_to_end(&mut buffer)
            .expect("failed to read random-file");
        assert_eq!(remove_file("./random-file").is_ok(), true);
        let _req = UploadTaskLogRequest::new("invk-123123", 0, buffer, 0);
        // println!("{:?}", req);
    }
}
