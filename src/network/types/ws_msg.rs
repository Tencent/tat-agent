use std::collections::HashMap;

use serde::{Deserialize, Serialize};
pub const EVENT_KICK: &str = "kick";
pub const EVENT_CHECK_UPDATE: &str = "CheckUpdate";
pub const EVENT_FORCE_RESTART: &str = "ForceRestart";

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WsMsg<T> {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyJsonBase<T> {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub channel_id: String,
    #[serde(flatten)]
    pub data: T,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyStart {
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
    #[serde(default)]
    pub init_block: bool,
    #[serde(default)]
    pub no_shell: bool,
    #[serde(default)]
    pub envs: HashMap<String, String>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyInput {
    #[serde(default)]
    pub input: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyResize {
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyStop {}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyOutput {
    pub output: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyReady {}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyMaxRate {
    pub rate: usize,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyPing {}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyPong {}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyError {
    pub reason: String,
}

impl PtyError {
    pub fn new(reason: impl ToString) -> Self {
        let reason = reason.to_string();
        Self { reason }
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyBinBase<T> {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub channel_id: String,
    #[serde(default)]
    pub custom_data: String,
    #[serde(default)]
    pub data: T,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyBinErrMsg {
    pub error: String,
}

impl PtyBinErrMsg {
    pub fn new(error: impl ToString) -> Self {
        let error = error.to_string();
        Self { error }
    }
}

//file msg
#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFileReq {
    pub path: String,
    pub mode: u32,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub is_dir: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFileResp {
    pub created: bool,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteFileReq {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub is_dir: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteFileResp {
    pub deleted: bool,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ReadFileReq {
    pub path: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_read_size")]
    pub size: usize,
}

fn default_read_size() -> usize {
    usize::MAX
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ReadFileResp {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub offset: usize,
    pub length: usize,
    pub is_last: bool,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WriteFileReq {
    pub path: String,
    pub offset: Option<usize>,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WriteFileResp {
    pub length: usize,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct FileExistsReq {
    #[serde(default)]
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct FileExistResp {
    pub exists: bool,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct FileInfoReq {
    #[serde(default)]
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FileInfoResp {
    pub r#type: String,
    pub name: String,
    pub size: u64,
    pub modify_time: u64,
    pub access_time: u64,
    #[cfg(unix)]
    pub owner: u32,
    #[cfg(unix)]
    pub group: u32,
    #[cfg(unix)]
    pub rights: String,
    #[cfg(unix)]
    pub longname: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ListPathReq {
    pub path: String,
    #[serde(default = "default_list_filter")]
    pub filter: String,
    #[serde(default = "default_show_hidden")]
    pub show_hidden: bool,
}

fn default_list_filter() -> String {
    "*".to_string()
}

fn default_show_hidden() -> bool {
    true
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ListPathResp {
    pub index: u32,
    pub is_last: bool,
    pub files: Vec<FileInfoResp>,
}

//exec msg
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdReq {
    pub cmd: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdResp {
    pub output: String,
}

//exec msg
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdStreamReq {
    pub cmd: String,
    pub timeout: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdStreamResp {
    pub index: u32,
    pub is_last: bool,
    // #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

//proxy msg
#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyNew {
    #[serde(default)]
    pub proxy_id: String,
    #[serde(default)]
    pub port: String,
    #[serde(default = "default_ip")]
    pub ip: String,
}

fn default_ip() -> String {
    "127.0.0.1".to_string()
}

//proxy msg
#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyReady {
    #[serde(default)]
    pub proxy_id: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyData {
    #[serde(default)]
    pub proxy_id: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyClose {
    #[serde(default)]
    pub proxy_id: String,
}
