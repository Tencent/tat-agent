use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WsMsg {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyStart {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
    #[serde(default)]
    pub init_block: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub input: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyResize {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyStop {
    #[serde(default)]
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyOutput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub output: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyReady {
    #[serde(default)]
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyError {
    #[serde(default)]
    pub session_id: String,
    pub reason: String,
}
