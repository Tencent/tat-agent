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
