use serde::{Deserialize, Serialize};

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
}
