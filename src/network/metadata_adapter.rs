// 用于封装访问HTTP API的方法
use crate::network::types::{GetTmpCredentialResponse, HttpMethod};
use crate::network::HttpRequester;

use log::{error, info};
use serde_json::from_str;

pub struct MetadataAPIAdapter {
    url: String,
}

const CREDENTIAL_URI: &str = "/latest/meta-data/cam/security-credentials";
const INSTANCE_ID_URI: &str = "/latest/meta-data/instance-id";

impl MetadataAPIAdapter {
    pub fn build(url: &str) -> Self {
        MetadataAPIAdapter {
            url: url.to_string(),
        }
    }

    pub async fn tmp_credential(&self) -> Result<GetTmpCredentialResponse, String> {
        let role_name = self.get_role_name().await?;
        self.get_tmp_credential(role_name).await
    }

    pub async fn instance_id(&self) -> String {
        let res = HttpRequester::new(&self.url)
            .with_time_out(3)
            .send_request::<String>(HttpMethod::GET, INSTANCE_ID_URI, None, None)
            .await;
        let resp = match res {
            Ok(resp) => resp,
            Err(e) => {
                error!("request error: {:?}", e);
                return format!("");
            }
        };
        match resp.text().await {
            Ok(txt) => {
                info!("response text: {:?}", txt);
                txt
            }
            Err(e) => {
                error!("failed to read response: {:?}", e);
                format!("")
            }
        }
    }

    async fn get_role_name(&self) -> Result<String, String> {
        let resp = HttpRequester::new(&self.url)
            .with_time_out(3)
            .send_request::<String>(HttpMethod::GET, CREDENTIAL_URI, None, None)
            .await
            .map_err(|e| {
                error!("request error: {:?}", e);
                format!("Get CAM role of instance failed.")
            })?;
        match resp.text().await {
            Ok(txt) => {
                info!("response text: {:?}", txt);
                Ok(txt)
            }
            Err(e) => {
                error!("failed to read response: {:?}", e);
                Err(format!("Get CAM role of instance failed."))
            }
        }
    }

    async fn get_tmp_credential(
        &self,
        role_name: String,
    ) -> Result<GetTmpCredentialResponse, String> {
        let url = format!("{}/{}", CREDENTIAL_URI, role_name);
        let resp = HttpRequester::new(&self.url)
            .with_time_out(3)
            .send_request::<String>(HttpMethod::GET, &*url, None, None)
            .await
            .map_err(|e| {
                error!("request error: {:?}", e);
                format!("Get credential of CAM role failed.")
            })?;
        let txt = resp.text().await.map_err(|e| {
            error!("failed to read response: {:?}", e);
            format!("Get credential of CAM role failed.")
        })?;
        let raw_resp_result: Result<GetTmpCredentialResponse, _> = from_str(&txt);
        raw_resp_result.or_else(|e| {
            error!("failed to parse json response: {:?}", e);
            Err(format!("Get credential of CAM role failed."))
        })
    }
}
