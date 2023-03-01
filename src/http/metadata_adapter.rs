// 用于封装访问HTTP API的方法
use log::{error, info};
use serde_json::from_str;

use crate::http::{HttpRequester, Requester};
use crate::types::{GetTmpCredentialResponse, HttpMethod};

pub struct MetadataAPIAdapter {
    requester: HttpRequester,
}

const CREDENTIAL_URI: &str = "/latest/meta-data/cam/security-credentials";
const INSTANCE_ID_URI: &str = "/latest/meta-data/instance-id";

impl MetadataAPIAdapter {
    pub fn build(url: &str) -> Self {
        let mut req = HttpRequester::new();
        req.initialize(url);
        MetadataAPIAdapter { requester: req }
    }

    pub async fn tmp_credential(&self) -> Result<GetTmpCredentialResponse, String> {
        let role_name = self.get_role_name().await?;
        self.get_tmp_credential(role_name).await
    }

    pub async fn instance_id(&self) -> String {
        async fn get_instance_id(self_0: &MetadataAPIAdapter) -> Result<String, ()> {
            let resp = self_0
                .requester
                .with_time_out(3)
                .with_retrying(2)
                .send_request::<String>(HttpMethod::GET, INSTANCE_ID_URI, None)
                .await
                .map_err(|e| error!("request error: {:?}", e))?;

            let txt = resp
                .text()
                .await
                .map_err(|e| error!("failed to read response {:?}", e))?;

            info!("response text {:?}", txt);
            Ok(txt)
        }

        get_instance_id(self).await.unwrap_or_default()
    }

    async fn get_role_name(&self) -> Result<String, String> {
        let resp = self
            .requester
            .with_time_out(3)
            .with_retrying(2)
            .send_request::<String>(HttpMethod::GET, CREDENTIAL_URI, None)
            .await
            .map_err(|e| {
                error!("request error: {:?}", e);
                format!("Get CAM role of instance failed.")
            })?;

        let txt = resp.text().await.map_err(|e| {
            error!("failed to read response {:?}", e);
            format!("Get CAM role of instance failed.")
        })?;

        info!("response text {:?}", txt);
        Ok(txt)
    }

    async fn get_tmp_credential(
        &self,
        role_name: String,
    ) -> Result<GetTmpCredentialResponse, String> {
        let url = format!("{}/{}", CREDENTIAL_URI, role_name);
        let resp = self
            .requester
            .with_time_out(3)
            .with_retrying(2)
            .send_request::<String>(HttpMethod::GET, &*url, None)
            .await
            .map_err(|e| {
                error!("request error: {:?}", e);
                format!("Get credential of CAM role failed.")
            })?;

        let txt = resp.text().await.map_err(|e| {
            error!("failed to read response {:?}", e);
            format!("Get credential of CAM role failed.")
        })?;

        let raw_resp = from_str::<'_, GetTmpCredentialResponse>(&txt).map_err(|e| {
            error!("failed to parse json response {:?}", e);
            format!("Get credential of CAM role failed.")
        })?;

        Ok(raw_resp)
    }
}
