use crate::network::types::GetTmpCredentialResponse;
use crate::network::HttpRequester;

use anyhow::Result;
use log::{error, info};
use serde_json::from_str;

pub struct MetadataAdapter {
    url: String,
}

const CREDENTIAL_URI: &str = "/latest/meta-data/cam/security-credentials";
const INSTANCE_ID_URI: &str = "/latest/meta-data/instance-id";
const REGION_URI: &str = "/latest/meta-data/placement/region";

impl MetadataAdapter {
    pub fn build(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    pub async fn tmp_credential(&self) -> Result<GetTmpCredentialResponse> {
        let role_name = self.get_role_name().await?;
        self.get_tmp_credential(&role_name).await
    }

    pub async fn instance_id(&self) -> String {
        let url = self.url.clone() + INSTANCE_ID_URI;
        Self::get(&url)
            .await
            .inspect(|id| info!("Metadata instance_id response: {}", id))
            .unwrap_or_default()
    }

    pub async fn region(&self) -> Result<String> {
        let url = self.url.clone() + REGION_URI;
        let txt = Self::get(&url).await?;
        info!("Metadata region response: {}", txt);
        Ok(txt)
    }

    async fn get_role_name(&self) -> Result<String> {
        let url = self.url.clone() + CREDENTIAL_URI;
        let txt = Self::get(&url).await?;
        info!("Metadata get_role_name response: {}", txt);
        Ok(txt)
    }

    async fn get_tmp_credential(&self, role_name: &str) -> Result<GetTmpCredentialResponse> {
        let url = self.url.clone() + CREDENTIAL_URI + "/" + role_name;
        let txt = Self::get(&url).await?;
        let obj = from_str::<GetTmpCredentialResponse>(&txt)
            .inspect_err(|e| error!("failed to parse json response: {}", e))?;
        Ok(obj)
    }

    async fn get(url: &str) -> Result<String> {
        let resp_text = HttpRequester::get(&url)
            .timeout(3)
            .send()
            .await
            .inspect_err(|e| error!("send request error: {}", e))?
            .text()
            .await
            .inspect_err(|e| error!("failed to read response: {}", e))?;
        Ok(resp_text)
    }
}
