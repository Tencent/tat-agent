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
        let res = self
            .requester
            .with_time_out(3)
            .with_retrying(2)
            .send_request::<String>(HttpMethod::GET, INSTANCE_ID_URI, None)
            .await;
        match res {
            Ok(resp) => match resp.text().await {
                Ok(txt) => {
                    info!("response text {:?}", txt);
                    txt
                }
                Err(e) => {
                    error!("failed to read response {:?}", e);
                    format!("")
                }
            },
            Err(e) => {
                error!("request error: {:?}", e);
                format!("")
            }
        }
    }

    async fn get_role_name(&self) -> Result<String, String> {
        let res = self
            .requester
            .with_time_out(3)
            .with_retrying(2)
            .send_request::<String>(HttpMethod::GET, CREDENTIAL_URI, None)
            .await;
        match res {
            Ok(resp) => match resp.text().await {
                Ok(txt) => {
                    info!("response text {:?}", txt);
                    Ok(txt)
                }
                Err(e) => {
                    error!("failed to read response {:?}", e);
                    Err(format!("Get CAM role of instance failed."))
                }
            },
            Err(e) => {
                error!("request error: {:?}", e);
                Err(format!("Get CAM role of instance failed."))
            }
        }
    }

    async fn get_tmp_credential(
        &self,
        role_name: String,
    ) -> Result<GetTmpCredentialResponse, String> {
        let url = format!("{}/{}", CREDENTIAL_URI, role_name);
        let res = self
            .requester
            .with_time_out(3)
            .with_retrying(2)
            .send_request::<String>(HttpMethod::GET, &*url, None)
            .await;
        match res {
            Ok(resp) => {
                // let txt = resp.text().await;
                match resp.text().await {
                    Ok(txt) => {
                        let raw_resp_result: Result<GetTmpCredentialResponse, _> = from_str(&txt);
                        match raw_resp_result {
                            Ok(raw_resp) => Ok(raw_resp),
                            Err(e) => {
                                error!("failed to parse json response {:?}", e);
                                Err(format!("Get credential of CAM role failed."))
                            }
                        }
                    }
                    Err(e) => {
                        error!("failed to read response {:?}", e);
                        Err(format!("Get credential of CAM role failed."))
                    }
                }
            }
            Err(e) => {
                error!("request error: {:?}", e);
                Err(format!("Get credential of CAM role failed."))
            }
        }
    }
}
