use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, DATE, HOST};
use std::collections::HashMap;

use crate::network::cos::auth::*;
use crate::network::cos::client::COS;
use crate::network::cos::errors::{Error, ObjectError};
use crate::network::cos::utils::*;
use async_trait::async_trait;
use log::info;
use tokio::fs::File;

#[async_trait]
pub trait ObjectAPI {
    async fn put_object_from_file(
        &self,
        file: String,
        object_name: String,
        headers: Option<HashMap<String, String>>,
    ) -> Result<(), Error>;
}

#[async_trait]
impl<'a> ObjectAPI for COS<'a> {
    async fn put_object_from_file(
        &self,
        file: String,
        object_name: String,
        headers: Option<HashMap<String, String>>,
    ) -> Result<(), Error> {
        let object_name = object_name.as_ref();
        let host = self.host();
        let date = self.date();
        let f = File::open(file).await?;
        let mut headers = if let Some(h) = headers.into() {
            to_headers(h)?
        } else {
            HeaderMap::new()
        };
        headers.insert(HOST, host.parse()?);
        headers.insert(DATE, date.parse()?);
        headers.insert(CONTENT_TYPE, "application/xml".parse()?);
        headers.insert(
            CONTENT_LENGTH,
            f.metadata().await.unwrap().len().to_string().parse()?,
        );
        let authorization = self.cos_sign(
            "PUT",
            self.secret_id(),
            self.secret_key(),
            object_name,
            600,
            &headers,
        );
        headers.insert(AUTHORIZATION, authorization.parse()?);
        headers.insert("x-cos-security-token", self.token().parse()?);
        info!("{:?}", authorization);

        let resp = self
            .client
            .put(&format!("{}{}", self.endpoint(), object_name))
            .headers(headers)
            .body(file_to_body(f))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::Object(ObjectError::PutError {
                msg: format!("can not put object, status code {}", resp.status()),
            }))
        }
    }
}
