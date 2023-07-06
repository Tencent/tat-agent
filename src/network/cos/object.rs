use crate::network::cos::auth::cos_sign;
use crate::network::cos::client::COS;
use crate::network::cos::errors::{Error, ObjectError};
use crate::network::cos::utils::*;
use std::collections::HashMap;

use async_trait::async_trait;
use log::info;
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, DATE, HOST};
use reqwest::Body;
use tokio::fs::File;

#[async_trait]
pub trait ObjectAPI {
    async fn put_object_from_file(
        &self,
        file: &str,
        object_name: &str,
        headers: Option<HashMap<String, String>>,
    ) -> Result<(), Error>;
}

#[async_trait]
impl<'a> ObjectAPI for COS<'a> {
    async fn put_object_from_file(
        &self,
        file: &str,
        object_name: &str,
        headers: Option<HashMap<String, String>>,
    ) -> Result<(), Error> {
        let object_name = object_name;
        let host = self.host();
        let date = self.date();
        let mut headers = match headers.into() {
            Some(h) => to_headers(h)?,
            None => HeaderMap::new(),
        };
        headers.insert(HOST, host.parse()?);
        headers.insert(DATE, date.parse()?);
        headers.insert(CONTENT_TYPE, "application/xml".parse()?);
        headers.insert(
            CONTENT_LENGTH,
            File::open(file)
                .await?
                .metadata()
                .await
                .unwrap()
                .len()
                .to_string()
                .parse()?,
        );
        let authorization = cos_sign(
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

        let body = Body::wrap_stream(FileStream(File::open(file).await?));
        let resp = self
            .client
            .put(&format!("{}{}", self.endpoint(), object_name))
            .headers(headers)
            .body(body)
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
