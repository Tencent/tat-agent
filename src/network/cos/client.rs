use std::borrow::Cow;
use std::str;

use chrono::prelude::*;
use reqwest::Client;
use url::Url;

#[derive(Clone, Debug)]
pub struct COS<'a> {
    secret_id: Cow<'a, str>,
    secret_key: Cow<'a, str>,
    token: Cow<'a, str>,
    endpoint: Cow<'a, str>,
    host: Cow<'a, str>,
    pub client: Client,
}

impl<'a> COS<'a> {
    pub fn new<S>(secret_id: S, secret_key: S, token: S, endpoint: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        let endpoint = endpoint.into().to_string();
        let host = Url::parse(&*endpoint.clone()).unwrap();
        let host = host.host().unwrap().to_string();
        COS {
            secret_id: secret_id.into(),
            secret_key: secret_key.into(),
            token: token.into(),
            endpoint: Cow::from(endpoint),
            host: Cow::from(host),
            client: Client::new(),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn secret_id(&self) -> &str {
        &self.secret_id
    }

    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn date(&self) -> String {
        let now: DateTime<Utc> = Utc::now();
        now.format("%a, %d %b %Y %T GMT").to_string()
    }
}

#[cfg(test)]
mod tests {
    // use crate::cos::client;
    // use crate::cos::object::ObjectAPI;

    // #[test]
    // fn test_upload_object() {
    //     let cli = client::COS::new(
    //         "tmp_ak_id",
    //         "tmp_ak_key",
    //         "tmp_token",
    //         "https://tat-xxxx.cos.ap-guangzhou.myqcloud.com",
    //     );
    //     let res = cli.put_object_from_file("README.md".to_string(), "/tat/README.md".to_string(), None);
    //     assert!(res.is_ok());
    // }
}
