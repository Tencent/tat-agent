use chrono::Local;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use urlencoding::encode;

use crate::network::cos::client::COS;

pub trait Auth {
    fn cos_sign(
        &self,
        verb: &str,
        secret_id: &str,
        secret_key: &str,
        prefix: &str,
        expires: i64,
        headers: &HeaderMap,
    ) -> String;
}

impl<'a> Auth for COS<'a> {
    fn cos_sign(
        &self,
        verb: &str,
        secret_id: &str,
        secret_key: &str,
        prefix: &str,
        expires: i64,
        headers: &HeaderMap,
    ) -> String {
        // 步骤1：生成 KeyTime
        // 拼接签名有效时间，格式为StartTimestamp;EndTimestamp，即为 KeyTime。例如：1557902800;1557910000。
        let key_time = {
            let timestamp = Local::now().timestamp();
            format!("{};{}", timestamp, timestamp + expires)
        };

        // 步骤2：生成 SignKey
        // 使用 HMAC-SHA1 以 SecretKey 为密钥，以 KeyTime 为消息，计算消息摘要（哈希值，16进制小写形式），即为 SignKey，例如：eb2519b498b02ac213cb1f3d1a3d27a3b3c9bc5f。
        let sign_key = {
            let mut hmac = Hmac::new(Sha1::new(), secret_key.as_ref());
            hmac.input(key_time.as_bytes());
            hex::encode(hmac.result().code())
        };

        // 步骤3：生成 UrlParamList 和 HttpParameters
        let url_param_list = format!("");
        let http_parameters = format!("");

        // 步骤4：生成 HeaderList 和 HttpHeaders
        let mut cos_headers: Vec<(&HeaderName, &HeaderValue)> = headers.iter().collect();
        cos_headers.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
        let header_list = cos_headers
            .iter()
            .map(|(key, _)| encode(key.as_ref()).to_lowercase())
            .collect::<Vec<String>>()
            .join(";");
        let http_headers = cos_headers
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    encode(&*k.to_owned().as_str()).to_lowercase(),
                    encode(&*v.to_owned().to_str().unwrap_or(""))
                )
            })
            .collect::<Vec<String>>()
            .join("&");

        // 步骤5：生成 HttpString
        let http_string = format!(
            "{}\n{}\n{}\n{}\n",
            verb.to_lowercase(),
            prefix,
            http_parameters,
            http_headers
        );

        // 步骤6：生成 StringToSign
        let string_to_sign = {
            let mut sha1 = Sha1::new();
            sha1.input_str(&http_string);
            format!("sha1\n{}\n{}\n", key_time, sha1.result_str())
        };

        // 步骤7：生成 Signature
        // 使用 HMAC-SHA1 以 SignKey 为密钥（字符串形式，非原始二进制），以 StringToSign 为消息，计算消息摘要，即为 Signature，例如：01681b8c9d798a678e43b685a9f1bba0f6c0e012。
        let signature = {
            let mut hmac = Hmac::new(Sha1::new(), sign_key.as_bytes());
            hmac.input(string_to_sign.as_bytes());
            hex::encode(hmac.result().code())
        };

        // 步骤8：生成签名
        format!("q-sign-algorithm=sha1&q-ak={ak}&q-sign-time={time}&q-key-time={time}&q-header-list={header_list}&q-url-param-list={url_param_list}&q-signature={signature}",
                ak = secret_id, time = key_time, header_list = header_list, url_param_list = url_param_list, signature = signature
        )
    }
}
