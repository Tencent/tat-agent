use std::iter::IntoIterator;

use chrono::Local;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha1::{Digest, Sha1};
use urlencoding::encode;

pub fn cos_sign(
    method: &str,
    secret_id: &str,
    secret_key: &str,
    prefix: &str,
    expires: i64,
    headers: &HeaderMap,
) -> String {
    // Step 1: Generate KeyTime
    // Concatenate the effective times of the signature in the format of StartTimestamp;EndTimestamp,
    // which is referred to as KeyTime.
    // For example: 1557902800;1557910000.
    let key_time = {
        let timestamp = Local::now().timestamp();
        format!("{};{}", timestamp, timestamp + expires)
    };

    // Step 2: Generate SignKey
    // Utilize HMAC-SHA1 with the SecretKey as the key and KeyTime as the message
    // to compute the message digest (hash value, in hexadecimal lowercase form), which is the SignKey.
    // For example: eb2519b498b02ac213cb1f3d1a3d27a3b3c9bc5f.
    let sign_key = Hmac::<Sha1>::new_from_slice(secret_key.as_bytes())
        .expect("Hmac init failed")
        .chain_update(key_time.as_bytes())
        .finalize()
        .into_bytes()
        .encode_hex();

    // Step 3: Generate UrlParamList and HttpParameters
    let url_param_list = String::new();
    let http_parameters = String::new();

    // Step 4: Generate and HttpHeaders
    let mut cos_headers: Vec<(&HeaderName, &HeaderValue)> = headers.iter().collect();
    cos_headers.sort_by_key(|x| x.0.to_string());
    let header_list = cos_headers
        .iter()
        .map(|(key, _)| encode(key.as_ref()).to_lowercase())
        .collect::<Vec<String>>()
        .join(";");
    let http_headers = cos_headers
        .iter()
        .map(|(k, v)| {
            let k = encode(k.to_owned().as_str()).to_lowercase();
            let v = encode(v.to_owned().to_str().unwrap_or(""));
            format!("{k}={v}")
        })
        .collect::<Vec<String>>()
        .join("&");

    // Step 5: Generate HttpString
    let http_string = format!(
        "{}\n{}\n{}\n{}\n",
        method.to_lowercase(),
        prefix,
        http_parameters,
        http_headers
    );

    // Step 6: Generate StringToSign
    let string_to_sign = format!(
        "sha1\n{}\n{}\n",
        key_time,
        Sha1::digest(&http_string).encode_hex()
    );

    // Step 7: Generate Signature
    // Use HMAC-SHA1 with the SignKey as the key (in string format, not raw binary)
    // and the StringToSign as the message to compute the message digest, which will be the Signature.
    // For example: 01681b8c9d798a678e43b685a9f1bba0f6c0e012.
    let signature = Hmac::<Sha1>::new_from_slice(sign_key.as_bytes())
        .expect("Hmac init failed")
        .chain_update(string_to_sign.as_bytes())
        .finalize()
        .into_bytes()
        .encode_hex();

    // Step 8: Concatenate the Signature String
    format!("q-sign-algorithm=sha1&q-ak={secret_id}&q-sign-time={key_time}&q-key-time={key_time}&q-header-list={header_list}&q-url-param-list={url_param_list}&q-signature={signature}")
}

trait EncodeHex {
    fn encode_hex(self) -> String;
}

impl<T: IntoIterator<Item = u8> + Sized> EncodeHex for T {
    fn encode_hex(self) -> String {
        self.into_iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    }
}
