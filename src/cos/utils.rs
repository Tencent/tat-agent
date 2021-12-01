use crate::cos::errors::Error;
use reqwest::header::{HeaderMap, HeaderName};
use reqwest::Body;
use std::collections::HashMap;
use tokio::fs::File;

pub fn to_headers<S>(hashmap: HashMap<S, S>) -> Result<HeaderMap, Error>
where
    S: AsRef<str>,
{
    let mut headers = HeaderMap::new();
    for (key, val) in hashmap.iter() {
        let key = key.as_ref();
        let val = val.as_ref();
        headers.insert(HeaderName::from_bytes(key.as_bytes())?, val.parse()?);
    }
    Ok(headers)
}

pub fn file_to_body(file: File) -> Body {
    let stream = tokio::io::reader_stream(file);
    Body::wrap_stream(stream)
}
