use crate::network::cos::errors::Error;
use std::collections::HashMap;
use std::pin::{pin, Pin};

use futures::task::{Context, Poll};
use futures::{io, Future, Stream};
use reqwest::header::{HeaderMap, HeaderName};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub fn to_headers<S: AsRef<str>>(hashmap: HashMap<S, S>) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    for (key, val) in hashmap.iter() {
        let key = key.as_ref();
        let val = val.as_ref();
        headers.insert(HeaderName::from_bytes(key.as_bytes())?, val.parse()?);
    }
    Ok(headers)
}

pub struct FileStream(pub File);

impl Stream for FileStream {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf = [0u8; 1204];
        let read = pin!(self.0.read(&mut buf));
        match read.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => Poll::Ready(None),
            Poll::Ready(Ok(n)) => Poll::Ready(Some(Ok(buf[..n].to_vec()))),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
        }
    }
}
