use std::collections::HashMap;
use std::future::Future;
use std::sync::LazyLock;

use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::RwLock;

static EVENT_BUS: LazyLock<EventBus> = LazyLock::new(Default::default);

#[derive(Default)]
struct EventBus(RwLock<HashMap<String, UnboundedSender<Vec<u8>>>>);

pub async fn subscribe<T>(event: &str, handler: impl Fn(Vec<u8>) -> T + Send + 'static) {
    let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            handler(msg);
        }
    });
    EVENT_BUS.0.write().await.insert(event.to_string(), tx);
}

pub async fn subscribe_future<F, Fut, T>(event: &str, handler: F)
where
    F: Fn(Vec<u8>) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            handler(msg).await;
        }
    });
    EVENT_BUS.0.write().await.insert(event.to_string(), tx);
}

pub async fn emit(event: &str, msg: Vec<u8>) {
    if let Some(tx) = EVENT_BUS.0.read().await.get(event) {
        let _ = tx.send(msg);
    }
}
