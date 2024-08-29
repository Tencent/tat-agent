use super::file::register_file_handlers;
use super::proxy::register_proxy_handlers;
use super::pty::register_pty_handlers;
use super::session::Session;
use super::{WS_BIN_MSG, WS_TXT_MSG};
use crate::common::evbus::EventBus;
use crate::network::types::ws_msg::{PtyBinBase, PtyJsonBase, WsMsg};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::Arc;

use leaky_bucket::RateLimiter;
use log::{error, info};
use once_cell::sync::OnceCell;
use serde::Serialize;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::RwLock;

const SIZE_1MB: usize = 1 * 1024 * 1024;

pub struct Gather {
    pub event_bus: Arc<EventBus>,
    pub stop_counter: Arc<AtomicU64>,
    pub sessions: RwLock<HashMap<String, Arc<Session>>>,
    pub ws_seq_num: AtomicU64,
    limiter: RwLock<RateLimiter>,
    runtime: Runtime,
}

static GATHER: OnceCell<Gather> = OnceCell::new();

pub fn run(event_bus: &Arc<EventBus>, running_task_num: &Arc<AtomicU64>) {
    GATHER.get_or_init(|| {
        let g = Gather {
            event_bus: event_bus.clone(),
            stop_counter: running_task_num.clone(),
            sessions: RwLock::new(HashMap::default()),
            ws_seq_num: AtomicU64::new(0),
            limiter: RwLock::new(build_limiter(SIZE_1MB)),
            runtime: Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build pty runtime failed"),
        };

        register_pty_handlers(event_bus);
        register_file_handlers(event_bus);
        register_proxy_handlers(event_bus);
        g
    });
}

impl Gather {
    pub fn instance() -> &'static Gather {
        GATHER.get().expect("runtime")
    }

    pub fn runtime() -> &'static Runtime {
        &Gather::instance().runtime
    }

    pub async fn add_session(session_id: &str, session: Arc<Session>) -> Result<(), String> {
        let gather = Gather::instance();
        let mut sessions = gather.sessions.write().await;
        if sessions.contains_key(session_id) {
            error!("duplicate add_session: {session_id}");
            Err(format!("session `{session_id}` already start"))?
        }

        sessions.insert(session_id.to_owned(), session.clone());
        info!("add_session: {}", session_id);
        gather.stop_counter.fetch_add(1, SeqCst);
        tokio::spawn(async move { session.process_output().await });
        Ok(())
    }

    pub async fn remove_session(session_id: &str) {
        let op = Gather::instance().sessions.write().await.remove(session_id);
        if let Some(s) = op {
            s.stop().await;
            info!("remove_session: {}", session_id);
            Gather::instance().stop_counter.fetch_sub(1, SeqCst);
        }
    }

    pub async fn get_session(session_id: &str) -> Option<Arc<Session>> {
        Gather::instance()
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|s| s.clone())
    }

    pub async fn set_limiter(rate: usize) {
        let mut l = Gather::instance().limiter.write().await;
        *l = build_limiter(rate);
    }

    pub async fn reply_json_msg<T: Serialize>(msg_type: &str, data: PtyJsonBase<T>) {
        let serialize = |ws_msg| {
            serde_json::to_string(&ws_msg)
                .expect("json serialize failed")
                .into_bytes()
        };
        Self::reply(msg_type, data, WS_TXT_MSG, serialize).await;
    }

    pub async fn reply_bson_msg<T: Serialize>(msg_type: &str, data: PtyBinBase<T>) {
        let serialize = |ws_msg| {
            let mut msg = Vec::new();
            let _ = bson::to_bson(&ws_msg)
                .expect("to_bson failed")
                .as_document()
                .expect("as_document failed")
                .to_writer(&mut msg);
            msg
        };
        Self::reply(msg_type, data, WS_BIN_MSG, serialize).await;
    }

    async fn reply<T, F>(msg_type: &str, data: T, event: &str, serialize: F)
    where
        T: Serialize,
        F: Fn(WsMsg<T>) -> Vec<u8>,
    {
        let gather = Gather::instance();
        let msg = serialize(WsMsg {
            r#type: msg_type.to_string(),
            seq: gather.ws_seq_num.fetch_add(1, SeqCst),
            data: Some(data),
        });
        gather.limiter.read().await.acquire(msg.len()).await;
        gather.event_bus.dispatch(event, msg);
    }
}

fn build_limiter(data_per_sec: usize) -> RateLimiter {
    RateLimiter::builder()
        .max(data_per_sec)
        .refill(data_per_sec / 10)
        .interval(tokio::time::Duration::from_millis(100))
        .build()
}
