mod file;
mod handler;
mod proxy;
mod pty;
mod session;

use self::file::register_file_handlers;
use self::handler::HandlerExt;
use self::proxy::register_proxy_handlers;
use self::pty::register_pty_handlers;
use self::session::Session;
use crate::common::evbus::EventBus;
use crate::network::{PtyBinBase, PtyJsonBase, WsMsg};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use leaky_bucket::RateLimiter;
use log::{error, info};
use serde::Serialize;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::RwLock;

const WS_MSG_TYPE_PTY_ERROR: &str = "PtyError";
const WS_MSG_TYPE_PTY_EXEC_CMD: &str = "PtyExecCmd";
const WS_MSG_TYPE_PTY_EXEC_CMD_STREAM: &str = "PtyExecCmdStream";
const WS_MSG_TYPE_PTY_START: &str = "PtyStart";
const WS_MSG_TYPE_PTY_STOP: &str = "PtyStop";
const WS_MSG_TYPE_PTY_RESIZE: &str = "PtyResize";
const WS_MSG_TYPE_PTY_INPUT: &str = "PtyInput";
const WS_MSG_TYPE_PTY_OUTPUT: &str = "PtyOutput";
const WS_MSG_TYPE_PTY_MAX_RATE: &str = "PtyMaxRate";
#[allow(unused)]
const WS_MSG_TYPE_PTY_READY: &str = "PtyReady";
pub const WS_TXT_MSG: &str = "pty_cmd_msg";
pub const WS_BIN_MSG: &str = "pty_file_msg";
pub const PTY_INSPECT_READ: u8 = 0x0;
pub const PTY_INSPECT_WRITE: u8 = 0x1;
pub const SLOT_PTY_BIN: &str = "event_slot_pty_file";
#[cfg(windows)]
pub const PTY_FLAG_ENABLE_BLOCK: u32 = 0x00000001;
#[cfg(not(test))]
pub const PTY_EXEC_DATA_SIZE: usize = 2048;
#[cfg(test)]
pub const PTY_EXEC_DATA_SIZE: usize = 5;
const SIZE_1MB: usize = 1 * 1024 * 1024;

pub struct TSSH {
    event_bus: Arc<EventBus>,
    stop_counter: Arc<AtomicU64>,
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    ws_seq_num: AtomicU64,
    limiter: RwLock<RateLimiter>,
    runtime: Runtime,
}

static TSSH: OnceLock<TSSH> = OnceLock::new();

pub fn run(event_bus: &Arc<EventBus>, running_task_num: &Arc<AtomicU64>) {
    TSSH.get_or_init(|| {
        let g = TSSH {
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

impl TSSH {
    pub fn instance() -> &'static TSSH {
        TSSH.get().expect("runtime")
    }

    pub fn sync_dispatch<T: HandlerExt>(msg: Vec<u8>, need_channel: bool) {
        let rt = &TSSH::instance().runtime;
        rt.block_on(T::dispatch(msg, need_channel));
    }

    pub fn dispatch<T: HandlerExt>(msg: Vec<u8>, need_channel: bool) {
        let rt = &TSSH::instance().runtime;
        rt.spawn(async move { T::dispatch(msg, need_channel).await });
    }

    pub async fn add_session(session_id: &str, session: Arc<Session>) -> Result<()> {
        let gather = TSSH::instance();
        let mut sessions = gather.sessions.write().await;
        if sessions.contains_key(session_id) {
            error!("duplicate add_session: {session_id}");
            Err(anyhow!("session `{session_id}` already start"))?
        }

        sessions.insert(session_id.to_owned(), session.clone());
        info!("add_session: {}", session_id);
        gather.stop_counter.fetch_add(1, SeqCst);
        tokio::spawn(async move { session.process_output().await });
        Ok(())
    }

    pub async fn remove_session(session_id: &str) {
        let op = TSSH::instance().sessions.write().await.remove(session_id);
        if let Some(s) = op {
            s.stop().await;
            info!("remove_session: {}", session_id);
            TSSH::instance().stop_counter.fetch_sub(1, SeqCst);
        }
    }

    pub async fn get_session(session_id: &str) -> Option<Arc<Session>> {
        TSSH::instance()
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|s| s.clone())
    }

    pub async fn set_limiter(rate: usize) {
        let mut l = TSSH::instance().limiter.write().await;
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
        let gather = TSSH::instance();
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
