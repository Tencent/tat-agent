mod file;
mod handler;
mod proxy;
mod pty;
mod session;

use self::file::register_file_handlers;
use self::proxy::register_proxy_handlers;
use self::pty::register_pty_handlers;
use self::session::Session;
use crate::common::evbus;
use crate::network::types::ws_msg::MsgFormat;
use crate::network::types::ws_msg::{MsgBase, MsgId, MsgSpec};

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, bail};
use leaky_bucket::RateLimiter;
use log::{error, info};
use serde::Serialize;
use tokio::{sync::OnceCell, sync::RwLock};

pub const WS_TXT_MSG: &str = "pty_cmd_msg";
pub const WS_BIN_MSG: &str = "pty_file_msg";
pub const PTY_INSPECT_READ: u8 = 0x0;
pub const PTY_INSPECT_WRITE: u8 = 0x1;
#[cfg(windows)]
pub const PTY_FLAG_ENABLE_BLOCK: u32 = 0x00000001;
#[cfg(not(test))]
pub const PTY_EXEC_DATA_SIZE: usize = 2048;
#[cfg(test)]
pub const PTY_EXEC_DATA_SIZE: usize = 5;
const SIZE_1MB: usize = 1024 * 1024;

pub struct Tssh {
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    ws_seq_num: AtomicU64,
    limiter: RwLock<RateLimiter>,
}

static TSSH: OnceCell<Tssh> = OnceCell::const_new();

pub async fn run() {
    TSSH.get_or_init(|| async {
        let g = Tssh {
            sessions: RwLock::new(HashMap::new()),
            ws_seq_num: AtomicU64::new(0),
            limiter: RwLock::new(build_limiter(SIZE_1MB)),
        };

        register_pty_handlers().await;
        register_file_handlers().await;
        register_proxy_handlers().await;
        g
    })
    .await;
}

impl Tssh {
    pub fn instance() -> &'static Tssh {
        TSSH.get().expect("runtime")
    }

    pub async fn add_session(session_id: &str, session: Arc<Session>) -> Result<()> {
        let gather = Tssh::instance();
        let mut sessions = gather.sessions.write().await;
        if sessions.contains_key(session_id) {
            error!("duplicate add_session: {session_id}");
            bail!("session `{session_id}` already start");
        }

        sessions.insert(session_id.to_owned(), session.clone());
        info!("add_session: {}", session_id);
        tokio::spawn(async move { session.process_output().await });
        Ok(())
    }

    pub async fn remove_session(session_id: &str) {
        let op = Tssh::instance().sessions.write().await.remove(session_id);
        if let Some(s) = op {
            s.stop().await;
            info!("remove_session: {}", session_id);
        }
    }

    pub async fn get_session(session_id: &str) -> Option<Arc<Session>> {
        Tssh::instance()
            .sessions
            .read()
            .await
            .get(session_id)
            .cloned()
    }

    pub async fn set_limiter(rate: usize) {
        let mut l = Tssh::instance().limiter.write().await;
        *l = build_limiter(rate);
    }

    async fn reply<F, T>(data: MsgId<F, T>)
    where
        F: MsgFormat,
        T: MsgSpec + Serialize,
    {
        let gather = Tssh::instance();
        let msg = MsgBase {
            r#type: T::MSG_TYPE.to_string(),
            seq: gather.ws_seq_num.fetch_add(1, Ordering::Relaxed),
            data,
        };
        let bytes = F::to_bytes(&msg);
        gather.limiter.read().await.acquire(bytes.len()).await;
        evbus::emit(F::msg_event(), bytes).await;
    }
}

fn build_limiter(data_per_sec: usize) -> RateLimiter {
    RateLimiter::builder()
        .max(data_per_sec)
        .refill(data_per_sec / 10)
        .interval(tokio::time::Duration::from_millis(100))
        .build()
}
