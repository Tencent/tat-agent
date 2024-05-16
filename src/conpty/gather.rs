use super::file::register_file_handlers;
use super::proxy::register_proxy_handlers;
use super::pty::register_pty_handlers;
use super::session::Session;
use super::{WS_BIN_MSG, WS_TXT_MSG};
use crate::common::evbus::EventBus;
use crate::network::types::ws_msg::{PtyBinBase, PtyJsonBase, WsMsg};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, RwLock};

use log::{error, info};
use once_cell::sync::OnceCell;
use serde::Serialize;
use tokio::runtime::{Builder, Runtime};

pub struct Gather {
    pub event_bus: Arc<EventBus>,
    pub stop_counter: Arc<AtomicU64>,
    pub sessions: RwLock<HashMap<String, Arc<Session>>>,
    pub ws_seq_num: AtomicU64,
    runtime: Arc<Runtime>,
}

static GATHER: OnceCell<Arc<Gather>> = OnceCell::new();

pub fn run(event_bus: &Arc<EventBus>, running_task_num: &Arc<AtomicU64>) {
    GATHER.get_or_init(|| {
        let sg = Arc::new(Gather {
            event_bus: event_bus.clone(),
            stop_counter: running_task_num.clone(),
            sessions: RwLock::new(HashMap::default()),
            ws_seq_num: AtomicU64::new(0),
            // Builder::new_multi_thread()
            runtime: Builder::new()
                .threaded_scheduler()
                .enable_all()
                .build()
                .expect("build pty runtime failed")
                .into(),
        });

        register_pty_handlers(event_bus);
        register_file_handlers(event_bus);
        register_proxy_handlers(event_bus);
        sg
    });
}

impl Gather {
    pub fn instance() -> Arc<Gather> {
        GATHER.get().expect("runtime").clone()
    }

    pub fn runtime() -> Arc<Runtime> {
        Gather::instance().runtime.clone()
    }

    pub fn add_session(session_id: &str, session: Arc<Session>) -> Result<(), String> {
        let gather = Gather::instance();
        let mut sessions = gather.sessions.write().expect("lock failed");
        if sessions.contains_key(session_id) {
            error!("duplicate add_session: {session_id}");
            Err(format!("session `{session_id}` already start"))?
        }

        sessions.insert(session_id.to_owned(), session.clone());
        info!("add_session: {}", session_id);
        gather.stop_counter.fetch_add(1, SeqCst);
        Gather::runtime().spawn(async move { session.process_output().await });
        Ok(())
    }

    pub fn remove_session(session_id: &str) {
        let _ = Gather::instance()
            .sessions
            .write()
            .expect("lock failed")
            .remove(session_id)
            .map(|s| s.stop())
            .map(|_| {
                info!("remove_session: {}", session_id);
                Gather::instance().stop_counter.fetch_sub(1, SeqCst);
            });
    }

    pub fn get_session(session_id: &str) -> Option<Arc<Session>> {
        Gather::instance()
            .sessions
            .read()
            .expect("lock failed")
            .get(session_id)
            .map(|s| s.clone())
    }

    pub fn reply_json_msg<T: Serialize>(msg_type: &str, data: PtyJsonBase<T>) {
        let serialize = |ws_msg| {
            serde_json::to_string(&ws_msg)
                .expect("json serialize failed")
                .into_bytes()
        };
        Self::reply(msg_type, data, WS_TXT_MSG, serialize);
    }

    pub fn reply_bson_msg<T: Serialize>(msg_type: &str, data: PtyBinBase<T>) {
        let serialize = |ws_msg| {
            let mut msg = Vec::new();
            let _ = bson::to_bson(&ws_msg)
                .expect("to_bson failed")
                .as_document()
                .expect("as_document failed")
                .to_writer(&mut msg);
            msg
        };
        Self::reply(msg_type, data, WS_BIN_MSG, serialize);
    }

    fn reply<T, F>(msg_type: &str, data: T, event: &str, serialize: F)
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
        gather.event_bus.dispatch(event, msg);
    }
}
