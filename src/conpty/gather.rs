use super::file::register_file_handlers;
use super::proxy::{register_proxy_handlers, PtyProxy};
use super::pty::{register_pty_handlers, PtySession};
use super::{WS_BIN_MSG, WS_TXT_MSG};
use crate::common::evbus::EventBus;
use crate::network::types::ws_msg::{PtyBinBase, WsMsg};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use log::info;
use once_cell::sync::OnceCell;
use serde::Serialize;
use tokio::runtime::{Builder, Runtime};

#[derive(Clone)]
pub struct PtyGather {
    pub ws_seq_num: Arc<AtomicU64>,
    pub stop_counter: Arc<AtomicU64>,
    pub sessions: Arc<RwLock<HashMap<String, Arc<PtySession>>>>,
    pub proxies: Arc<RwLock<HashMap<String, Arc<PtyProxy>>>>,
    pub event_bus: Arc<EventBus>,
    runtime: Arc<Runtime>,
}

static SESSION_GATHER: OnceCell<Arc<PtyGather>> = OnceCell::new();

pub fn run(event_bus: &Arc<EventBus>, running_task_num: &Arc<AtomicU64>) {
    let _ = SESSION_GATHER.get_or_try_init(|| -> Result<Arc<PtyGather>, ()> {
        let sg = Arc::new(PtyGather {
            event_bus: event_bus.clone(),
            sessions: Arc::new(RwLock::new(HashMap::default())),
            proxies: Arc::new(RwLock::new(HashMap::default())),
            stop_counter: running_task_num.clone(),
            ws_seq_num: Arc::new(AtomicU64::new(0)),
            runtime: Arc::new(
                // Builder::new_multi_thread()
                Builder::new()
                    .threaded_scheduler()
                    .enable_all()
                    .build()
                    .expect("build pty runtime failed"),
            ),
        });

        register_pty_handlers(event_bus);
        register_file_handlers(event_bus);
        register_proxy_handlers(event_bus);
        Ok(sg)
    });
}

impl PtyGather {
    pub fn runtime() -> Arc<Runtime> {
        PtyGather::instance().runtime.clone()
    }

    pub fn instance() -> Arc<PtyGather> {
        SESSION_GATHER.get().expect("runtime").clone()
    }

    pub fn add_session(session_id: &str, session: Arc<PtySession>) {
        let _ = PtyGather::instance()
            .sessions
            .write()
            .expect("proxy lock failed")
            .insert(session_id.to_owned(), session)
            .map(|_| info!("old session {} removed", session_id))
            .ok_or_else(|| {
                info!("session {} inserted", session_id);
                PtyGather::instance()
                    .stop_counter
                    .fetch_add(1, Ordering::SeqCst);
            });
    }

    pub fn remove_session(session_id: &str) {
        let _ = PtyGather::instance()
            .sessions
            .write()
            .expect("proxy lock failed")
            .remove(session_id)
            .map(|_| {
                info!("remove_session: {} removed", session_id);
                PtyGather::instance()
                    .stop_counter
                    .fetch_sub(1, Ordering::SeqCst);
            });
    }

    pub fn get_session(session_id: &str) -> Option<Arc<PtySession>> {
        PtyGather::instance()
            .sessions
            .read()
            .expect("session read lock failed")
            .get(session_id)
            .map(|s| s.clone())
    }

    pub fn add_proxy(proxy_id: &str, proxy: Arc<PtyProxy>) {
        info!("add_proxy: {}", proxy_id);
        let _ = PtyGather::instance()
            .proxies
            .write()
            .expect("proxy lock failed")
            .insert(proxy_id.to_owned(), proxy);
    }

    pub fn remove_proxy(proxy_id: &str) -> Option<Arc<PtyProxy>> {
        PtyGather::instance()
            .proxies
            .write()
            .expect("proxy lock failed")
            .remove(proxy_id)
            .map(|proxy| {
                info!("remove_proxy: {} removed", proxy_id);
                proxy.clone()
            })
    }

    pub fn get_proxy(proxy_id: &str) -> Option<Arc<PtyProxy>> {
        PtyGather::instance()
            .proxies
            .read()
            .expect("proxy lock failed")
            .get(proxy_id)
            .map(|p| p.clone())
    }

    pub fn reply_json_msg<T: Serialize>(msg_type: &str, msg_body: T) {
        let self_0 = PtyGather::instance();
        let msg = WsMsg {
            r#type: msg_type.to_string(),
            seq: self_0.ws_seq_num.fetch_add(1, Ordering::SeqCst),
            data: Some(msg_body),
        };

        PtyGather::instance().event_bus.dispatch(
            WS_TXT_MSG,
            serde_json::to_string(&msg)
                .expect("json serialize failed")
                .into_bytes(),
        )
    }

    pub fn reply_bson_msg<Rep: Serialize>(msg_type: &str, data: PtyBinBase<Rep>) {
        let self_0 = PtyGather::instance();
        let ws_msg = WsMsg::<PtyBinBase<Rep>> {
            r#type: msg_type.to_string(),
            seq: self_0.ws_seq_num.fetch_add(1, Ordering::SeqCst),
            data: Some(data),
        };

        let mut result = Vec::new();
        let obj = bson::to_bson(&ws_msg).expect("to_bson failed");
        let doc = obj.as_document().expect("as_document failed");
        let _ = doc.to_writer(&mut result);
        PtyGather::instance().event_bus.dispatch(WS_BIN_MSG, result)
    }
}
