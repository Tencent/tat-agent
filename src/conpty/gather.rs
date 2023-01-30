use log::info;
use once_cell::sync::OnceCell;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};
use tokio::runtime::{Builder, Runtime};

use crate::common::evbus::EventBus;
use crate::network::types::ws_msg::WsMsg;
use crate::{
    common::consts::{WS_BIN_MSG, WS_TXT_MSG},
    network::types::ws_msg::PtyBinBase,
};

use super::{
    file::register_file_handlers,
    proxy::{register_proxy_handlers, PtyProxy},
    pty::{register_pty_handlers, PtySession},
};

#[derive(Clone)]
pub(crate) struct PtyGather {
    pub(crate) ws_seq_num: Arc<AtomicU64>,
    pub(crate) stop_counter: Arc<AtomicU64>,
    pub(crate) sessions: Arc<RwLock<HashMap<String, Arc<PtySession>>>>,
    pub(crate) proxies: Arc<RwLock<HashMap<String, Arc<PtyProxy>>>>,
    pub(crate) event_bus: Arc<EventBus>,
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
                Builder::new()
                    .threaded_scheduler()
                    .enable_all()
                    .build()
                    .expect("build pty runtime fail"),
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
        if let Some(_) = PtyGather::instance()
            .sessions
            .write()
            .expect("proxy lock fail")
            .insert(session_id.to_owned(), session)
        {
            info!("old session removed {}", session_id)
        } else {
            info!("session {} inserted", { session_id });
            PtyGather::instance()
                .stop_counter
                .fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn remove_session(session_id: &str) {
        if let Some(_session) = PtyGather::instance()
            .sessions
            .write()
            .expect("proxy lock fail")
            .remove(session_id)
        {
            info!("remove_session  {} removed", session_id);
            PtyGather::instance()
                .stop_counter
                .fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub(crate) fn get_session(session_id: &str) -> Option<Arc<PtySession>> {
        if let Some(session) = PtyGather::instance()
            .sessions
            .read()
            .expect("session read lock fail")
            .get(session_id)
        {
            return Some(session.clone());
        } else {
            None
        }
    }

    pub fn add_proxy(proxy_id: &str, proxy: Arc<PtyProxy>) {
        info!("add_proxy  {}", proxy_id);
        let _ = PtyGather::instance()
            .proxies
            .write()
            .expect("proxy lock fail")
            .insert(proxy_id.to_owned(), proxy);
    }

    pub fn remove_proxy(proxy_id: &str) -> Option<Arc<PtyProxy>> {
        if let Some(proxy) = PtyGather::instance()
            .proxies
            .write()
            .expect("proxy lock fail")
            .remove(proxy_id)
        {
            info!("remove_proxy  {} removed", proxy_id);
            return Some(proxy.clone());
        } else {
            None
        }
    }

    pub(crate) fn get_proxy(proxy_id: &str) -> Option<Arc<PtyProxy>> {
        if let Some(proxy) = PtyGather::instance()
            .proxies
            .read()
            .expect("proxy lock fail")
            .get(proxy_id)
        {
            return Some(proxy.clone());
        } else {
            None
        }
    }

    pub fn reply_json_msg<T>(msg_type: &str, msg_body: T)
    where
        T: Serialize,
    {
        let self_0 = PtyGather::instance();
        let msg = WsMsg {
            r#type: msg_type.to_string(),
            seq: self_0.ws_seq_num.fetch_add(1, Ordering::SeqCst),
            data: Some(msg_body),
        };

        PtyGather::instance().event_bus.dispatch(
            WS_TXT_MSG,
            serde_json::to_string(&msg)
                .expect("json serialize fail")
                .into_bytes(),
        )
    }

    pub fn reply_bson_msg<Rep>(msg_type: &str, data: PtyBinBase<Rep>)
    where
        Rep: Serialize,
    {
        let self_0 = PtyGather::instance();
        let ws_msg = WsMsg::<PtyBinBase<Rep>> {
            r#type: msg_type.to_string(),
            seq: self_0.ws_seq_num.fetch_add(1, Ordering::SeqCst),
            data: Some(data),
        };

        let mut result = Vec::new();
        let obj = bson::to_bson(&ws_msg).expect("to_bson fail");
        let doc = obj.as_document().expect("as_document fail");
        let _ = doc.to_writer(&mut result);
        PtyGather::instance().event_bus.dispatch(WS_BIN_MSG, result)
    }
}
