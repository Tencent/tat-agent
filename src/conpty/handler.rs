use bson::Document;
use log::error;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::Cursor,
    sync::{atomic::Ordering, Arc},
};

use crate::{
    common::{
        consts::{WS_MSG_TYPE_PTY_ERROR, WS_TXT_MSG},
        utils::get_now_secs,
    },
    network::types::ws_msg::{PtyBinBase, PtyBinErrMsg, PtyError, WsMsg},
};

use super::{gather::PtyGather, pty::PtySession, PtyBase};

pub trait Handler {
    fn process(self);
}

#[derive(Clone)]
pub(crate) struct BsonHandler<T> {
    pub(crate) associate_pty: Arc<dyn PtyBase + Send + Sync>,
    pub(crate) request: Arc<PtyBinBase<T>>,
    pub(crate) op_type: String,
}

impl<T> BsonHandler<T>
where
    T: DeserializeOwned + Default + Sync + Send + 'static,
{
    pub(crate) fn dispatch(msg: Vec<u8>)
    where
        BsonHandler<T>: Handler,
    {
        match Document::from_reader(&mut Cursor::new(&msg[..])) {
            Ok(doc) => {
                let msg = match bson::from_document::<WsMsg<PtyBinBase<T>>>(doc) {
                    Ok(msg) => msg,
                    Err(e) => {
                        log::error!("dispatch_operation from_document fail {}", e.to_string());
                        return;
                    }
                };

                let req = match msg.data {
                    Some(req) => req,
                    None => {
                        log::error!("{} msg.data is None", msg.r#type);
                        return;
                    }
                };

                let op = msg.r#type.to_string();
                if let Some(session) = PtyGather::get_session(&req.session_id) {
                    //update last input time
                    session.last_time.store(get_now_secs(), Ordering::SeqCst);
                    let handle = BsonHandler::<T> {
                        associate_pty: session.pty_base.clone(),
                        request: Arc::new(req),
                        op_type: op,
                    };
                    handle.process();
                } else {
                    error!("Session {} not find", req.session_id);
                    let session_id = req.session_id;
                    let custom = req.custom_data;
                    let msg = PtyBinBase::<PtyBinErrMsg> {
                        session_id: session_id.clone(),
                        custom_data: custom.clone(),
                        data: PtyBinErrMsg {
                            error: "Session not find".to_owned(),
                        },
                    };
                    return PtyGather::reply_bson_msg(&op, msg);
                };
            }
            Err(e) => {
                log::error!("dispatch_operation from_reader fail {}", e.to_string())
            }
        };
    }

    pub(crate) fn reply<M>(&self, msg: M)
    where
        M: Serialize,
    {
        let session_id = self.request.session_id.clone();
        let custom = self.request.custom_data.clone();
        let msg = PtyBinBase::<M> {
            session_id: session_id.clone(),
            custom_data: custom.clone(),
            data: msg,
        };
        return PtyGather::reply_bson_msg(&self.op_type, msg);
    }
}

#[derive(Clone)]
pub(crate) struct JsonHandler<T> {
    pub(crate) associate_session: Option<Arc<PtySession>>,
    pub(crate) request: T,
    pub(crate) _op_type: String,
}

impl<T> JsonHandler<T>
where
    T: DeserializeOwned + Default + Sync + Send + 'static,
{
    pub(crate) fn dispatch(msg: Vec<u8>, session_required: bool)
    where
        JsonHandler<T>: Handler,
    {
        let msg = String::from_utf8_lossy(&msg[..]);
        let get_session_id = |msg: &str| -> Option<String> {
            Some(
                serde_json::from_str::<serde_json::Value>(msg)
                    .ok()?
                    .get("Data")?
                    .get("SessionId")?
                    .as_str()?
                    .to_owned(),
            )
        };

        let session_id = match get_session_id(&msg) {
            Some(session_id) => session_id,
            None => {
                error!("parse session_id fail {}", msg);
                return;
            }
        };

        let ws_msg: WsMsg<T> = match serde_json::from_str(&msg) {
            Ok(ws_msg) => ws_msg,
            Err(_) => {
                error!("parse WsMsg fail {}", msg);
                return;
            }
        };

        if ws_msg.data.is_none() {
            error!("no request data {}", msg);
            return;
        };

        let op = ws_msg.r#type.to_string();
        if let Some(session) = PtyGather::get_session(&session_id) {
            //update last input time
            session.last_time.store(get_now_secs(), Ordering::SeqCst);
            let handle = JsonHandler::<T> {
                associate_session: Some(session.clone()),
                request: ws_msg.data.expect("no request data"),
                _op_type: op.to_string(),
            };
            return handle.process();
        }

        if !session_required {
            let handle = JsonHandler::<T> {
                associate_session: None,
                request: ws_msg.data.expect("no request data"),
                _op_type: op.to_string(),
            };
            handle.process();
        } else {
            error!("Session {} not find", session_id);
            let pty_error = PtyError {
                session_id: session_id.to_owned(),
                reason: format!("Session {} not exist", session_id),
            };
            PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_ERROR, pty_error);
        }
    }

    pub fn reply<M>(&self, msg_type: &str, msg_body: M)
    where
        M: Serialize,
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
                .expect("serialize fail")
                .into_bytes(),
        )
    }
}
