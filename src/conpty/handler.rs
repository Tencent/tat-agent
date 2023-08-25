use super::{gather::PtyGather, pty::PtySession};
use super::{PtyBase, WS_MSG_TYPE_PTY_ERROR, WS_TXT_MSG};
use crate::common::utils::get_now_secs;
use crate::network::types::ws_msg::{PtyBinBase, PtyBinErrMsg, PtyError, WsMsg};
use std::io::Cursor;
use std::sync::{atomic::Ordering, Arc};

use bson::Document;
use log::error;
use serde::{de::DeserializeOwned, Serialize};

pub trait Handler {
    fn process(self);
}

#[derive(Clone)]
pub struct BsonHandler<T> {
    pub associate_pty: Arc<dyn PtyBase + Send + Sync>,
    pub request: Arc<PtyBinBase<T>>,
    pub op_type: String,
}

impl<T> BsonHandler<T>
where
    T: DeserializeOwned + Default + Sync + Send + 'static,
{
    pub fn dispatch(msg: Vec<u8>)
    where
        BsonHandler<T>: Handler,
    {
        let Ok(doc) = Document::from_reader(&mut Cursor::new(&msg[..]))
            .map_err(|e| error!("dispatch_operation from_reader failed: {}", e ))
        else { return; };

        let msg = match bson::from_document::<WsMsg<PtyBinBase<T>>>(doc) {
            Ok(msg) => msg,
            Err(e) => return error!("dispatch_operation from_document failed: {}", e),
        };

        let req = match msg.data {
            Some(req) => req,
            None => return error!("{} msg.data is None", msg.r#type),
        };

        let op = msg.r#type.to_string();
        match PtyGather::get_session(&req.session_id) {
            Some(session) => {
                //update last input time
                session.last_time.store(get_now_secs(), Ordering::SeqCst);
                let handle = BsonHandler::<T> {
                    associate_pty: session.pty_base.clone(),
                    request: Arc::new(req),
                    op_type: op,
                };
                handle.process();
            }
            None => {
                error!("Session {} not found", req.session_id);
                let msg = PtyBinBase::<PtyBinErrMsg> {
                    session_id: req.session_id,
                    custom_data: req.custom_data,
                    data: PtyBinErrMsg::new("Session not found"),
                };
                return PtyGather::reply_bson_msg(&op, msg);
            }
        };
    }

    pub fn reply<M: Serialize>(&self, msg: M) {
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
pub struct JsonHandler<T> {
    pub associate_session: Option<Arc<PtySession>>,
    pub request: T,
    pub _op_type: String,
}

impl<T> JsonHandler<T>
where
    T: DeserializeOwned + Default + Sync + Send + 'static,
{
    pub fn dispatch(msg: Vec<u8>, session_required: bool)
    where
        JsonHandler<T>: Handler,
    {
        let msg = String::from_utf8_lossy(&msg[..]);
        let get_session_id = |msg: &str| {
            let id = serde_json::from_str::<serde_json::Value>(msg)
                .ok()?
                .get("Data")?
                .get("SessionId")?
                .as_str()?
                .to_owned();
            Some(id)
        };

        let session_id = match get_session_id(&msg) {
            Some(session_id) => session_id,
            None => return error!("parse session_id failed: {}", msg),
        };

        let ws_msg: WsMsg<T> = match serde_json::from_str(&msg) {
            Ok(ws_msg) => ws_msg,
            Err(_) => return error!("parse WsMsg failed: {}", msg),
        };

        if ws_msg.data.is_none() {
            return error!("no request data: {}", msg);
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
            error!("Session {} not found", session_id);
            let pty_error = PtyError {
                session_id: session_id.to_owned(),
                reason: format!("Session {} not exist", session_id),
            };
            PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_ERROR, pty_error);
        }
    }

    pub fn reply<M: Serialize>(&self, msg_type: &str, msg_body: M) {
        let self_0 = PtyGather::instance();
        let msg = WsMsg {
            r#type: msg_type.to_string(),
            seq: self_0.ws_seq_num.fetch_add(1, Ordering::SeqCst),
            data: Some(msg_body),
        };

        PtyGather::instance().event_bus.dispatch(
            WS_TXT_MSG,
            serde_json::to_string(&msg)
                .expect("serialize failed")
                .into_bytes(),
        )
    }
}
