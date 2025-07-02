use super::{session::Channel, Tssh};
use crate::common::evbus;
use crate::network::{PtyBinBase, PtyBinErrMsg, PtyError, PtyJsonBase, WsMsg};

use std::{future::Future, io::Cursor, sync::Arc};

use bson::Document;
use log::error;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

/// use for handling specific request messages
pub trait Handler {
    /// type of the request message, extracted from WsMsg.r#type
    const MSG_TYPE: &str;

    /// if the request depends on an existing channel, default value is true
    const NEED_CHANNEL: bool = true;

    /// if the request must be strictly dispatched synchronously, default value is false
    const NEED_SYNC_DISPATCH: bool = false;

    /// handle request
    fn process(self) -> impl Future<Output = ()> + Send;
}

/// use for handling a type of request message, such as JSON or BSON requests
pub trait HandlerExt: Handler + 'static {
    /// get the unique ID of a channel for logging purposes
    fn id(&self) -> String;

    /// preprocess upon receiving a request and call the handling function
    fn dispatch(msg: Vec<u8>) -> impl Future<Output = ()> + Send + 'static;

    /// reply the response message
    async fn reply<M: Serialize>(&self, data: M);

    /// register the request handler to the event bus
    async fn register() {
        if Self::NEED_SYNC_DISPATCH {
            return evbus::subscribe_future(Self::MSG_TYPE, Self::dispatch).await;
        }
        let handler = |msg| tokio::spawn(async move { Self::dispatch(msg).await });
        evbus::subscribe(Self::MSG_TYPE, handler).await;
    }
}

pub struct BsonHandler<T> {
    pub channel: Option<Arc<Channel>>,
    pub request: PtyBinBase<T>,
    pub op_type: String,
}

impl<T> HandlerExt for BsonHandler<T>
where
    T: DeserializeOwned + Default + Send + Sync + 'static,
    Self: Handler,
{
    fn id(&self) -> String {
        format!("{}:{}", self.request.session_id, self.request.channel_id)
    }

    async fn dispatch(msg: Vec<u8>)
    where
        Self: Handler,
    {
        let doc = match Document::from_reader(&mut Cursor::new(&msg[..])) {
            Ok(doc) => doc,
            Err(e) => return error!("BsonHandler::dispatch from_reader failed: {:#}", e),
        };

        let msg = match bson::from_document::<WsMsg<PtyBinBase<T>>>(doc) {
            Ok(msg) => msg,
            Err(e) => return error!("BsonHandler::dispatch from_document failed: {:#}", e),
        };

        let op = msg.r#type.clone();

        let Some(req) = msg.data else {
            return error!("BsonHandler::dispatch {} msg.data is None", msg.r#type);
        };

        // Compatible with legacy front-end code
        // If no channel_id is provided, use empty string as channel_id.
        // if session_id.is_empty() || channel_id.is_empty() {
        //     todo!()
        // }

        let mut handler = Self {
            channel: None,
            request: req,
            op_type: op,
        };

        let session_id = &handler.request.session_id;
        let channel_id = &handler.request.channel_id;

        if let Some(session) = Tssh::get_session(session_id).await {
            if let Some(channel) = session.get_channel(channel_id).await {
                handler.channel = Some(channel);
            }
        }

        if Self::NEED_CHANNEL && handler.channel.is_none() {
            error!("BsonHandler::dispatch channel `{}` not found", handler.id());
            return handler.reply(PtyBinErrMsg::new("Channel not found")).await;
        }

        handler.process().await
    }

    async fn reply<M: Serialize>(&self, data: M) {
        let msg = PtyBinBase {
            session_id: self.request.session_id.clone(),
            channel_id: self.request.channel_id.clone(),
            custom_data: self.request.custom_data.clone(),
            data,
        };
        Tssh::reply_bson_msg(&self.op_type, msg).await
    }
}

pub struct JsonHandler<T> {
    pub channel: Option<Arc<Channel>>,
    pub request: PtyJsonBase<T>,
}

impl<T> HandlerExt for JsonHandler<T>
where
    T: DeserializeOwned + Default + Send + Sync + 'static,
    Self: Handler,
{
    fn id(&self) -> String {
        format!("{}:{}", self.request.session_id, self.request.channel_id)
    }

    async fn dispatch(msg: Vec<u8>)
    where
        Self: Handler,
    {
        let msg = String::from_utf8_lossy(&msg[..]);

        let Ok(json_msg) = serde_json::from_str::<Value>(&msg) else {
            return error!("JsonHandler::dispatch parse msg failed: {}", msg);
        };

        let Some(json_data) = json_msg.get("Data") else {
            return error!("JsonHandler::dispatch no request data: {}", msg);
        };

        let Some(Some(session_id)) = json_data.get("SessionId").map(|v| v.as_str()) else {
            return error!("JsonHandler::dispatch parse SessionId failed: {}", msg);
        };
        let session_id = session_id.to_owned();

        // Compatible with legacy front-end code
        // If no channel_id is provided, use empty string as channel_id.
        let channel_id = json_data
            .get("ChannelId")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();

        let Ok(request) = serde_json::from_value::<PtyJsonBase<T>>(json_data.clone()) else {
            return error!("JsonHandler::dispatch parse Data failed: {}", msg);
        };

        let mut handler = Self {
            channel: None,
            request,
        };

        if let Some(session) = Tssh::get_session(&session_id).await {
            if let Some(channel) = session.get_channel(&channel_id).await {
                handler.channel = Some(channel);
            }
        }

        if Self::NEED_CHANNEL && handler.channel.is_none() {
            error!("JsonHandler::dispatch channel `{}` not found", handler.id());
            return handler.reply(PtyError::new("Channel not found")).await;
        }

        handler.process().await
    }

    async fn reply<M: Serialize>(&self, data: M) {
        let msg_type = get_msg_type(&data);
        let body = PtyJsonBase {
            session_id: self.request.session_id.clone(),
            channel_id: self.request.channel_id.clone(),
            data,
        };
        Tssh::reply_json_msg(&msg_type, body).await
    }
}

// only works for non-generic types
// For example: Type 'S' is supported, but type 'S<T>' with generics is not supported
fn get_msg_type<M: Serialize>(_: &M) -> String {
    let msg_type_abs = std::any::type_name::<M>();
    msg_type_abs
        .rsplit_once("::")
        .map(|(_, s)| s)
        .unwrap_or(msg_type_abs)
        .to_string()
}

#[cfg(test)]
mod test {
    use super::get_msg_type;
    use crate::network::{PtyError, PtyOutput, PtyReady};

    #[test]
    fn test_get_msg_type() {
        let d = PtyError::new("");
        let t = get_msg_type(&d);
        assert_eq!("PtyError", t);

        let d = PtyReady {};
        let t = get_msg_type(&d);
        assert_eq!("PtyReady", t);

        let d = PtyOutput {
            output: "".to_owned(),
        };
        let t = get_msg_type(&d);
        assert_eq!("PtyOutput", t);
    }
}
