use super::{gather::Gather, session::Channel};
use crate::network::types::ws_msg::{PtyBinBase, PtyBinErrMsg, PtyError, PtyJsonBase, WsMsg};

use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use bson::Document;
use log::error;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

#[async_trait]
pub trait Handler {
    async fn process(self);
}

pub struct BsonHandler<T> {
    pub channel: Option<Arc<Channel>>,
    pub request: PtyBinBase<T>,
    pub op_type: String,
}

impl<T> BsonHandler<T>
where
    T: DeserializeOwned + Default + Sync + Send + 'static,
{
    pub fn id(&self) -> String {
        format!("{}:{}", self.request.session_id, self.request.channel_id)
    }

    pub fn dispatch(msg: Vec<u8>, channel_required: bool)
    where
        Self: Handler,
    {
        let doc = match Document::from_reader(&mut Cursor::new(&msg[..])) {
            Ok(doc) => doc,
            Err(e) => return error!("BsonHandler::dispatch from_reader failed: {}", e),
        };

        let msg = match bson::from_document::<WsMsg<PtyBinBase<T>>>(doc) {
            Ok(msg) => msg,
            Err(e) => return error!("BsonHandler::dispatch from_document failed: {}", e),
        };

        let op = msg.r#type.clone();

        let Some(req) = msg.data else {
            return error!("BsonHandler::dispatch {} msg.data is None", msg.r#type);
        };

        let session_id = req.session_id.clone();
        let channel_id = req.channel_id.clone();

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

        Gather::runtime().spawn(async move {
            if let Some(session) = Gather::get_session(&session_id).await {
                if let Some(channel) = session.get_channel(&channel_id).await {
                    handler.channel = Some(channel);
                }
            }

            if channel_required && handler.channel.is_none() {
                error!("BsonHandler::dispatch channel `{}` not found", handler.id());
                return handler.reply(PtyBinErrMsg::new("Channel not found")).await;
            }

            handler.process().await
        });
    }

    pub async fn reply<M: Serialize>(&self, data: M) {
        Self::reply_with(&self.request, &self.op_type, data).await
    }

    async fn reply_with<M: Serialize>(req: &PtyBinBase<T>, op: &str, data: M) {
        let session_id = req.session_id.clone();
        let channel_id = req.channel_id.clone();
        let custom_data = req.custom_data.clone();
        let msg = PtyBinBase {
            session_id,
            channel_id,
            custom_data,
            data,
        };
        Gather::reply_bson_msg(op, msg).await
    }
}

// #[derive(Clone)]
pub struct JsonHandler<T> {
    pub channel: Option<Arc<Channel>>,
    pub request: PtyJsonBase<T>,
}

impl<T> JsonHandler<T>
where
    T: DeserializeOwned + Default + Sync + Send + 'static,
{
    pub fn id(&self) -> String {
        format!("{}:{}", self.request.session_id, self.request.channel_id)
    }

    pub fn dispatch(msg: Vec<u8>, channel_required: bool)
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
            .map(|v| v.as_str())
            .flatten()
            .unwrap_or_default()
            .to_owned();

        let Ok(request) = serde_json::from_value::<PtyJsonBase<T>>(json_data.clone()) else {
            return error!("JsonHandler::dispatch parse Data failed: {}", msg);
        };

        let mut handler = Self {
            channel: None,
            request,
        };

        Gather::runtime().spawn(async move {
            if let Some(session) = Gather::get_session(&session_id).await {
                if let Some(channel) = session.get_channel(&channel_id).await {
                    handler.channel = Some(channel);
                }
            }

            if channel_required && handler.channel.is_none() {
                error!("JsonHandler::dispatch channel `{}` not found", handler.id());
                return handler.reply(PtyError::new("Channel not found")).await;
            }

            handler.process().await
        });
    }

    pub async fn reply<M: Serialize>(&self, data: M) {
        let msg_type = get_msg_type(&data);
        let body = PtyJsonBase {
            session_id: self.request.session_id.clone(),
            channel_id: self.request.channel_id.clone(),
            data,
        };
        Gather::reply_json_msg(&msg_type, body).await
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
    use crate::network::types::ws_msg::{PtyError, PtyOutput, PtyReady};

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
