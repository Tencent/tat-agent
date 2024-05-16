use super::gather::Gather;
use super::handler::{BsonHandler, Handler};
use super::session::{PluginCtrl, PluginData};
use crate::common::evbus::EventBus;
use crate::conpty::session::{Channel, Plugin, PluginComp, Session};
use crate::network::types::ws_msg::{
    ProxyClose, ProxyData, ProxyNew, ProxyReady, PtyBinBase, PtyBinErrMsg,
};

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::{error, info};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::SLOT_PTY_BIN;
const WS_MSG_TYPE_PTY_PROXY_NEW: &str = "PtyProxyNew";
const WS_MSG_TYPE_PTY_PROXY_READY: &str = "PtyProxyReady";
const WS_MSG_TYPE_PTY_PROXY_DATA: &str = "PtyProxyData";
const WS_MSG_TYPE_PTY_PROXY_CLOSE: &str = "PtyProxyClose";
const PROXY_REMOVE_INTERVAL: u64 = 60 * 5;
const PROXY_BUF_SIZE: usize = 2048;

pub fn register_proxy_handlers(event_bus: &Arc<EventBus>) {
    event_bus
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_NEW, move |msg| {
            BsonHandler::<ProxyNew>::dispatch(msg, false);
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_DATA, move |msg| {
            BsonHandler::<ProxyData>::dispatch(msg, true);
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_CLOSE, move |msg| {
            BsonHandler::<ProxyClose>::dispatch(msg, false);
        });
}

#[async_trait]
impl Handler for BsonHandler<ProxyNew> {
    async fn process(self) {
        let req = &self.request;
        let proxy_id = req.data.proxy_id.clone();
        info!("=>proxy_new `{}`, channel `{}`", proxy_id, self.id());

        let channel_id = match self.channel.as_ref() {
            Some(ch) if ch.plugin.try_get_proxy().is_some() => {
                error!("duplicate proxy_new `{proxy_id}`");
                return self.reply(PtyBinErrMsg::new(format!("proxy already start")));
            }
            // Compatible with legacy front-end code
            // If no channel_id is provided, use proxy_id as channel_id.
            _ if req.channel_id.is_empty() => proxy_id.clone(),
            Some(_) => {
                error!("channel `{}` already start", self.id());
                return self.reply(PtyBinErrMsg::new(format!("channel already start")));
            }
            None => req.channel_id.clone(),
        };

        let dest = format!("127.0.0.1:{}", req.data.port);
        let r = TcpStream::connect(&dest).await;
        let Ok(stream) = r.map_err(|e| info!("proxy `{proxy_id}` connect failed: {e}")) else {
            return;
        };
        let (reader, writer) = stream.into_split();
        let proxy = Proxy {
            proxy_id: proxy_id.clone(),
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        };
        let plugin = Plugin {
            component: PluginComp::Proxy(proxy),
            data: req.into(),
            controller: PluginCtrl::new(PROXY_REMOVE_INTERVAL),
        };
        let channel = Arc::new(Channel::new(&req.session_id, &channel_id, plugin));
        let session = Gather::get_session(&req.session_id).unwrap_or_else(|| {
            let s = Arc::new(Session::new(&req.session_id));
            let _ = Gather::add_session(&req.session_id, s.clone());
            s
        });

        if let Err(e) = session.add_channel(&channel_id, channel) {
            return self.reply(PtyBinErrMsg::new(e));
        }

        let data = PtyBinBase {
            session_id: req.session_id.clone(),
            channel_id: req.channel_id.clone(),
            custom_data: "".to_owned(),
            data: ProxyReady { proxy_id },
        };
        Gather::reply_bson_msg(WS_MSG_TYPE_PTY_PROXY_READY, data);
    }
}

#[async_trait]
impl Handler for BsonHandler<ProxyData> {
    async fn process(self) {
        let req = &self.request;
        let proxy_id = &req.data.proxy_id;
        // info!("=>proxy_data `{}`, channel `{}`", proxy_id, self.id());

        let mut ch = self.channel.unwrap().clone();
        // Compatible with legacy front-end code
        // If no channel_id is provided, use proxy_id as channel_id.
        if req.channel_id.is_empty() {
            if let Some(session) = Gather::get_session(&req.session_id) {
                if let Some(channel) = session.get_channel(proxy_id) {
                    ch = channel.clone();
                }
            }
        }
        let Some(proxy) = ch.plugin.try_get_proxy() else {
            return error!("proxy `{}` not found", proxy_id);
        };

        let _ = proxy
            .writer
            .lock()
            .await
            .write_all(&req.data.data)
            .await
            .map_err(|err| error!("proxy_data `{}` write failed: {}", proxy_id, err));
    }
}

#[async_trait]
impl Handler for BsonHandler<ProxyClose> {
    async fn process(self) {
        let req = &self.request;
        let proxy_id = &req.data.proxy_id;
        info!("=>proxy_closed `{}`, channel `{}`", proxy_id, self.id());
        let Some(session) = Gather::get_session(&req.session_id) else {
            return;
        };
        if req.channel_id.is_empty() {
            // Compatible with legacy front-end code
            // If no channel_id is provided, use proxy_id as channel_id.
            session.remove_channel(proxy_id);
        } else if self.channel.is_some() {
            session.remove_channel(&req.channel_id);
        }
    }
}

pub struct Proxy {
    pub proxy_id: String,
    reader: Mutex<OwnedReadHalf>,
    writer: Mutex<OwnedWriteHalf>,
}

impl Proxy {
    pub async fn process(&self, id: &str, data: &PluginData, ctrl: &PluginCtrl) {
        let mut buffer = [0u8; PROXY_BUF_SIZE];
        let mut size = 0;
        let mut count = 0;
        let mut stopper_rx = ctrl.stopper.get_receiver().expect("get_receiver failed");
        let mut reader = self.reader.lock().await;
        // Upon initialization, set the last reply time to an instant before the timer was created.
        let mut last_reply = Instant::now() - Duration::from_secs(PROXY_REMOVE_INTERVAL);

        info!("Proxy `{}` start loop for proxy responses", id);
        loop {
            tokio::select! {
                res = reader.read(&mut buffer[..]) => match res {
                    Ok(0) => break info!("Proxy `{}` closed", id),
                    Ok(i) => {
                        let msg_data = ProxyData {
                            proxy_id: self.proxy_id.clone(),
                            data: buffer[..i].to_vec(),
                        };
                        self.post(WS_MSG_TYPE_PTY_PROXY_DATA, data, msg_data);
                        last_reply = Instant::now();
                        size += i;
                        count += 1;
                    }
                    Err(e) => break error!("Proxy `{}` read failed: {}", id, e),
                },
                _ = &mut stopper_rx => break info!("Proxy `{}` stopped", id),
                _ = ctrl.timer.timeout() => if ctrl.timer.is_timeout_refresh(last_reply) {
                    break info!("Proxy `{}` timeout", id);
                },
            };
        }

        let msg_data = ProxyClose {
            proxy_id: self.proxy_id.clone(),
        };
        self.post(WS_MSG_TYPE_PTY_PROXY_CLOSE, data, msg_data);
        info!("Proxy `{}` send total size: {}, count: {}", id, size, count);
    }

    fn post<T: Serialize>(&self, msg_type: &str, ids: &PluginData, data: T) {
        let data = PtyBinBase {
            session_id: ids.session_id.clone(),
            channel_id: ids.channel_id.clone(),
            custom_data: "".to_owned(),
            data,
        };
        Gather::reply_bson_msg(msg_type, data);
    }
}
