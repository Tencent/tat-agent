use super::handler::{BsonHandler, Handler};
use super::session::{PluginCtrl, PluginData};
use super::TSSH;
use crate::common::evbus::EventBus;
use crate::network::{ProxyClose, ProxyData, ProxyNew, ProxyReady, PtyBinBase, PtyBinErrMsg};
use crate::tssh::handler::HandlerExt;
use crate::tssh::session::{Channel, Plugin, PluginComp, Session};

use std::sync::Arc;

use log::{error, info};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
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
            TSSH::dispatch::<BsonHandler<ProxyNew>>(msg, false);
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_DATA, move |msg| {
            TSSH::sync_dispatch::<BsonHandler<ProxyData>>(msg, true);
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_CLOSE, move |msg| {
            TSSH::dispatch::<BsonHandler<ProxyClose>>(msg, false);
        });
}

impl Handler for BsonHandler<ProxyNew> {
    async fn process(self) {
        let req = &self.request;
        let proxy_id = req.data.proxy_id.clone();
        let addr = format!("{}:{}", req.data.ip, req.data.port);
        let id = self.id();
        info!("=>proxy_new `{proxy_id}`, channel `{id}`, addr `{addr}`",);

        let session_id = req.session_id.clone();
        let channel_id = match self.channel.as_ref() {
            Some(ch) if ch.plugin.try_get_proxy().is_some() => {
                error!("duplicate proxy_new `{proxy_id}`");
                let e = "proxy already start";
                return self.reply(PtyBinErrMsg::new(e)).await;
            }
            // Compatible with legacy front-end code
            // If no channel_id is provided, use proxy_id as channel_id.
            _ if req.channel_id.is_empty() => proxy_id.clone(),
            Some(_) => {
                error!("channel `{}` already start", id);
                let e = "channel already start";
                return self.reply(PtyBinErrMsg::new(e)).await;
            }
            None => req.channel_id.clone(),
        };

        let stream = match TcpStream::connect(&addr).await {
            Ok(s) => Mutex::new(s),
            Err(e) => {
                info!("proxy `{proxy_id}` connect failed: {e}");
                return self.reply(PtyBinErrMsg::new(e)).await;
            }
        };
        let (tx, rx) = unbounded_channel();
        let proxy = Proxy {
            proxy_id: proxy_id.clone(),
            stream,
            rx: Mutex::new(rx),
            tx,
        };
        let plugin = Plugin {
            component: PluginComp::Proxy(proxy),
            data: req.into(),
            controller: PluginCtrl::new(PROXY_REMOVE_INTERVAL),
        };
        let channel = Arc::new(Channel::new(&session_id, &channel_id, plugin));
        let session = match TSSH::get_session(&session_id).await {
            Some(s) => s,
            None => {
                let s = Arc::new(Session::new(&session_id));
                let _ = TSSH::add_session(&session_id, s.clone()).await;
                s
            }
        };

        if let Err(e) = session.add_channel(&channel_id, channel).await {
            return self.reply(PtyBinErrMsg::new(e)).await;
        }

        let data = PtyBinBase {
            session_id,
            channel_id,
            custom_data: "".to_owned(),
            data: ProxyReady { proxy_id },
        };
        TSSH::reply_bson_msg(WS_MSG_TYPE_PTY_PROXY_READY, data).await
    }
}

impl Handler for BsonHandler<ProxyData> {
    async fn process(self) {
        let req = self.request;
        let proxy_id = req.data.proxy_id.clone();
        // info!("=>proxy_data `{}`, channel `{}`", proxy_id, self.id());

        let mut ch = self.channel.unwrap().clone();
        // Compatible with legacy front-end code
        // If no channel_id is provided, use proxy_id as channel_id.
        if req.channel_id.is_empty() {
            if let Some(session) = TSSH::get_session(&req.session_id).await {
                if let Some(channel) = session.get_channel(&proxy_id).await {
                    ch = channel.clone();
                }
            }
        }
        let Some(proxy) = ch.plugin.try_get_proxy() else {
            return error!("proxy `{}` not found", proxy_id);
        };

        let _ = proxy
            .tx
            .send(req.data.data)
            .inspect_err(|err| error!("proxy_data `{}` send failed: {}", proxy_id, err));
    }
}

impl Handler for BsonHandler<ProxyClose> {
    async fn process(self) {
        let req = &self.request;
        let proxy_id = &req.data.proxy_id;
        info!("=>proxy_closed `{}`, channel `{}`", proxy_id, self.id());
        let Some(session) = TSSH::get_session(&req.session_id).await else {
            return;
        };
        if req.channel_id.is_empty() {
            // Compatible with legacy front-end code
            // If no channel_id is provided, use proxy_id as channel_id.
            session.remove_channel(proxy_id).await;
        } else if self.channel.is_some() {
            session.remove_channel(&req.channel_id).await;
        }
    }
}

pub struct Proxy {
    pub proxy_id: String,
    stream: Mutex<TcpStream>,
    rx: Mutex<UnboundedReceiver<Vec<u8>>>,
    tx: UnboundedSender<Vec<u8>>,
}

impl Proxy {
    pub async fn process(&self, id: &str, data: &PluginData, ctrl: &PluginCtrl) {
        let mut buffer = [0u8; PROXY_BUF_SIZE];
        let mut size = 0;
        let mut count = 0;
        let mut stopper_rx = ctrl.stopper.get_receiver().await.unwrap();
        let mut stream = self.stream.lock().await;
        let (mut reader, mut writer) = stream.split();
        let mut proxy_rx = self.rx.lock().await;
        let mut last_reply = Instant::now();

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
                        self.post(WS_MSG_TYPE_PTY_PROXY_DATA, data, msg_data).await;
                        last_reply = Instant::now();
                        size += i;
                        count += 1;
                    }
                    Err(e) => break error!("Proxy `{}` read failed: {}", id, e),
                },
                recv = proxy_rx.recv() => if let Some(v) = recv {
                    let _ = writer
                        .write_all(&v)
                        .await
                        .inspect_err(|err| error!("Proxy `{}` write failed: {}", id, err));
                },
                _ = &mut stopper_rx => break info!("Proxy `{}` stopped", id),
                _ = ctrl.timer.timeout() => if ctrl.timer.is_timeout_refresh(last_reply).await {
                    break info!("Proxy `{}` timeout", id);
                },
            };
        }

        let msg_data = ProxyClose {
            proxy_id: self.proxy_id.clone(),
        };
        self.post(WS_MSG_TYPE_PTY_PROXY_CLOSE, data, msg_data).await;
        info!("Proxy `{}` send total size: {}, count: {}", id, size, count);
    }

    async fn post<T: Serialize>(&self, msg_type: &str, ids: &PluginData, data: T) {
        let data = PtyBinBase {
            session_id: ids.session_id.clone(),
            channel_id: ids.channel_id.clone(),
            custom_data: "".to_owned(),
            data,
        };
        TSSH::reply_bson_msg(msg_type, data).await
    }
}
