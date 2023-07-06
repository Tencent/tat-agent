use crate::common::evbus::EventBus;
use crate::common::Opts;
use crate::network::build_extra_headers;
use crate::network::types::ws_msg::WsMsg;
use crate::network::urls::get_ws_url;

use std::borrow::Cow;
use std::cmp::min;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{thread, time};

use bson::Document;
use log::{error, info};
use serde_json::{self, Value};

use futures::channel::mpsc::{unbounded, UnboundedSender};
use futures::prelude::*;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::time::interval;
use tokio_stream::wrappers::IntervalStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::Error;
use tokio_tungstenite::tungstenite::protocol::frame::{coding::CloseCode, CloseFrame};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use crate::conpty::{WS_BIN_MSG, WS_TXT_MSG};
use crate::network::types::ws_msg::{WS_MSG_TYPE_CHECK_UPDATE, WS_MSG_TYPE_KICK};
const WS_MSG_TYPE_ACK: &str = "ack";
const WS_PASSIVE_CLOSE: &str = "cli_passive_close";
const WS_ACTIVE_CLOSE: &str = "cli_active_close";
const MAX_PING_FROM_LAST_PONG: usize = 3;
const WS_RECONNECT_INTERVAL_BASE: u64 = 3;
const WS_RECONNECT_RANDOM_MAX: u64 = 512;
const WS_RECONNECT_RANDOM_MIN: u64 = 4;
const WS_RECONNECT_RANDOM_TIMES: u64 = 4;
const ONTIME_PING_INTERVAL: u64 = 2 * 60;

#[derive(Clone)]
struct WsContext {
    msg_sender: Arc<RwLock<Option<UnboundedSender<Message>>>>,
    event_bus: Arc<EventBus>,
    ping_cnt_from_last_pong: Arc<AtomicUsize>,
    close_sent: Arc<AtomicBool>,
}

pub fn run(dispatcher: &Arc<EventBus>) {
    let context = WsContext::new(&dispatcher);
    if Opts::get_opts().server_mode {
        context.work_as_server();
    } else {
        context.work_as_client();
    }
}

impl WsContext {
    pub fn new(event_bus: &Arc<EventBus>) -> Self {
        let context = WsContext {
            msg_sender: Arc::new(RwLock::new(None)),
            ping_cnt_from_last_pong: Arc::new(AtomicUsize::new(0)),
            close_sent: Arc::new(AtomicBool::new(false)),
            event_bus: event_bus.clone(),
        };
        //pty message to server
        let wsctx_0 = context.clone();
        event_bus.register(WS_TXT_MSG, move |data: Vec<u8>| {
            let data = String::from_utf8_lossy(&data).to_string();
            if let Some(sender) = wsctx_0.msg_sender.read().unwrap().as_ref() {
                sender.unbounded_send(Message::Text(data)).ok();
            }
        });

        let wsctx_1 = context.clone();
        event_bus.register(WS_BIN_MSG, move |data: Vec<u8>| {
            if let Some(sender) = wsctx_1.msg_sender.read().unwrap().as_ref() {
                sender.unbounded_send(Message::Binary(data)).ok();
            }
        });
        return context;
    }

    fn work_as_client(&self) {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("ws tokio runtime build failed");
        let mut random_range = WS_RECONNECT_RANDOM_MIN;

        loop {
            info!("start ws connection...");
            self.close_sent.store(false, Ordering::SeqCst);
            self.ping_cnt_from_last_pong.store(0, Ordering::SeqCst);

            let mut req = get_ws_url()
                .into_client_request()
                .expect("Url to request failed");
            req.headers_mut().extend(build_extra_headers());
            let ws_stream = connect_async(req).map_err(|e| {
                error!("ws connect failed: {:?}", e);
                e
            });

            let runner = ws_stream
                .and_then(|(duplex, _)| {
                    info!("ws connection established");
                    random_range = WS_RECONNECT_RANDOM_MIN;

                    // check unfinished task on ws connected
                    self.event_bus
                        .dispatch(WS_MSG_TYPE_KICK, "start".to_string().into_bytes());

                    let (sink, stream) = duplex.split();
                    let (msg_sender, msg_receiver) = unbounded::<Message>();
                    self.msg_sender.write().unwrap().replace(msg_sender);

                    let msg_stream = stream
                        .filter_map(|res| async move { res.ok() })
                        .filter_map(|msg| async move { self.handle_server_msg(msg) });
                    let select_stream = stream::select(msg_receiver, self.make_ping_check());
                    stream::select(msg_stream, select_stream)
                        .map(|msg| Ok(msg))
                        .forward(sink)
                        .map_err(|e| {
                            error!("ws connection ended with an error: {:?}", e);
                            e
                        })
                })
                .map(|_| info!("ws connection finished"));

            let _ = runtime.block_on(runner);
            self.msg_sender.write().unwrap().take();

            // round 1: wait(WS_RECONNECT_INTERVAL_BASE + random(0, BASE + MIN))
            // ...
            // round n: wait(WS_RECONNECT_INTERVAL_BASE + random(0, min(BASE + MIN*4^n, MAX)))
            let wait_time = WS_RECONNECT_INTERVAL_BASE + rand::random::<u64>() % random_range;
            thread::sleep(time::Duration::from_secs(wait_time));
            random_range = min(
                random_range * WS_RECONNECT_RANDOM_TIMES,
                WS_RECONNECT_RANDOM_MAX,
            );
        }
    }

    fn handle_server_msg(&self, msg: Message) -> Option<Message> {
        //info!("ws recv msg: {:?}", msg);
        match msg {
            Message::Ping(data) => Some(Message::Pong(data)),
            Message::Pong(_) => {
                self.ping_cnt_from_last_pong.store(0, Ordering::SeqCst);
                None
            }
            Message::Text(msg) => self.handle_ws_text_msg(msg),
            Message::Binary(msg) => self.handle_ws_bin_msg(msg),
            Message::Close(_) => {
                self.close_sent.store(true, Ordering::SeqCst);
                Some(Message::Close(Some(CloseFrame {
                    code: CloseCode::Away,
                    reason: Cow::from(WS_PASSIVE_CLOSE),
                })))
            }
            Message::Frame(_) => None,
        }
    }

    fn handle_ws_text_msg(&self, msg: String) -> Option<Message> {
        let msg_json: Value = serde_json::from_str(msg.as_str()).ok()?;
        let msg_type = msg_json.get("Type")?.as_str()?;
        match msg_type {
            WS_MSG_TYPE_KICK => self.handle_kick_msg(),
            WS_MSG_TYPE_CHECK_UPDATE => self.handle_check_update_msg(),
            _ => {
                self.event_bus.dispatch(msg_type, msg.into_bytes());
                None
            }
        };
        None
    }

    fn handle_ws_bin_msg(&self, msg: Vec<u8>) -> Option<Message> {
        if let Ok(doc) = Document::from_reader(&mut Cursor::new(&msg[..])) {
            if let Ok(msg_type) = doc.get_str("Type") {
                self.event_bus.dispatch(msg_type, msg)
            };
        }
        None
    }

    fn handle_kick_msg(&self) -> Option<Message> {
        info!("kick_sender sent to notify fetch task, kick_source ws");
        self.event_bus
            .dispatch(WS_MSG_TYPE_KICK, "ws".to_string().into_bytes());

        let ack_msg = WsMsg::<String> {
            r#type: WS_MSG_TYPE_ACK.to_string(),
            seq: 0,
            data: None,
        };

        let ret = serde_json::to_string(&ack_msg);
        match ret {
            Ok(ws_rsp) => Some(Message::Text(ws_rsp)),
            Err(e) => {
                error!("ws rsp json encode failed: {:?}", e);
                None
            }
        }
    }

    fn handle_check_update_msg(&self) -> Option<Message> {
        info!("kick_sender sent to notify check update, kick_source ws");
        self.event_bus
            .dispatch(WS_MSG_TYPE_CHECK_UPDATE, "ws".to_string().into_bytes());

        let ack_msg = WsMsg::<String> {
            r#type: WS_MSG_TYPE_ACK.to_string(),
            seq: 0,
            data: None,
        };

        let ret = serde_json::to_string(&ack_msg);
        match ret {
            Ok(ws_rsp) => Some(Message::Text(ws_rsp)),
            Err(e) => {
                error!("ws rsp json encode failed: {:?}", e);
                None
            }
        }
    }

    fn make_ping_check(&self) -> impl Stream<Item = Message> {
        let self_0 = Arc::new(self.clone());
        let self_1 = Arc::new(self.clone());
        let count = Arc::new(AtomicU64::new(0));

        IntervalStream::new(interval(Duration::from_secs(1)))
            .then(move |_| {
                let self_ = self_0.clone();
                async move {
                    if self_.close_sent.load(Ordering::SeqCst) {
                        error!("ping_check close_sent is true");
                        return Err(Error::ConnectionClosed);
                    }
                    Ok(())
                }
            })
            .filter(move |_| {
                let old = count.clone().fetch_add(1, Ordering::SeqCst);
                async move { old % ONTIME_PING_INTERVAL == 0 }
            })
            .and_then(move |_| {
                let self_ = self_1.clone();
                async move {
                    let cnt = self_.ping_cnt_from_last_pong.fetch_add(1, Ordering::SeqCst);
                    if cnt >= MAX_PING_FROM_LAST_PONG {
                        error!("ping_check error: cnt >= MAX_PING_FROM_LAST_PONG");
                        self_.close_sent.store(true, Ordering::SeqCst);
                        Ok(Message::Close(Some(CloseFrame {
                            code: CloseCode::Normal,
                            reason: Cow::from(WS_ACTIVE_CLOSE),
                        })))
                    } else {
                        Ok(Message::Ping(Vec::new()))
                    }
                }
            })
            .filter_map(|res| async move { res.ok() })
    }

    fn work_as_server(&self) {
        info!("work as server");
        let runtime = Builder::new_current_thread().build().unwrap();
        let _ = async move {
            let listener = TcpListener::bind("0.0.0.0:3333")
                .await
                .expect("bind failed");
            let fut = listener.accept().and_then(|(tcp_stream, addr)| async move {
                let ws_stream = accept_async(tcp_stream)
                    .await
                    .expect("Error during the websocket handshake occurred");
                info!("get a connection from: {}", addr);
                let (sink, stream) = ws_stream.split();
                let (msg_sender, msg_receiver) = unbounded::<Message>();
                let self_ = Arc::new(self.clone());
                self_
                    .msg_sender
                    .write()
                    .expect("get sender lock failed")
                    .replace(msg_sender);
                let msg_stream =
                    stream
                        .filter_map(|res| async move { res.ok() })
                        .filter_map(move |msg| {
                            let self_ = self_.clone();
                            async move { self_.clone().handle_server_msg(msg) }
                        });
                let fut = stream::select(msg_stream, msg_receiver)
                    .map(|msg| Ok(msg))
                    .forward(sink)
                    .map_err(move |e| println!("{}: '{:?}'", addr, e))
                    .map(move |_| println!("{} closed.", addr));
                tokio::spawn(fut);
                Ok(())
            });
            let _ = runtime.block_on(fut);
        };
    }
}

// handle the message from WebSocket server
#[cfg(test)]
mod tests {
    // use super::*;
    use crate::common::logger::init_test_log;
    use crate::network::{build_extra_headers, mock_enabled};
    use log::info;

    #[test]
    fn _test_ws_cus_header() {
        init_test_log();
        let header = build_extra_headers();
        if mock_enabled() {
            assert_eq!(4, header.len());
        } else {
            assert_eq!(2, header.len());
        }

        info!("header: {:?}", header);
    }
}
