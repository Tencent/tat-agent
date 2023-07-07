use std::cmp::min;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{thread, time};

use bson::Document;
use futures01::future::Future;
use futures01::sync::mpsc::{self, UnboundedSender};
use futures01::Stream;

use log::{debug, error, info};
use once_cell::sync::OnceCell;
use serde_json::{self, Value};
use tokio01::runtime::current_thread::Runtime;
use tokio01::timer::Interval;
use websocket::header::Headers;
use websocket::r#async::Server;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, CloseData, OwnedMessage};
 
use crate::common::evbus::EventBus;
use crate::common::Opts;
use crate::network::build_extra_headers;
use crate::network::types::ws_msg::WsMsg;
use crate::network::urls::get_ws_url;


use crate::conpty::{WS_BIN_MSG, WS_TXT_MSG};
use crate::network::types::ws_msg::{WS_MSG_TYPE_CHECK_UPDATE, WS_MSG_TYPE_KICK};
const WS_MSG_TYPE_ACK: &str = "ack";
const WS_PASSIVE_CLOSE: &str = "cli_passive_close";
const WS_PASSIVE_CLOSE_CODE: u16 = 3001;
const WS_ACTIVE_CLOSE: &str = "cli_active_close";
const WS_ACTIVE_CLOSE_CODE: u16 = 3002;
const MAX_PING_FROM_LAST_PONG: usize = 3;
const WS_RECONNECT_INTERVAL_BASE: u64 = 3;
const WS_RECONNECT_RANDOM_MAX: u64 = 512;
const WS_RECONNECT_RANDOM_MIN: u64 = 4;
const WS_RECONNECT_RANDOM_TIMES: u64 = 4;
const ONTIME_PING_INTERVAL: u64 = 2 * 60;

#[derive(Clone)]
struct WsContext {
    msg_sender: Arc<RwLock<Option<UnboundedSender<OwnedMessage>>>>,
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
                sender.unbounded_send(OwnedMessage::Text(data)).ok();
            }
        });

        let wsctx_1 = context.clone();
        event_bus.register(WS_BIN_MSG, move |data: Vec<u8>| {
            if let Some(sender) = wsctx_1.msg_sender.read().unwrap().as_ref() {
                sender.unbounded_send(OwnedMessage::Binary(data)).ok();
            }
        });
        return context;
    }

    fn work_as_client(&self) {
        let mut runtime = Runtime::new().expect("ws tokio runtime build fail");
        let mut random_range = WS_RECONNECT_RANDOM_MIN;

        loop {
            info!("start ws connection...");
            let header = gen_ver_header();
            self.close_sent.store(false, Ordering::SeqCst);
            self.ping_cnt_from_last_pong.store(0, Ordering::SeqCst);

            let ws_stream = ClientBuilder::new(&get_ws_url())
                .expect("ws cli builder fail")
                .custom_headers(&header)
                .async_connect(None);

            let runner = ws_stream
                .map_err(|e| {
                    error!("ws connect fail:{:?}", e);
                    e
                })
                .and_then(|(duplex, _)| {
                    info!("ws connection established");
                    random_range = WS_RECONNECT_RANDOM_MIN;
                    //dispatch kick msg on ws connected
                    self.event_bus
                        .dispatch(WS_MSG_TYPE_KICK, "ws".to_string().into_bytes());

                    let (msg_sender, msg_receiver) = mpsc::unbounded::<OwnedMessage>();
                    self.msg_sender.write().unwrap().replace(msg_sender);

                    let (sink, stream) = duplex.split();
                    stream
                        .filter_map(|msg| self.handle_server_msg(msg))
                        .select(msg_receiver.map_err(|_| WebSocketError::NoDataAvailable))
                        .select(self.make_ping_check())
                        .forward(sink)
                        .map_err(|e| {
                            error!("ws connection ended with an error:{:?}", e);
                            e
                        })
                })
                .map(|_| {
                    info!("ws connection finished");
                });

            let _ = runtime.block_on(runner);
            self.msg_sender.write().unwrap().take();

            /*round 1: wait(WS_RECONNECT_INTERVAL_BASE + random(0,BASE + MIN))
              ...
            round n: wait(WS_RECONNECT_INTERVAL_BASE + random(0,max(BASE + MIN*4^n,MAX)))
            */
            let wait_time = WS_RECONNECT_INTERVAL_BASE + rand::random::<u64>() % random_range;
            thread::sleep(time::Duration::from_secs(wait_time));
            random_range = min(
                random_range * WS_RECONNECT_RANDOM_TIMES,
                WS_RECONNECT_RANDOM_MAX,
            );
        }
    }

    fn handle_server_msg(&self, msg: OwnedMessage) -> Option<OwnedMessage> {
        //info!("ws recv msg: {:?}", msg);
        match msg {
            OwnedMessage::Ping(data) => Some(OwnedMessage::Pong(data)),
            OwnedMessage::Pong(_) => {
                self.ping_cnt_from_last_pong.store(0, Ordering::SeqCst);
                None
            }
            OwnedMessage::Text(msg) => self.handle_ws_text_msg(msg),
            OwnedMessage::Binary(msg) => self.handle_ws_bin_msg(msg),
            OwnedMessage::Close(_) => {
                self.close_sent.store(true, Ordering::SeqCst);
                Some(OwnedMessage::Close(Some(CloseData {
                    status_code: WS_PASSIVE_CLOSE_CODE,
                    reason: WS_PASSIVE_CLOSE.to_string(),
                })))
            }
        }
    }

    fn handle_ws_text_msg(&self, msg: String) -> Option<OwnedMessage> {
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

    fn handle_ws_bin_msg(&self, msg: Vec<u8>) -> Option<OwnedMessage> {
        if let Ok(doc) = Document::from_reader(&mut Cursor::new(&msg[..])) {
            if let Ok(msg_type) = doc.get_str("Type") {
                self.event_bus.dispatch(msg_type, msg)
            };
        }
        None
    }

    fn handle_kick_msg(&self) -> Option<OwnedMessage> {
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
            Ok(ws_rsp) => Some(OwnedMessage::Text(ws_rsp)),
            Err(e) => {
                error!("ws rsp json encode fail:{:?}", e);
                None
            }
        }
    }

    fn handle_check_update_msg(&self) -> Option<OwnedMessage> {
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
            Ok(ws_rsp) => Some(OwnedMessage::Text(ws_rsp)),
            Err(e) => {
                error!("ws rsp json encode fail:{:?}", e);
                None
            }
        }
    }

    fn make_ping_check(&self) -> Box<dyn Stream<Item = OwnedMessage, Error = WebSocketError>> {
        let self_0 = self.clone();
        let self_1 = self.clone();
        let count = Arc::new(AtomicU64::new(0));
        let stream = Interval::new_interval(Duration::from_secs(1))
            .then(move |_| {
                if self_0.close_sent.load(Ordering::SeqCst) {
                    error!("ping_check close_sent is true");
                    return Err(WebSocketError::NoDataAvailable);
                }
                Ok(())
            })
            .filter(move |_| {
                let old = count.fetch_add(1, Ordering::SeqCst);
                old % ONTIME_PING_INTERVAL == 0
            })
            .and_then(move |_| {
                let cnt = self_1
                    .ping_cnt_from_last_pong
                    .fetch_add(1, Ordering::SeqCst);
                if cnt >= MAX_PING_FROM_LAST_PONG {
                    error!("ping_check err, cnt >= MAX_PING_FROM_LAST_PONG");
                    self_1.close_sent.store(true, Ordering::SeqCst);
                    Ok(OwnedMessage::Close(Some(CloseData {
                        status_code: WS_ACTIVE_CLOSE_CODE,
                        reason: WS_ACTIVE_CLOSE.to_string(),
                    })))
                } else {
                    Ok(OwnedMessage::Ping("".to_string().into_bytes()))
                }
            });
        Box::new(stream)
    }

    fn work_as_server(&self) {
        info!("work as server");
        static SERVER_CONTEXT: OnceCell<Arc<WsContext>> = OnceCell::new();
        let _ = SERVER_CONTEXT.set(Arc::new(self.clone()));
        let mut runtime = tokio01::runtime::Builder::new().build().unwrap();

        let server =
            Server::bind("0.0.0.0:3333", &tokio01::reactor::Handle::default()).expect("bind fail");

        let f = server
            .incoming()
            .map_err(|err| {
                error!("incoming error {:?}", err);
                err
            })
            .for_each(move |(upgrade, addr)| {
                info!("get a connection from: {}", addr);
                let self_ = SERVER_CONTEXT.get().expect("get server").clone();
                let f = upgrade.accept().and_then(move |(s, _)| {
                    let (sink, stream) = s.split();
                    let (msg_sender, msg_receiver) = mpsc::unbounded::<OwnedMessage>();
                    self_
                        .msg_sender
                        .write()
                        .expect("get sender lock fail")
                        .replace(msg_sender);
                    let self_ = self_.clone();
                    stream
                        .filter_map(move |msg| self_.handle_server_msg(msg))
                        .select(msg_receiver.map_err(|_| WebSocketError::NoDataAvailable))
                        .forward(sink)
                });

                tokio01::spawn(
                    f.map_err(move |e| println!("{}: '{:?}'", addr, e))
                        .map(move |_| println!("{} closed.", addr)),
                );
                Ok(())
            });
        runtime.block_on(f).unwrap();
    }
}

fn gen_ver_header() -> Headers {
    let mut headers = Headers::new();
    let header_maps = build_extra_headers();
    for (opt_key, value) in header_maps.into_iter() {
        if let Some(key) = opt_key {
            headers.append_raw(key.to_string(), value.as_bytes().to_vec())
        }
    }

    debug!("ws header:{:?}", headers);
    headers
}

// handle the message from WebSocket server
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common::logger::init_test_log, network::mock_enabled};
    use log::info;

    #[test]
    fn _test_ws_cus_header() {
        init_test_log();
        let header = gen_ver_header();
        if mock_enabled() {
            assert_eq!(4, header.len());
        } else {
            assert_eq!(2, header.len());
        }

        info!("header:{:?}", header);
    }
}
