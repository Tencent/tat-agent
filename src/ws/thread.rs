use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::{thread, time};

use futures01::future::Future;
use futures01::sync::mpsc::{self, UnboundedSender};
use futures01::Stream;
use log::{debug, error, info};
use serde_json;
use tokio01 as tokio;
use tokio01::timer::Interval;
use websocket::header::Headers;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, CloseData, OwnedMessage};

use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{
    AGENT_VERSION, MAX_PING_FROM_LAST_PONG, ONTIME_PING_INTERVAL, PTY_WS_MSG, VIP_HEADER,
    VPCID_HEADER, WS_ACTIVE_CLOSE, WS_ACTIVE_CLOSE_CODE, WS_KERNEL_NAME_HEADER, WS_MSG_TYPE_ACK,
    WS_MSG_TYPE_KICK, WS_PASSIVE_CLOSE, WS_PASSIVE_CLOSE_CODE, WS_RECONNECT_INTERVAL,
    WS_VERSION_HEADER, WS_MSG_TYPE_CHECK_UPDATE,
};
use crate::common::envs::get_ws_url;
use crate::common::evbus::EventBus;
use crate::common::{envs, Opts};
use crate::types::ws_msg::WsMsg;
use crate::uname::common::UnameExt;
use crate::uname::Uname;

#[derive(Clone)]
struct WsContext {
    msg_sender: Arc<RwLock<Option<UnboundedSender<OwnedMessage>>>>,
    dispatcher: Arc<EventBus>,
    ping_cnt_from_last_pong: Arc<AtomicUsize>,
    close_sent: Arc<AtomicBool>,
}

pub fn run(dispatcher: &Arc<EventBus>) {
    let context = WsContext::new(&dispatcher);
    if Opts::get_opts().pty_server {
        context.work_as_server();
    } else {
        context.work_as_client();
    }
}

impl WsContext {
    pub fn new(dispatcher: &Arc<EventBus>) -> Self {
        let context = WsContext {
            msg_sender: Arc::new(RwLock::new(None)),
            ping_cnt_from_last_pong: Arc::new(AtomicUsize::new(0)),
            close_sent: Arc::new(AtomicBool::new(false)),
            dispatcher: dispatcher.clone(),
        };
        //pty message to server
        let msg_context = context.clone();
        dispatcher.register(PTY_WS_MSG, move |data: String| {
            if let Some(sender) = msg_context.msg_sender.read().unwrap().as_ref() {
                sender.unbounded_send(OwnedMessage::Text(data)).ok();
            }
        });
        return context;
    }

    fn work_as_client(&self) {
        let header = gen_ver_header();

        let mut runtime = tokio::runtime::current_thread::Builder::new()
            .build()
            .unwrap_or_exit("ws tokio runtime build fail");

        loop {
            info!("start ws connection...");

            self.close_sent.store(false, Ordering::SeqCst);
            self.ping_cnt_from_last_pong.store(0, Ordering::SeqCst);

            let ws_stream = ClientBuilder::new(get_ws_url().as_str())
                .unwrap_or_exit("ws cli builder fail")
                .custom_headers(&header)
                .async_connect(None);

            let runner = ws_stream
                .map_err(|e| {
                    error!("ws connect fail:{:?}", e);
                    e
                })
                .and_then(|(duplex, _)| {
                    info!("ws connection established");

                    //dispatch kick msg on ws connected
                    self.dispatcher.dispatch(WS_MSG_TYPE_KICK, "ws".to_string());

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
            thread::sleep(time::Duration::from_secs(WS_RECONNECT_INTERVAL));
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
            OwnedMessage::Close(_) => {
                self.close_sent.store(true, Ordering::SeqCst);
                Some(OwnedMessage::Close(Some(CloseData {
                    status_code: WS_PASSIVE_CLOSE_CODE,
                    reason: WS_PASSIVE_CLOSE.to_string(),
                })))
            }
            _ => None,
        }
    }

    fn handle_ws_text_msg(&self, msg: String) -> Option<OwnedMessage> {
        let ret: Result<WsMsg, serde_json::Error> = serde_json::from_str(msg.as_str());
        match ret {
            Ok(ws_msg) => match ws_msg.r#type.as_str() {
                WS_MSG_TYPE_KICK => self.handle_kick_msg(ws_msg),
                WS_MSG_TYPE_CHECK_UPDATE => self.handle_check_update_msg(ws_msg),
                _ => {
                    if let Some(v) = ws_msg.data {
                        let data = v.to_string();
                        self.dispatcher.dispatch(&ws_msg.r#type, data);
                    }
                    None
                }
            },
            Err(e) => {
                error!("json parse fail, invalid ws text msg: {:?}", e);
                None
            }
        }
    }

    fn handle_kick_msg(&self, mut ws_msg: WsMsg) -> Option<OwnedMessage> {
        info!("kick_sender sent to notify fetch task, kick_source ws");
        self.dispatcher.dispatch(WS_MSG_TYPE_KICK, "ws".to_string());
        ws_msg.r#type = WS_MSG_TYPE_ACK.to_string();
        let ret = serde_json::to_string(&ws_msg);
        match ret {
            Ok(ws_rsp) => Some(OwnedMessage::Text(ws_rsp)),
            Err(e) => {
                error!("ws rsp json encode fail:{:?}", e);
                None
            }
        }
    }

    fn handle_check_update_msg(&self, mut ws_msg: WsMsg) -> Option<OwnedMessage> {
        info!("kick_sender sent to notify check update, kick_source ws");
        self.dispatcher.dispatch(WS_MSG_TYPE_CHECK_UPDATE, "ws".to_string());
        ws_msg.r#type = WS_MSG_TYPE_ACK.to_string();
        let ret = serde_json::to_string(&ws_msg);
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

    //just used for debug pty
    fn work_as_server(&self) {
        use websocket::sync::Server;
        let server = Server::bind("0.0.0.0:3333").unwrap();
        for request in server.filter_map(Result::ok) {
            let client = request.use_protocol("rust-websocket").accept().unwrap();
            let ip = client.peer_addr().unwrap();
            println!("Connection from {}", ip);

            let (mut receiver, sender) = client.split().unwrap();

            let sender = Arc::new(Mutex::new(sender));
            self.dispatcher.register(PTY_WS_MSG, move |data: String| {
                let message = OwnedMessage::Text(data);
                let _ = sender.lock().unwrap().send_message(&message);
            });

            for message in receiver.incoming_messages() {
                if message.is_err() {
                    println!("recv msg err {}", message.unwrap_err());
                    break;
                }
                let message = message.unwrap();
                self.handle_server_msg(message);
            }
        }
    }
}

fn gen_ver_header() -> Headers {
    let mut headers = Headers::new();
    headers.set_raw(WS_VERSION_HEADER, vec![AGENT_VERSION.as_bytes().to_vec()]);
    if envs::enable_test() {
        headers.set_raw(VPCID_HEADER, vec![envs::test_vpcid().as_bytes().to_vec()]);
        headers.set_raw(VIP_HEADER, vec![envs::test_vip().as_bytes().to_vec()]);
    }
    if let Ok(uname) = Uname::new() {
        headers.set_raw(WS_KERNEL_NAME_HEADER, vec![uname.sys_name().into_bytes()]);
    }
    debug!("ws header:{:?}", headers);
    headers
}

// handle the message from WebSocket server
#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::logger::init_test_log;
    use log::info;

    // #[test] unused
    fn _test_ws_cus_header() {
        init_test_log();
        let header = gen_ver_header();
        assert_eq!(2, header.len());
        info!("header:{:?}", header);
    }
}
