use super::{build_extra_headers, urls::get_ws_url};
use crate::common::{evbus::EventBus, Opts};

use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;

use bson::Document;
use futures::{stream_select, Stream, StreamExt};
use log::{error, info};
use rand::{thread_rng, Rng};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{interval, sleep};
use tokio_stream::wrappers::{IntervalStream, UnboundedReceiverStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::tungstenite::Message::{self, *};
use tokio_tungstenite::{accept_async, connect_async};

use super::{EVENT_CHECK_UPDATE, EVENT_FORCE_RESTART, EVENT_KICK};
use crate::tssh::{WS_BIN_MSG, WS_TXT_MSG};
const WS_PASSIVE_CLOSE: &str = "cli_passive_close";
const WS_ACTIVE_CLOSE: &str = "cli_active_close";
const MAX_PING_FROM_LAST_PONG: usize = 3;
const BASE_DELAY: u64 = 8;
const MIN_DELAY: u64 = 3;
const MAX_DELAY: u64 = 512;
const SOURCE_START: &str = "start";
pub const SOURCE_WS: &str = "ws";

type WsRes = Result<Message, Error>;

struct WsContext {
    receiver: Option<UnboundedReceiverStream<WsRes>>,
    event_bus: Arc<EventBus>,
    ping_cnt_from_last_pong: AtomicUsize,
    close_sent: AtomicBool,
}

pub async fn run(event_bus: &Arc<EventBus>) {
    if Opts::get_opts().server_mode {
        return work_as_server(&event_bus).await;
    }

    let mut retry_count = 0u32;
    loop {
        match work_as_client(event_bus.clone()).await {
            Ok(_) => retry_count = 0,
            Err(_) => retry_count += 1,
        };
        exponential_backoff_with_jitter(retry_count).await;
    }
}

async fn work_as_client(event_bus: Arc<EventBus>) -> Result<(), Error> {
    info!("ws: start connection...");
    let mut ctx = WsContext::new(event_bus.clone());
    let req = handshake_request().await.expect("ws: gen request failed");
    let (ws_stream, _) = connect_async(req)
        .await
        .inspect_err(|e| error!("ws: connect failed, {e:#}"))?;
    info!("ws: connection established");
    let (sink, stream) = ws_stream.split();

    tokio::spawn(async move {
        sleep(Duration::from_secs(2)).await; // avoid record not found
        event_bus.dispatch(EVENT_KICK, Vec::from(SOURCE_START));
    });

    let select = stream_select!(
        ctx.receiver.take().unwrap().boxed(),
        ctx.ping_check().boxed(),
        stream.filter_map(|m| async { ctx.handle_msg(m) }).boxed(),
    );
    let _ = select
        .forward(sink)
        .await
        .inspect_err(|e| error!("ws: connection ended with error: {e:#}"));
    Ok(())
}

async fn work_as_server(event_bus: &Arc<EventBus>) {
    info!("ws: work as server...");
    let listener = TcpListener::bind("0.0.0.0:3333")
        .await
        .expect("ws server: TcpListener::bind failed");

    while let Ok((tcp_stream, _)) = listener.accept().await {
        let mut ctx = WsContext::new(event_bus.clone());
        let (sink, stream) = match accept_async(tcp_stream).await {
            Ok(ws) => ws.split(),
            Err(e) => return error!("ws server: connect failed, {e:#}"),
        };
        let select = stream_select!(
            ctx.receiver.take().unwrap().boxed(),
            stream.filter_map(|m| async { ctx.handle_msg(m) }).boxed(),
        );
        let _ = select
            .forward(sink)
            .await
            .inspect_err(|e| error!("ws server: connection ended with error: {e:#}"));
    }
}

async fn exponential_backoff_with_jitter(retry_count: u32) {
    let exponential_max = BASE_DELAY * 2u64.pow(retry_count);
    let max_delay = min(exponential_max, MAX_DELAY);
    let jitter = thread_rng().gen_range(MIN_DELAY..max_delay);
    info!("Retrying in {} seconds...", jitter);
    sleep(Duration::from_secs(jitter)).await;
}

async fn handshake_request() -> Result<Request, Error> {
    let mut rq = get_ws_url().await.into_client_request()?;
    rq.headers_mut().extend(build_extra_headers().await);
    Ok(rq)
}

impl WsContext {
    fn new(event_bus: Arc<EventBus>) -> Self {
        let (tx, rx) = unbounded_channel::<WsRes>();
        //pty message to server
        event_bus.register(WS_TXT_MSG, {
            let tx = tx.clone();
            move |data| {
                let data = String::from_utf8_lossy(&data).to_string();
                let _ = tx.send(Ok(Text(data)));
            }
        });
        event_bus.register(WS_BIN_MSG, {
            let tx = tx.clone();
            move |data| {
                let _ = tx.send(Ok(Binary(data)));
            }
        });

        WsContext {
            receiver: Some(UnboundedReceiverStream::new(rx)),
            ping_cnt_from_last_pong: AtomicUsize::new(0),
            close_sent: AtomicBool::new(false),
            event_bus,
        }
    }

    fn handle_msg(&self, msg: WsRes) -> Option<WsRes> {
        let msg = msg
            .inspect_err(|e| error!("ws: receive error, {e:#}"))
            .ok()?;

        // handle
        match &msg {
            Text(msg) => self.on_text(msg),
            Binary(msg) => self.on_binary(msg),
            Pong(_) => self.ping_cnt_from_last_pong.store(0, SeqCst),
            Close(_) => self.close_sent.store(true, SeqCst),
            _ => (),
        }

        // response
        match msg {
            Ping(v) => Some(Pong(v)),
            Close(_) => Some(Close(Some(CloseFrame {
                reason: WS_PASSIVE_CLOSE.into(),
                code: CloseCode::Normal,
            }))),
            _ => None,
        }
        .map(|r| Ok(r))
    }

    fn on_text(&self, msg: &str) {
        let Ok(json) = serde_json::from_str::<Value>(msg) else {
            return;
        };
        let Some(Some(msg_type)) = json.get("Type").map(Value::as_str) else {
            return;
        };
        let vec = match msg_type {
            EVENT_KICK => {
                let id = json
                    .get("Data")
                    .and_then(|v| v.get("InvocationTaskID"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                info!("ws: receive `{msg_type}`, task_id: `{id}`");
                Vec::from(format!("{SOURCE_WS} ({id})"))
            }
            EVENT_CHECK_UPDATE | EVENT_FORCE_RESTART => {
                info!("ws: receive `{msg_type}`");
                Vec::from(SOURCE_WS)
            }
            _ => Vec::from(msg),
        };
        self.event_bus.dispatch(msg_type, vec);
    }

    fn on_binary(&self, msg: &[u8]) {
        let Ok(bson) = Document::from_reader(msg) else {
            return;
        };
        let Ok(msg_type) = bson.get_str("Type") else {
            return;
        };
        self.event_bus.dispatch(msg_type, msg.to_vec());
    }

    fn ping_check<'a>(&'a self) -> impl Stream<Item = WsRes> + 'a {
        IntervalStream::new(interval(Duration::from_secs(2 * 60))).map(move |_| {
            if self.close_sent.load(SeqCst) {
                return Err(Error::ConnectionClosed);
            }
            let cnt = self.ping_cnt_from_last_pong.fetch_add(1, SeqCst);
            if cnt >= MAX_PING_FROM_LAST_PONG {
                error!("ws: ping_check error, max ping count reached since last pong");
                self.close_sent.store(true, SeqCst);
                return Ok(Close(Some(CloseFrame {
                    reason: WS_ACTIVE_CLOSE.into(),
                    code: CloseCode::Away,
                })));
            }
            Ok(Ping(Vec::new()))
        })
    }
}
