use super::{build_extra_headers, urls::get_ws_url};
use crate::common::evbus;

use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bson::Document;
use futures::{Stream, StreamExt, stream_select};
use log::{error, info, warn};
use rand::{Rng, thread_rng};
use serde_json::Value;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::time::{interval, sleep};
use tokio_stream::wrappers::{IntervalStream, UnboundedReceiverStream};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::tungstenite::Message::{self, *};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
use tokio_tungstenite::tungstenite::{Bytes, Utf8Bytes};

use super::types::ws_msg::{ConnectForwardData, MsgBase};
use super::types::ws_msg::{EVENT_CHECK_UPDATE, EVENT_FORCE_RESTART, EVENT_KICK};
use super::urls::get_forward_url;
use crate::tssh::{WS_BIN_MSG, WS_TXT_MSG};

const EVENT_CONNECT_FORWARD: &str = "ConnectForward";
const WS_PASSIVE_CLOSE: &str = "cli_passive_close";
const WS_ACTIVE_CLOSE: &str = "cli_active_close";
const MAX_PING_FROM_LAST_PONG: usize = 3;
const BASE_DELAY: u64 = 8;
const MIN_DELAY: u64 = 3;
const MAX_DELAY: u64 = 512;
const SOURCE_START: &str = "start";
pub const SOURCE_WS: &str = "ws";

type WsRes = Result<Message, Error>;

async fn exponential_backoff_with_jitter(retry_count: u32) {
    let exponent = min(retry_count, MAX_DELAY.ilog2()); // avoid overflow
    let exponential_max = BASE_DELAY * 2u64.pow(exponent);
    let max_delay = min(exponential_max, MAX_DELAY);
    let jitter = thread_rng().gen_range(MIN_DELAY..max_delay);
    info!("Retrying in {} seconds...", jitter);
    sleep(Duration::from_secs(jitter)).await;
}

pub async fn run() {
    ForwardWs::start();

    let mut retry_count = 0u32;
    loop {
        match NotifyWs::run_client().await {
            Ok(_) => retry_count = 0,
            Err(_) => retry_count += 1,
        };
        exponential_backoff_with_jitter(retry_count).await;
    }
}

struct NotifyWs {
    ping_cnt_from_last_pong: AtomicUsize,
    close_sent: AtomicBool,
}

impl NotifyWs {
    fn new() -> Self {
        Self {
            ping_cnt_from_last_pong: AtomicUsize::new(0),
            close_sent: AtomicBool::new(false),
        }
    }

    pub async fn run_client() -> Result<(), Error> {
        info!("ws: start connection...");
        let ctx = NotifyWs::new();
        let mut req = get_ws_url(None)
            .await
            .into_client_request()
            .expect("ws: gen request failed");
        req.headers_mut().extend(build_extra_headers().await);
        let (ws_stream, _) = connect_async(req)
            .await
            .inspect_err(|e| error!("ws: connect failed, {e:#}"))?;
        info!("ws: connection established");
        let (sink, stream) = ws_stream.split();

        tokio::spawn(async {
            sleep(Duration::from_secs(2)).await;
            evbus::emit(EVENT_KICK, Vec::from(SOURCE_START)).await;
        });

        let select = stream_select!(
            ctx.ping_check().boxed(),
            stream.filter_map(|msg| async { ctx.on(msg).await }).boxed(),
        );
        let _ = select
            .forward(sink)
            .await
            .inspect_err(|e| error!("ws: connection ended with error: {e:#}"));
        Ok(())
    }

    async fn on(&self, msg: WsRes) -> Option<WsRes> {
        let msg = msg
            .inspect_err(|e| error!("ws: receive error, {e:#}"))
            .ok()?;

        match &msg {
            Text(msg) => self.on_text(msg).await,
            Binary(msg) => self.on_binary(msg).await,
            Pong(_) => self.ping_cnt_from_last_pong.store(0, Ordering::Relaxed),
            Close(_) => self.close_sent.store(true, Ordering::Relaxed),
            _ => (),
        }

        match msg {
            Ping(v) => Some(Ok(Pong(v))),
            Close(_) => Some(Ok(Close(Some(CloseFrame {
                reason: WS_PASSIVE_CLOSE.into(),
                code: CloseCode::Normal,
            })))),
            _ => None,
        }
    }

    async fn on_text(&self, msg: &str) {
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
            EVENT_CONNECT_FORWARD => {
                let session_id = json
                    .get("Data")
                    .and_then(|v| v.get("SessionId"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                info!("ws: receive `{msg_type}`, session_id: `{session_id}`");
                Vec::from(session_id)
            }
            _ => Vec::from(msg),
        };
        evbus::emit(msg_type, vec).await;
    }

    async fn on_binary(&self, msg: &[u8]) {
        let Ok(bson) = Document::from_reader(msg) else {
            return;
        };
        let Ok(msg_type) = bson.get_str("Type") else {
            return;
        };
        evbus::emit(msg_type, msg.to_vec()).await;
    }

    fn ping_check(&self) -> impl Stream<Item = WsRes> + '_ {
        const INTERVAL_SECS: u64 = 2 * 60;

        let first_delay = thread_rng().gen_range(0..(INTERVAL_SECS - 1));
        let mut interval = interval(Duration::from_secs(INTERVAL_SECS));
        interval.reset_after(Duration::from_secs(first_delay));
        IntervalStream::new(interval).map(move |_| {
            if self.close_sent.load(Ordering::Relaxed) {
                return Err(Error::ConnectionClosed);
            }
            let cnt = self.ping_cnt_from_last_pong.fetch_add(1, Ordering::Relaxed);
            if cnt >= MAX_PING_FROM_LAST_PONG {
                error!("ws: ping_check error, max ping count reached since last pong");
                self.close_sent.store(true, Ordering::Relaxed);
                return Ok(Close(Some(CloseFrame {
                    reason: WS_ACTIVE_CLOSE.into(),
                    code: CloseCode::Away,
                })));
            }
            Ok(Ping(Bytes::new()))
        })
    }
}

struct ForwardWs;

impl ForwardWs {
    pub fn start() {
        tokio::spawn(async {
            let (event_tx, mut event_rx) = unbounded_channel::<String>();

            evbus::subscribe(EVENT_CONNECT_FORWARD, move |msg: Vec<u8>| {
                let session_id = String::from_utf8_lossy(&msg).to_string();
                let _ = event_tx.send(session_id);
            })
            .await;

            let mut cmd_tx: Option<UnboundedSender<String>> = None;

            while let Some(session_id) = event_rx.recv().await {
                let alive = cmd_tx.as_ref().map(|tx| !tx.is_closed()).unwrap_or(false);
                if alive {
                    if let Some(tx) = cmd_tx.as_ref()
                        && tx.send(session_id.clone()).is_ok()
                    {
                        info!("forward: reuse connection, session_id: {session_id}");
                        continue;
                    }
                } else if cmd_tx.is_some() {
                    warn!("forward: previous connection is dead, reconnecting");
                }

                let (tx, rx) = unbounded_channel::<String>();
                let _ = tx.send(session_id);
                cmd_tx = Some(tx);

                tokio::spawn(async move {
                    if let Err(e) = Self::run(rx).await {
                        warn!("forward: connection ended: {e:#}");
                    }
                    info!("forward: connection exited, next ConnectForward will reconnect");
                });
            }
        });
    }

    async fn run(cmd_rx: tokio::sync::mpsc::UnboundedReceiver<String>) -> Result<(), Error> {
        info!("forward: connecting to forward service");

        let mut req = get_forward_url(None).await.into_client_request()?;
        req.headers_mut().extend(build_extra_headers().await);
        let (ws_stream, _) = connect_async(req).await?;
        info!("forward: connection established");
        let (sink, stream) = ws_stream.split();

        let command_stream = Self::command_stream(cmd_rx);
        let outbound_stream = Self::subscribe_outbound().await;
        let inbound_stream = Self::handle_inbound(stream);
        let ping_stream =
            IntervalStream::new(interval(Duration::from_secs(60))).map(|_| Ok(Ping(Bytes::new())));

        let merged = stream_select!(
            command_stream.boxed(),
            outbound_stream.boxed(),
            inbound_stream.boxed(),
            ping_stream.boxed(),
        );
        merged.forward(sink).await
    }

    fn command_stream(
        cmd_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> impl Stream<Item = WsRes> {
        UnboundedReceiverStream::new(cmd_rx).filter_map(|session_id| async move {
            let msg = MsgBase {
                r#type: EVENT_CONNECT_FORWARD.to_string(),
                seq: 1,
                data: ConnectForwardData {
                    session_id: session_id.clone(),
                },
            };
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    info!("forward: send ConnectForward, session_id: {session_id}");
                    Some(Ok(Text(Utf8Bytes::from(json))))
                }
                Err(e) => {
                    warn!("forward: serialize ConnectForward failed: {e:#}");
                    None
                }
            }
        })
    }

    async fn subscribe_outbound() -> impl Stream<Item = WsRes> {
        let (tx, rx) = unbounded_channel::<WsRes>();

        evbus::subscribe(WS_TXT_MSG, {
            let tx = tx.clone();
            move |data: Vec<u8>| {
                let _ = tx.send(Ok(Text(Utf8Bytes::try_from(data).unwrap_or_default())));
            }
        })
        .await;

        evbus::subscribe(WS_BIN_MSG, {
            let tx = tx.clone();
            move |data: Vec<u8>| {
                let _ = tx.send(Ok(Binary(Bytes::from_owner(data))));
            }
        })
        .await;

        UnboundedReceiverStream::new(rx)
    }

    fn handle_inbound(
        stream: impl Stream<Item = Result<Message, Error>>,
    ) -> impl Stream<Item = WsRes> {
        stream.filter_map(|msg| async {
            let msg = match msg {
                Ok(msg) => msg,
                Err(e) => {
                    warn!("forward: recv error: {e:#}");
                    return Some(Err(e));
                }
            };

            // first: parse msg_type and emit, same as NotifyWs::on_text/on_binary
            match &msg {
                Text(t) => {
                    if let Ok(json) = serde_json::from_str::<Value>(t.as_str())
                        && let Some(msg_type) = json.get("Type").and_then(Value::as_str)
                    {
                        evbus::emit(msg_type, t.as_bytes().to_vec()).await;
                    }
                }
                Binary(b) => {
                    if let Ok(bson) = Document::from_reader(b.as_ref())
                        && let Ok(msg_type) = bson.get_str("Type")
                    {
                        evbus::emit(msg_type, b.to_vec()).await;
                    }
                }
                _ => (),
            }

            match msg {
                Ping(v) => Some(Ok(Pong(v))),
                Close(_) => Some(Err(Error::ConnectionClosed)),
                _ => None,
            }
        })
    }
}
