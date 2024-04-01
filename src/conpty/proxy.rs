use super::gather::PtyGather;
use super::handler::{BsonHandler, Handler};
use crate::common::{evbus::EventBus, utils::get_now_secs};
use crate::network::types::ws_msg::{ProxyClose, ProxyData, ProxyNew, ProxyReady, PtyBinBase};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use super::SLOT_PTY_BIN;
const WS_MSG_TYPE_PTY_PROXY_NEW: &str = "PtyProxyNew";
const WS_MSG_TYPE_PTY_PROXY_READY: &str = "PtyProxyReady";
const WS_MSG_TYPE_PTY_PROXY_DATA: &str = "PtyProxyData";
const WS_MSG_TYPE_PTY_PROXY_CLOSE: &str = "PtyProxyClose";

pub fn register_proxy_handlers(event_bus: &Arc<EventBus>) {
    event_bus
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_NEW, move |msg| {
            BsonHandler::<ProxyNew>::dispatch(msg);
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_DATA, move |msg| {
            BsonHandler::<ProxyData>::dispatch(msg);
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_CLOSE, move |msg| {
            BsonHandler::<ProxyClose>::dispatch(msg);
        });
}

impl Handler for BsonHandler<ProxyNew> {
    fn process(self) {
        let request = self.request.clone();
        info!("{} ProxyNew", request.data.proxy_id);
        PtyGather::runtime().spawn(async move {
            let dest = format!("127.0.0.1:{}", request.data.port);
            match TcpStream::connect(&dest).await {
                Ok(stream) => {
                    let (reader, writer) = stream.into_split();
                    let proxy = Arc::new(PtyProxy {
                        reader: Arc::new(Mutex::new(reader)),
                        writer: Arc::new(Mutex::new(writer)),
                        last_time: Arc::new(AtomicU64::new(get_now_secs())),
                        proxy_id: request.data.proxy_id.clone(),
                        session_id: request.session_id.clone(),
                        is_stopped: Arc::new(AtomicBool::new(false)),
                    });
                    PtyGather::add_proxy(&request.data.proxy_id, proxy.clone());
                    proxy.post(
                        WS_MSG_TYPE_PTY_PROXY_READY,
                        ProxyReady {
                            proxy_id: request.data.proxy_id.clone(),
                        },
                    );
                    tokio::spawn(async move { proxy.proxy_response().await });
                }
                Err(e) => {
                    info!("{} ProxyNew failed: {}", request.data.proxy_id, e)
                }
            }
        });
    }
}

impl Handler for BsonHandler<ProxyData> {
    fn process(self) {
        //info!("=> ProxyData");
        let request = self.request.clone();
        PtyGather::runtime().spawn(async move {
            let proxy_id = request.data.proxy_id.clone();
            let Some(proxy) = PtyGather::get_proxy(&proxy_id) else {
                return error!("{} failed find proxy", proxy_id);
            };

            let input_time = get_now_secs();
            proxy.last_time.store(input_time, SeqCst);
            let _ = proxy
                .writer
                .lock()
                .await
                .write_all(&request.data.data)
                .await
                .map_err(|err| error!("{} proxy write failed: {}", proxy_id, err));
        });
    }
}

impl Handler for BsonHandler<ProxyClose> {
    fn process(self) {
        let request = self.request.clone();
        info!("{} receive proxy closed", request.data.proxy_id);
        if let Some(proxy) = PtyGather::remove_proxy(&request.data.proxy_id) {
            proxy.is_stopped.store(true, SeqCst);
        };
    }
}

pub struct PtyProxy {
    proxy_id: String,
    session_id: String,
    reader: Arc<Mutex<OwnedReadHalf>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    last_time: Arc<AtomicU64>,
    is_stopped: Arc<AtomicBool>,
}

impl PtyProxy {
    pub async fn proxy_response(&self) {
        const BUF_SIZE: usize = 2048;
        let mut buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];
        let duration = Duration::from_millis(100);

        let mut data_send_size = 0;
        let mut data_send_cnt = 0;
        info!("{} start loop for proxy responses", self.proxy_id);
        loop {
            if self.is_stopped.load(SeqCst) {
                break info!("{} proxy is_stopped break", self.proxy_id);
            }

            let elapse = get_now_secs() - self.last_time.load(SeqCst);
            if elapse > 60 * 5 {
                break info!("proxy {} no data 5 minute break", self.proxy_id); //time out
            }
            let timeout_read =
                timeout(duration, self.reader.lock().await.read(&mut buffer[..])).await;

            if timeout_read.is_err() {
                continue; // timeout continue
            }

            match timeout_read.unwrap() {
                Ok(0) => break info!("{} proxy closed, break", self.proxy_id),
                Ok(size) => {
                    self.post(
                        WS_MSG_TYPE_PTY_PROXY_DATA,
                        ProxyData {
                            proxy_id: self.proxy_id.clone(),
                            data: buffer[0..size].to_vec(),
                        },
                    );
                    data_send_size = data_send_size + size;
                    data_send_cnt = data_send_cnt + 1;
                }
                Err(e) => break error!("{} proxy read failed: {}", self.proxy_id, e),
            }
        }
        self.post(
            WS_MSG_TYPE_PTY_PROXY_CLOSE,
            ProxyClose {
                proxy_id: self.proxy_id.clone(),
            },
        );
        info!(
            "{} send total size: {} cnt: {}",
            self.proxy_id, data_send_size, data_send_cnt
        );
        PtyGather::remove_proxy(&self.proxy_id);
    }

    fn post<T: Serialize>(&self, msg_type: &str, data: T) {
        PtyGather::reply_bson_msg(
            msg_type,
            PtyBinBase::<T> {
                session_id: self.session_id.clone(),
                custom_data: "".to_owned(),
                data,
            },
        );
    }
}
