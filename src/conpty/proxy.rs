use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc,
    },
    time::Duration,
};

use super::{
    gather::PtyGather,
    handler::{BsonHandler, Handler},
};
use crate::{
    common::{
        consts::{
            SLOT_PTY_BIN, WS_MSG_TYPE_PTY_PROXY_CLOSE, WS_MSG_TYPE_PTY_PROXY_DATA,
            WS_MSG_TYPE_PTY_PROXY_NEW, WS_MSG_TYPE_PTY_PROXY_READY,
        },
        evbus::EventBus,
        utils::get_now_secs,
    },
    network::types::ws_msg::{ProxyClose, ProxyData, ProxyNew, ProxyReady, PtyBinBase},
};
use log::{error, info};
use serde::Serialize;
use std::sync::atomic::Ordering::SeqCst;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::Mutex,
    time::timeout,
};

pub(crate) fn register_proxy_handlers(event_bus: &Arc<EventBus>) {
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
                    info!("{} ProxyNew fail  {}", request.data.proxy_id, e.to_string());
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
            if let Some(proxy) = PtyGather::get_proxy(&proxy_id) {
                let input_time = get_now_secs();
                proxy.last_time.store(input_time, SeqCst);
                match proxy
                    .writer
                    .lock()
                    .await
                    .write_all(&request.data.data)
                    .await
                {
                    Ok(_) => return,
                    Err(err) => {
                        error!("{} proxy  write fail {}", proxy_id, err);
                    }
                };
            } else {
                error!("{} failed find proxy", proxy_id)
            }
        });
    }
}

impl Handler for BsonHandler<ProxyClose> {
    fn process(self) {
        let request = self.request.clone();
        info!("{} receive proxy close", request.data.proxy_id);
        if let Some(proxy) = PtyGather::remove_proxy(&request.data.proxy_id) {
            proxy.is_stopped.store(true, SeqCst);
        };
    }
}

pub(crate) struct PtyProxy {
    proxy_id: String,
    session_id: String,
    reader: Arc<Mutex<OwnedReadHalf>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    last_time: Arc<AtomicU64>,
    is_stopped: Arc<AtomicBool>,
}

impl PtyProxy {
    pub(crate) async fn proxy_response(&self) {
        const BUF_SIZE: usize = 2048;
        let mut buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];
        let duration = Duration::from_millis(100);

        let mut data_send_size = 0;
        let mut data_send_cnt = 0;
        info!("{}  start loop for proxy responses", self.proxy_id);
        loop {
            if self.is_stopped.load(SeqCst) {
                info!("{} proxy is_stopped break", self.proxy_id);
                break;
            }

            let last = self.last_time.load(SeqCst);
            let now = get_now_secs();
            if now - last > 1000 * 60 * 5 {
                info!("proxy{} no data 5 minute break", self.proxy_id);
                break; //time out
            }
            let timeout_read =
                timeout(duration, self.reader.lock().await.read(&mut buffer[..])).await;

            if timeout_read.is_err() {
                continue; // timeout continue
            }

            match timeout_read.expect("timeout check error") {
                Ok(size) => {
                    if size == 0 {
                        info!("{} proxy closed,break", self.proxy_id);
                        break;
                    }
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
                Err(e) => {
                    error!("{} proxy read failed  {}", self.proxy_id, e.to_string());
                    break;
                }
            }
        }
        self.post(
            WS_MSG_TYPE_PTY_PROXY_CLOSE,
            ProxyClose {
                proxy_id: self.proxy_id.clone(),
            },
        );
        info!(
            "{} send total size: {}  cnt: {}",
            self.proxy_id, data_send_size, data_send_cnt
        );
        PtyGather::remove_proxy(&self.proxy_id);
    }

    fn post<T>(&self, msg_type: &str, data: T)
    where
        T: Serialize,
    {
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
