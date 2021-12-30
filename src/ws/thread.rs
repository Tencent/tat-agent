use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::{thread, time};

use futures01::future::Future;
use futures01::sink::{Sink, Wait};
use futures01::stream::Stream;
use futures01::sync::mpsc;
use futures01::sync::mpsc::UnboundedSender;
use log::debug;
use log::error;
use log::info;
use serde_json;
use tokio01 as tokio;
use websocket::header::Headers;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, CloseData, OwnedMessage};

use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{
    AGENT_VERSION, MAX_PING_FROM_LAST_PONG, VIP_HEADER, VPCID_HEADER, WS_ACTIVE_CLOSE,
    WS_ACTIVE_CLOSE_CODE, WS_KERNEL_NAME_HEADER, WS_LAST_CLOSE_INTERVAL, WS_MSG_TYPE_ACK,
    WS_MSG_TYPE_KICK, WS_PASSIVE_CLOSE, WS_PASSIVE_CLOSE_CODE, WS_RECONNECT_INTERVAL, WS_URL,
    WS_VERSION_HEADER,
};
use crate::common::envs;
use crate::types::inner_msg::KickMsg;
use crate::types::ws_msg::WsMsg;
use crate::uname::common::UnameExt;
use crate::uname::Uname;

pub fn run(
    kick_sender: Sender<KickMsg>,
    ping_channel_sender: Sender<UnboundedSender<OwnedMessage>>,
) -> thread::JoinHandle<()> {
    let ret = thread::spawn(move || {
        let mut runtime = tokio::runtime::current_thread::Builder::new()
            .build()
            .unwrap_or_exit("ws tokio runtime build fail");

        let ping_cnt_from_last_pong = Arc::new(AtomicUsize::new(0));
        let close_sent = Arc::new(AtomicBool::new(false));
        let header = gen_ver_header();

        loop {
            // a loop of new connection, reset the flag
            ping_cnt_from_last_pong.store(0, Ordering::SeqCst);
            close_sent.store(false, Ordering::SeqCst);

            // new channel pair in this loop
            let (ping_sender, ping_receiver) = mpsc::unbounded();
            let my_ping_sender0 = ping_sender.clone();
            let mut my_ping_sender0 = my_ping_sender0.wait();
            let my_ping_sender1 = ping_sender.clone();
            let mut my_ping_sender1 = my_ping_sender1.wait();
            // send the new sender to ontime thread
            ping_channel_sender
                .send(ping_sender)
                .unwrap_or_exit("ping channel send fail");

            let sender = kick_sender.clone();

            let runner = ClientBuilder::new(WS_URL)
                .unwrap_or_exit("ws cli builder fail")
                .custom_headers(&header)
                .async_connect_insecure()
                .map_err(|e| {
                    error!("connect fail:{:?}", e);
                    thread::sleep(time::Duration::from_secs(WS_RECONNECT_INTERVAL));
                    panic!();
                })
                .and_then(|(duplex, _)| {
                    info!("connection established");
                    let (sink, stream) = duplex.split();
                    stream
                        .filter_map(|msg| {
                            handle_server_msg(
                                msg,
                                &close_sent,
                                &ping_cnt_from_last_pong,
                                &sender,
                                &mut my_ping_sender0,
                            )
                        })
                        .select(
                            ping_receiver
                                .filter_map(|msg| {
                                    handle_ping_notify_msg(
                                        msg,
                                        &close_sent,
                                        &ping_cnt_from_last_pong,
                                        &mut my_ping_sender1,
                                    )
                                })
                                .map_err(|_| WebSocketError::NoDataAvailable),
                        )
                        .forward(sink)
                })
                .map(|_| {
                    info!("ws connection finished");
                })
                .or_else(|err| {
                    error!("ws connection ended with an error: {:?}", err);
                    Ok(()) as Result<(), ()>
                });

            info!("establishing new ws connection");
            runtime.block_on(runner).or_log("ws runtime run failed");

            thread::sleep(time::Duration::from_secs(WS_RECONNECT_INTERVAL));
        }
    });

    ret
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
fn handle_server_msg(
    msg: OwnedMessage,
    close_sent: &Arc<AtomicBool>,
    ping_cnt_from_last_pong: &Arc<AtomicUsize>,
    kick_sender: &Sender<KickMsg>,
    my_ping_sender: &mut Wait<UnboundedSender<OwnedMessage>>,
) -> Option<OwnedMessage> {
    info!("ws recv msg: {:?}", msg);
    if close_sent.load(Ordering::SeqCst) {
        info!("ws close msg sent, ignore following msg from server");
        return None;
    }
    match msg {
        OwnedMessage::Ping(data) => Some(OwnedMessage::Pong(data)),
        OwnedMessage::Pong(_) => {
            // connection ok now, just clear the cnt
            ping_cnt_from_last_pong.store(0, Ordering::SeqCst);
            None
        }
        OwnedMessage::Text(msg) => {
            let ret = handle_ws_text_msg(msg, &kick_sender);
            ret
        }
        OwnedMessage::Close(_) => {
            close_sent.store(true, Ordering::SeqCst);
            // notify myself to be ready to abort this task
            my_ping_sender
                .send(OwnedMessage::Ping("".to_string().into_bytes()))
                .or_log("notify myself to abort this ws task failed");
            Some(OwnedMessage::Close(Some(CloseData {
                status_code: WS_PASSIVE_CLOSE_CODE,
                reason: WS_PASSIVE_CLOSE.to_string(),
            })))
        }
        _ => None,
    }
}

fn handle_ws_text_msg(msg: String, kick_sender: &Sender<KickMsg>) -> Option<OwnedMessage> {
    let ret: Result<WsMsg, serde_json::Error> = serde_json::from_str(msg.as_str());
    match ret {
        Ok(ws_msg) => gen_ws_text_rsp(ws_msg, kick_sender),
        Err(e) => {
            error!("json parse fail, invalid ws text msg: {:?}", e);
            // ignore it
            None
        }
    }
}

fn gen_ws_text_rsp(mut ws_msg: WsMsg, kick_sender: &Sender<KickMsg>) -> Option<OwnedMessage> {
    if ws_msg.r#type != WS_MSG_TYPE_KICK {
        error!("not kick, unknown ws msg:{:?}", ws_msg.r#type);
        return None;
    }

    let msg = KickMsg {
        kick_source: "ws".to_string(),
    };
    // notify http thread to fetch task
    kick_sender.send(msg).unwrap_or_exit("ws kick send fail");
    info!("kick_sender sent to notify fetch task, kick_source ws");

    // gen ack rsp for ws server
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

// msg from ontime thread, which notify ws to ping server
fn handle_ping_notify_msg(
    msg: OwnedMessage,
    close_sent: &Arc<AtomicBool>,
    ping_cnt_from_last_pong: &Arc<AtomicUsize>,
    my_ping_sender: &mut Wait<UnboundedSender<OwnedMessage>>,
) -> Option<OwnedMessage> {
    if close_sent.load(Ordering::SeqCst) {
        // give an opportunity of 1s to send the last ws close msg out
        thread::sleep(time::Duration::from_secs(WS_LAST_CLOSE_INTERVAL));
        panic!("in case of server never response, abort this task & reconnect");
    }

    let pre_val = ping_cnt_from_last_pong.fetch_add(1, Ordering::SeqCst);

    if pre_val >= MAX_PING_FROM_LAST_PONG {
        if !close_sent.load(Ordering::SeqCst) {
            close_sent.store(true, Ordering::SeqCst);
            // notify myself to be ready to abort this task
            my_ping_sender
                .send(OwnedMessage::Ping("".to_string().into_bytes()))
                .or_log("notify myself to abort this ws task failed");
        }
        info!(
            "pre val of ping_cnt_from_last_pong:{}, lost pong too long, now send ws close msg",
            pre_val
        );
        Some(OwnedMessage::Close(Some(CloseData {
            status_code: WS_ACTIVE_CLOSE_CODE,
            reason: WS_ACTIVE_CLOSE.to_string(),
        })))
    } else {
        // send ping for heartbeat
        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use log::info;

    use crate::common::logger::init_test_log;

    use super::*;

    // #[test] unused
    fn _test_ws_cus_header() {
        init_test_log();
        let header = gen_ver_header();
        assert_eq!(2, header.len());
        info!("header:{:?}", header);
    }
}
