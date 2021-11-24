use log::info;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::channel;
use std::sync::Arc;

mod common;
mod executor;
mod http;
mod ontime;
mod types;
mod ws;
mod uname;
mod daemonizer;

use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::AGENT_VERSION;
use crate::common::logger;
use crate::common::Opts;
use crate::http::thread as http_thread;
use crate::ontime::thread as ontime_thread;
use crate::ontime::timer::Timer;
use crate::ws::thread as ws_thread;

#[tokio::main]
async fn main() {

    let _opts = Opts::get_opts();
    daemonizer::daemonize(||{
        // log init after daemonized, so log dir will at same dir of agent
        logger::init();
        info!("agent version:[{}]", AGENT_VERSION);
        Timer::get_instance();

        // code of thread communication
        let (ws_kick_sender, kick_receiver) = channel();
        let ontime_kick_sender = ws_kick_sender.clone();

        let (ping_channel_sender,
            ping_channel_receiver) = channel();

        let running_task_num = Arc::new(AtomicU64::new(0));

        // ontime thread send ping request
        let _ot_thread = ontime_thread::run(
            ping_channel_receiver,
            ontime_kick_sender,
            running_task_num.clone(),
        );
        //
        // // http thread recv the notify
        let _h_thread = http_thread::run(kick_receiver, running_task_num.clone());

        loop {
            info!("now spawn a new ws connection");
            let s1 = ws_kick_sender.clone();
            let s2 = ping_channel_sender.clone();
            let ws_thread = ws_thread::run(s1, s2);
            ws_thread.join().or_log("ws thread joined");
        }
    });
}
