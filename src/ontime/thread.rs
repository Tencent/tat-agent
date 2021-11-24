use log::debug;
use log::info;
use log::warn;
use std::ops::AddAssign;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use futures01::sink::{Sink, Wait};
use futures01::sync::mpsc::UnboundedSender;
use websocket::OwnedMessage;

use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{
    ONTIME_CHECK_TASK_NUM, ONTIME_KICK_INTERVAL, ONTIME_KICK_SOURCE, ONTIME_PING_INTERVAL,
    ONTIME_THREAD_INTERVAL, ONTIME_UPDATE_INTERVAL,
};
use crate::ontime::self_update::try_update;
use crate::ontime::timer::Timer;
use crate::types::inner_msg::KickMsg;

pub fn run(
    ping_channel_receiver: Receiver<UnboundedSender<OwnedMessage>>,
    ontime_kick_sender: Sender<KickMsg>,
    running_task_num: Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    let ret = thread::spawn(move || {
        let ping_sender = ping_channel_receiver
            .recv()
            .unwrap_or_exit("ping channel recv fail");
        let mut sender = ping_sender.wait();

        let mut instant_kick = SystemTime::now();
        let mut instant_ping = SystemTime::now();
        let mut instant_update =
            SystemTime::now() - Duration::from_secs(ONTIME_UPDATE_INTERVAL - 10);
        let mut instant_check_tasks = SystemTime::now();
        // Will be set to true after self updating finished,
        // and then exit current agent to switch to new version agent.
        let need_restart = Arc::new(AtomicBool::new(false));
        let self_updating = Arc::new(AtomicBool::new(false));

        // kick once after agent start
        send_kick_msg(&ontime_kick_sender);
        // ping once after agent start
        send_ping_msg(&ping_channel_receiver, &mut sender);

        loop {
            // inter-thread channel communication, very fast
            check_ontime_kick(&mut instant_kick, &ontime_kick_sender);
            // do self update in a new thread, will not block current thread
            check_ontime_update(&mut instant_update, &self_updating, &need_restart);
            // run the tasks whose timer is arrived, generally very quick task
            schedule_timer_task();
            // check running tasks number and need_restart flag to do graceful restart when no running tasks
            check_running_task_num(&mut instant_check_tasks, &need_restart, &running_task_num);
            // may block thread during WebSocket reconnect, put it at end
            check_ontime_ping(&mut instant_ping, &ping_channel_receiver, &mut sender);

            thread::sleep(Duration::from_secs(ONTIME_THREAD_INTERVAL));
        }
    });
    ret
}

fn schedule_timer_task() {
    let tasks;
    {
        let timer = Timer::get_instance();
        let mut timer = timer.lock().unwrap_or_exit("");
        debug!("current status of timer:{:?}", timer);
        tasks = timer.tasks_to_schedule();
    }
    // release the lock and then run each task
    let cnt = tasks.len();
    for task in tasks {
        task.run_task();
    }
    if cnt > 0 {
        info!("total {} timer tasks scheduled", cnt);
    }
}

fn check_ontime_kick(instant_kick: &mut SystemTime, ontime_kick_sender: &Sender<KickMsg>) {
    let interval = Duration::from_secs(ONTIME_KICK_INTERVAL);
    match instant_kick.elapsed() {
        Ok(duration) => {
            if duration < interval {
                // interval not reach, do nothing
                return;
            }
        }
        Err(e) => {
            warn!("get systemTime err: {:?}", e);
            return;
        }
    }
    // instant.add_assign() is better than *instant = now(),
    // the latter may cause accumulated latency after long term running.
    instant_kick.add_assign(interval);
    send_kick_msg(ontime_kick_sender);
}

fn send_kick_msg(ontime_kick_sender: &Sender<KickMsg>) {
    let msg = KickMsg {
        kick_source: ONTIME_KICK_SOURCE.to_string(),
    };
    ontime_kick_sender
        .send(msg)
        .unwrap_or_exit("ontime kick send fail");
    info!("ontime kick sent");
}

fn check_ontime_ping(
    instant_ping: &mut SystemTime,
    ping_channel_receiver: &Receiver<UnboundedSender<OwnedMessage>>,
    sender: &mut Wait<UnboundedSender<OwnedMessage>>,
) {
    let interval = Duration::from_secs(ONTIME_PING_INTERVAL);
    match instant_ping.elapsed() {
        Ok(duration) => {
            if duration < interval {
                // interval not reach, do nothing
                return;
            }
        }
        Err(e) => {
            warn!("get systemTime err: {:?}", e);
            return;
        }
    }
    instant_ping.add_assign(interval);
    send_ping_msg(ping_channel_receiver, sender);
}

fn send_ping_msg(
    ping_channel_receiver: &Receiver<UnboundedSender<OwnedMessage>>,
    sender: &mut Wait<UnboundedSender<OwnedMessage>>,
) {
    loop {
        let ret = sender.send(OwnedMessage::Ping(Vec::new()));
        if let Err(e) = ret {
            info!("ping_sender ret: {:?}", e);
            // may block few seconds at this line
            let ping_sender = ping_channel_receiver
                .recv()
                .unwrap_or_exit("ping channel recv fail");
            info!("new ping_sender got, try send again");
            *sender = ping_sender.wait();
        } else {
            break;
        }
    }
    info!("ontime ping sent");
}

fn check_ontime_update(
    instant_update: &mut SystemTime,
    self_updating: &Arc<AtomicBool>,
    need_restart: &Arc<AtomicBool>,
) {
    if self_updating.load(Ordering::SeqCst) {
        return;
    }

    let interval = Duration::from_secs(ONTIME_UPDATE_INTERVAL);
    match instant_update.elapsed() {
        Ok(duration) => {
            if duration < interval {
                // interval not reach, do nothing
                return;
            }
        }
        Err(e) => {
            warn!("get systemTime err: {:?}", e);
            return;
        }
    }

    instant_update.add_assign(interval);

    self_updating.store(true, Ordering::SeqCst);
    info!("start check self update");
    let self_updating_clone = self_updating.clone();
    let need_restart_clone = need_restart.clone();
    thread::Builder::new()
        .spawn(move || {
            try_update(self_updating_clone, need_restart_clone);
        })
        .ok();
}

fn check_running_task_num(
    instance_check: &mut SystemTime,
    need_restart: &Arc<AtomicBool>,
    running_task_num: &Arc<AtomicU64>,
) {
    let interval = Duration::from_secs(ONTIME_CHECK_TASK_NUM);
    match instance_check.elapsed() {
        Ok(duration) => {
            if duration < interval {
                // interval not reach, do nothing
                return;
            }
        }
        Err(e) => {
            warn!("get systemTime err: {:?}", e);
            return;
        }
    }
    instance_check.add_assign(interval);
    let restart_flag = need_restart.load(Ordering::SeqCst);
    if restart_flag {
        let task_num = running_task_num.load(Ordering::SeqCst);
        if task_num == 0 {
            info!(
                "running tasks num: {}, need_restart is {}, exit prgram",
                task_num, restart_flag
            );
            std::process::exit(2);
        }
        debug!(
            "running tasks num: {}, need_restart is {}, continue running",
            task_num, restart_flag
        );
    } else {
        debug!("need_restart is {}, continue running", restart_flag);
    }
}
