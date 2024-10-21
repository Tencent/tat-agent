use crate::common::evbus::EventBus;
use crate::ontime::leak_check::check_resource_leak;
use crate::ontime::self_update::{try_restart_agent, try_update};

use std::ops::AddAssign;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use log::{debug, info, warn};

use crate::network::types::ws_msg::WS_MSG_TYPE_CHECK_UPDATE;
const ONTIME_UPDATE_INTERVAL: u64 = 2 * 60 * 60;
const ONTIME_THREAD_INTERVAL: u64 = 1;
const ONTIME_CHECK_TASK_NUM: u64 = 10;
const ONTIME_LEAK_CEHECK_INTERVAL: u64 = 10;

pub fn run(
    dispatcher: &Arc<EventBus>,
    running_task_num: &Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    let dispatcher = dispatcher.clone();
    let running_task_num = running_task_num.clone();

    let ret = thread::spawn(move || {
        let mut instant_leak = SystemTime::now();

        let mut instant_update =
            SystemTime::now() - Duration::from_secs(ONTIME_UPDATE_INTERVAL - 10);

        let mut instant_check_tasks = SystemTime::now();
        // Will be set to true after self updating finished,
        // and then exit current agent to switch to new version agent.
        let need_restart = Arc::new(AtomicBool::new(false));
        let self_updating = Arc::new(AtomicBool::new(false));

        register_update_handlers(&dispatcher, &self_updating, &need_restart);

        loop {
            //leakage check
            check_resource_leakage(&mut instant_leak);
            // do self update in a new thread, will not block current thread
            check_ontime_update(&mut instant_update, &self_updating, &need_restart);
            // check running tasks number and need_restart flag to do graceful restart when no running tasks
            check_running_task_num(&mut instant_check_tasks, &need_restart, &running_task_num);
            thread::sleep(Duration::from_secs(ONTIME_THREAD_INTERVAL));
        }
    });
    ret
}

fn register_update_handlers(
    dispatcher: &Arc<EventBus>,
    self_updating: &Arc<AtomicBool>,
    need_restart: &Arc<AtomicBool>,
) {
    dispatcher.register(WS_MSG_TYPE_CHECK_UPDATE, {
        let self_updating = self_updating.clone();
        let need_restart = need_restart.clone();
        move |_| {
            if !self_updating.fetch_or(true, Ordering::SeqCst) {
                try_update(self_updating.clone(), need_restart.clone());
            }
        }
    });
}

fn check_interval_elapsed(instant_time: &mut SystemTime, secs: u64) -> bool {
    let interval = Duration::from_secs(secs);
    match instant_time.elapsed() {
        Ok(duration) if duration < interval => return false, // interval not reach, do nothing
        Ok(_) => (),
        Err(e) => {
            warn!("get systemTime error: {}", e);
            return false;
        }
    }
    // instant.add_assign() is better than *instant = now(),
    // the latter may cause accumulated latency after long term running.
    instant_time.add_assign(interval);
    return true;
}

fn check_ontime_update(
    instant_update: &mut SystemTime,
    self_updating: &Arc<AtomicBool>,
    need_restart: &Arc<AtomicBool>,
) {
    if !check_interval_elapsed(instant_update, ONTIME_UPDATE_INTERVAL) {
        return;
    }

    if self_updating.fetch_or(true, Ordering::SeqCst) {
        return;
    }

    info!("start check self update");
    let _ = thread::Builder::new().name("update".to_string()).spawn({
        let self_updating = self_updating.clone();
        let need_restart = need_restart.clone();
        move || try_update(self_updating, need_restart)
    });
}

fn check_running_task_num(
    instance_check: &mut SystemTime,
    need_restart: &Arc<AtomicBool>,
    running_task_num: &Arc<AtomicU64>,
) {
    if !check_interval_elapsed(instance_check, ONTIME_CHECK_TASK_NUM) {
        return;
    }

    let restart_flag = need_restart.load(Ordering::SeqCst);
    if restart_flag {
        let task_num = running_task_num.load(Ordering::SeqCst);
        if task_num == 0 {
            info!(
                "running tasks num: {}, need_restart: {}, restart program.",
                task_num, restart_flag
            );

            if let Err(e) = try_restart_agent() {
                warn!("try restart agent failed: {}", e)
            }

            // should not comes here, because agent should has been killed when called `try_restart_agent`.
            std::process::exit(2);
        }
        debug!(
            "running tasks num: {}, need_restart: {}, continue running",
            task_num, restart_flag
        );
    } else {
        debug!("need_restart: {}, continue running", restart_flag);
    }
}

fn check_resource_leakage(instant_leak: &mut SystemTime) {
    if !check_interval_elapsed(instant_leak, ONTIME_LEAK_CEHECK_INTERVAL) {
        return;
    }
    check_resource_leak();
}
