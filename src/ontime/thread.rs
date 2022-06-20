use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{
    ONTIME_CHECK_TASK_NUM, ONTIME_KICK_INTERVAL, ONTIME_KICK_SOURCE, ONTIME_THREAD_INTERVAL,
    ONTIME_UPDATE_INTERVAL, WS_MSG_TYPE_KICK,
};
use crate::common::evbus::EventBus;
use crate::ontime::self_update::{try_restart_agent, try_update};
use crate::ontime::timer::Timer;
use log::debug;
use log::info;
use log::warn;
use std::ops::AddAssign;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

pub fn run(
    dispatcher: &Arc<EventBus>,
    running_task_num: &Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    let dispatcher = dispatcher.clone();
    let running_task_num = running_task_num.clone();

    let ret = thread::spawn(move || {
        let mut instant_kick = SystemTime::now();
        let mut instant_update =
            SystemTime::now() - Duration::from_secs(ONTIME_UPDATE_INTERVAL - 10);
        let mut instant_check_tasks = SystemTime::now();
        // Will be set to true after self updating finished,
        // and then exit current agent to switch to new version agent.
        let need_restart = Arc::new(AtomicBool::new(false));
        let self_updating = Arc::new(AtomicBool::new(false));
        loop {
            // inter-thread channel communication, very fast
            check_ontime_kick(&mut instant_kick, dispatcher.clone());
            // do self update in a new thread, will not block current thread
            check_ontime_update(&mut instant_update, &self_updating, &need_restart);
            // run the tasks whose timer is arrived, generally very quick task
            schedule_timer_task();
            // check running tasks number and need_restart flag to do graceful restart when no running tasks
            check_running_task_num(&mut instant_check_tasks, &need_restart, &running_task_num);
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

fn check_interval_elapsed(instant_time: &mut SystemTime, secs: u64) -> bool {
    let interval = Duration::from_secs(secs);
    match instant_time.elapsed() {
        Ok(duration) => {
            if duration < interval {
                // interval not reach, do nothing
                return false;
            }
        }
        Err(e) => {
            warn!("get systemTime err: {:?}", e);
            return false;
        }
    }
    // instant.add_assign() is better than *instant = now(),
    // the latter may cause accumulated latency after long term running.
    instant_time.add_assign(interval);
    return true;
}

fn check_ontime_kick(instant_kick: &mut SystemTime, dispatcher: Arc<EventBus>) {
    if !check_interval_elapsed(instant_kick, ONTIME_KICK_INTERVAL) {
        return;
    }
    dispatcher.dispatch(WS_MSG_TYPE_KICK, ONTIME_KICK_SOURCE.to_string());
}

fn check_ontime_update(
    instant_update: &mut SystemTime,
    self_updating: &Arc<AtomicBool>,
    need_restart: &Arc<AtomicBool>,
) {
    if self_updating.load(Ordering::SeqCst) {
        return;
    }

    if !check_interval_elapsed(instant_update, ONTIME_UPDATE_INTERVAL) {
        return;
    }

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
    if !check_interval_elapsed(instance_check, ONTIME_CHECK_TASK_NUM) {
        return;
    }

    let restart_flag = need_restart.load(Ordering::SeqCst);
    if restart_flag {
        let task_num = running_task_num.load(Ordering::SeqCst);
        if task_num == 0 {
            info!(
                "running tasks num: {}, need_restart is {}, restart program.",
                task_num, restart_flag
            );

            if let Err(e) = try_restart_agent() {
                warn!("try restart agent fail: {:?}", e)
            }

            // should not comes here, because agent should has been killed when called `try_restart_agent`.
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
