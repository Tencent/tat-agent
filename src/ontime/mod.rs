pub mod leak_check;
pub mod self_update;

use self::leak_check::LeakChecker;
use self::self_update::{check_update, remove_update_file, restart};
use crate::common::evbus::EventBus;
use crate::network::{InvokeAdapter, EVENT_CHECK_UPDATE, EVENT_FORCE_RESTART};

use std::sync::{atomic::AtomicU64, Arc};
use std::{thread, time::Duration};

use tokio::time::{sleep, timeout};
use tokio::{runtime::Runtime, sync::Notify};

const UPDATE_CHECK_INVL: Duration = Duration::from_secs(2 * 60 * 60); // 2 hours
const RESTART_CHECK_INVL: Duration = Duration::from_secs(10);
const LEAK_CHECK_INVL: Duration = Duration::from_secs(10);

pub fn run(dispatcher: &Arc<EventBus>, stop_counter: Arc<AtomicU64>, rt: &Arc<Runtime>) {
    let (update_notify, restart_notify) = <(Arc<Notify>, Arc<Notify>) as Default>::default();
    let (update_waiter, restart_waiter) = (update_notify.clone(), restart_notify.clone());

    dispatcher.register(EVENT_CHECK_UPDATE, move |_| update_notify.notify_one());
    dispatcher.register(EVENT_FORCE_RESTART, move |_| restart_notify.notify_one());
    thread::spawn(move || ontime_thread(&stop_counter, update_waiter, restart_waiter));
    rt.spawn(check_resource_leak_interval());
}

#[tokio::main(flavor = "current_thread")]
async fn ontime_thread(stop_counter: &Arc<AtomicU64>, update: Arc<Notify>, restart: Arc<Notify>) {
    remove_update_file().await;
    sleep(Duration::from_secs(1)).await;
    tokio::spawn(force_restart(restart));
    check_update_interval(&stop_counter, update).await;
}

async fn check_update_interval(stop_counter: &Arc<AtomicU64>, notify: Arc<Notify>) {
    loop {
        check_update(stop_counter).await;
        let _ = timeout(UPDATE_CHECK_INVL, notify.notified()).await;
    }
}

async fn check_resource_leak_interval() {
    let mut checker = LeakChecker::new();
    loop {
        checker.check_resource_leak().await;
        sleep(LEAK_CHECK_INVL).await;
    }
}

async fn force_restart(notify: Arc<Notify>) {
    notify.notified().await;
    if let Err(e) = restart().await {
        InvokeAdapter::log(&format!("force_restart failed: {e:#}")).await;
    }
    // should not comes here, because agent should has been killed when called `restart()`.
    std::process::exit(2);
}
