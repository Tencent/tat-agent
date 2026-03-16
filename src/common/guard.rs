use std::time::Duration;

use tokio::{
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::sleep,
};

const TRY_ACQUIRE_RESTART_LOCK_INTERVAL: Duration = Duration::from_secs(2);

static RESTART_LOCK: RwLock<()> = RwLock::const_new(());

pub type PreventRestartGuard = RwLockReadGuard<'static, ()>;

/// Acquires exclusive permission to restart the system with the lowest priority.
pub async fn acquire_restart_lock() -> RwLockWriteGuard<'static, ()> {
    loop {
        if let Ok(guard) = RESTART_LOCK.try_write() {
            return guard;
        }
        sleep(TRY_ACQUIRE_RESTART_LOCK_INTERVAL).await;
    }
}

/// Acquires a guard that prevents the system from restarting.
pub async fn prevent_restart() -> PreventRestartGuard {
    RESTART_LOCK.read().await
}
