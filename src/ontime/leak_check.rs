use crate::common::sysinfo::system;
use crate::network::{Invoke, InvokeAdapter};
use crate::ontime::self_update::restart;

use log::info;
use ringbuffer::{AllocRingBuffer, RingBuffer};
use sysinfo::{get_current_pid, ProcessRefreshKind, ProcessesToUpdate};

#[cfg(unix)]
const MAX_FD_COUNT: u64 = 1000;
#[cfg(windows)]
const MAX_FD_COUNT: u64 = 2000;
const MAX_MEM_RES_BYTES: u64 = 200 * 1024 * 1024;
const LEAK_REPORT_FREQUENCY: u64 = 360;

pub struct LeakChecker {
    check_cnt: u64,
    mem_cnt: u64,
    fd_cnt: u64,
    mem_res_rf: AllocRingBuffer<u64>,
    fd_rf: AllocRingBuffer<u64>,
}

impl LeakChecker {
    pub fn new() -> Self {
        Self {
            check_cnt: 0,
            mem_cnt: 0,
            fd_cnt: 0,
            mem_res_rf: AllocRingBuffer::new(64),
            fd_rf: AllocRingBuffer::new(64),
        }
    }

    pub async fn check_resource_leak(&mut self) {
        let handle_cnt = get_handle_cnt();
        let mem_size = get_mem_size().await;
        self.fd_rf.push(handle_cnt);
        self.mem_res_rf.push(mem_size);

        if self.fd_rf.iter().all(|x| *x >= MAX_FD_COUNT)
            || self.mem_res_rf.iter().all(|x| *x >= MAX_MEM_RES_BYTES)
        {
            let log = format!(
                "resource leak detected, fd:{:?}, mem:{:?}",
                self.fd_rf, self.mem_res_rf
            );
            InvokeAdapter::log(&log).await;
            if let Err(e) = restart().await {
                InvokeAdapter::log(&format!("check_resource_leak restart failed: {e:#}")).await;
            }
            // should not comes here, because agent should has been killed when called `restart()`.
            std::process::exit(2);
        }

        self.fd_cnt += handle_cnt;
        self.mem_cnt += mem_size;
        if self.check_cnt != 0 && self.check_cnt % LEAK_REPORT_FREQUENCY == 0 {
            let fd_avg = (self.fd_cnt / LEAK_REPORT_FREQUENCY) as u32;
            let mem_avg = (self.mem_cnt / LEAK_REPORT_FREQUENCY) as u32;
            let zp_cnt = get_zombie_process().await;

            self.fd_cnt = 0;
            self.mem_cnt = 0;

            info!("ReportResource mem {mem_avg} handle {fd_avg} zp_cnt {zp_cnt}");
            let _ = InvokeAdapter::report_resource(fd_avg, mem_avg, zp_cnt).await;
        }
        self.check_cnt += 1;
    }
}

async fn get_mem_size() -> u64 {
    let current = get_current_pid().unwrap();
    let mut sys = system().await;
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[current]),
        false,
        ProcessRefreshKind::nothing().with_memory(),
    );
    sys.process(current).map(|p| p.memory()).unwrap_or_default()
}

#[cfg(unix)]
fn get_handle_cnt() -> u64 {
    let pid = std::process::id();
    if let Ok(proc) = procfs::process::Process::new(pid as i32) {
        match proc.fd_count() {
            Ok(fd) => return fd as u64,
            Err(err) => log::error!("get_handle_cnt {}", err),
        }
    }
    0
}

#[cfg(windows)]
fn get_handle_cnt() -> u64 {
    use winapi::um::processthreadsapi::{GetCurrentProcess, GetProcessHandleCount};
    let mut handle_cnt: u32 = 0;
    unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handle_cnt) };
    handle_cnt as u64
}

#[cfg(unix)]
async fn get_zombie_process() -> u32 {
    let current = get_current_pid().unwrap();
    let mut sys = system().await;
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let mut count = 0;
    for p in sys.processes().values() {
        if p.parent() == Some(current) && p.status() == sysinfo::ProcessStatus::Zombie {
            count += 1;
        }
    }
    count
}

#[cfg(windows)]
async fn get_zombie_process() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[tokio::test]
    async fn test_get_zombie_process() {
        use super::*;
        use crate::common::logger::init_test_log;
        use std::process::Command;
        init_test_log();
        let mut nz = get_zombie_process().await;
        assert_eq!(0, nz);
        let mut cmd = Command::new("pwd");
        let mut child = cmd.spawn().unwrap();
        nz = get_zombie_process().await;
        assert_eq!(1, nz);
        let _ = child.wait();
        nz = get_zombie_process().await;
        assert_eq!(0, nz);
    }
}
