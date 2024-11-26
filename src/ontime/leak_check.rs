use crate::network::{Invoke, InvokeAdapter};
use crate::ontime::self_update::try_restart_agent;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{atomic::AtomicU64, LazyLock, Mutex};

use log::{error, info, warn};
use ringbuffer::{AllocRingBuffer, RingBuffer};
use tokio::runtime::Builder;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::fs::{self, File};
        use std::io::BufRead;
        use std::path::Path;
        use std::process;
        use procfs::process::Process;
        const ONTIME_MAX_FD_COUNT: u64 = 1000;
    } else if #[cfg(windows)] {
        use winapi::um::processthreadsapi::{GetProcessHandleCount, GetCurrentProcess};
        use winapi::um::psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use std::mem;
        const ONTIME_MAX_FD_COUNT: u64 = 2000;
    }
}

const ONTIME_MAX_MEM_RES_BYTES: u64 = 200 * 1024 * 1024;
const ONTIME_LEAK_REPORT_FREQUENCY: u64 = 360;

pub fn check_resource_leak() {
    static CHECK_CNT: AtomicU64 = AtomicU64::new(0);
    static FD_CNT: AtomicU64 = AtomicU64::new(0);
    static MEM_CNT: AtomicU64 = AtomicU64::new(0);
    static MEM_RES_RF: LazyLock<Mutex<AllocRingBuffer<u64>>> =
        LazyLock::new(|| Mutex::new(AllocRingBuffer::new(64)));
    static FD_RF: LazyLock<Mutex<AllocRingBuffer<u64>>> =
        LazyLock::new(|| Mutex::new(AllocRingBuffer::new(64)));

    let check_cnt = CHECK_CNT.fetch_add(1, SeqCst);
    let handle_cnt = get_handle_cnt();
    let mem_size = get_mem_size();

    let mut fd_rf = FD_RF.lock().unwrap();
    let mut mem_res_rf = MEM_RES_RF.lock().unwrap();
    fd_rf.push(handle_cnt);
    mem_res_rf.push(mem_size);

    if fd_rf.iter().all(|x| *x >= ONTIME_MAX_FD_COUNT)
        || mem_res_rf.iter().all(|x| *x >= ONTIME_MAX_MEM_RES_BYTES)
    {
        warn!(
            "Resource leak detected, fd:{:?}, mem:{:?}",
            fd_rf.to_vec(),
            mem_res_rf.to_vec()
        );
        if let Err(e) = try_restart_agent() {
            error!("try restart agent failed: {:#}", e)
        }

        // should not comes here, because agent should has been killed when called `try_restart_agent`.
        std::process::exit(2);
    }

    let fd_total = FD_CNT.fetch_add(handle_cnt, SeqCst);
    let mem_total = MEM_CNT.fetch_add(mem_size, SeqCst);

    if check_cnt != 0 && check_cnt % ONTIME_LEAK_REPORT_FREQUENCY == 0 {
        FD_CNT.store(0, SeqCst);
        MEM_CNT.store(0, SeqCst);

        let fd_avg = (fd_total / ONTIME_LEAK_REPORT_FREQUENCY) as u32;
        let mem_avg = (mem_total / ONTIME_LEAK_REPORT_FREQUENCY) as u32;
        #[cfg(unix)]
        let zp_cnt = get_zoom_process() as u32;
        #[cfg(windows)]
        let zp_cnt = 0 as u32;

        info!("ReportResource mem {mem_avg} handle {fd_avg} zp_cnt {zp_cnt}");
        let _ = Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(InvokeAdapter::report_resource(fd_avg, mem_avg, zp_cnt));
    }
}

#[cfg(windows)]
fn get_handle_cnt() -> u64 {
    unsafe {
        let mut handle_cnt: u32 = 0;
        GetProcessHandleCount(GetCurrentProcess(), &mut handle_cnt);
        handle_cnt as u64
    }
}

#[cfg(windows)]
fn get_mem_size() -> u64 {
    unsafe {
        let mut mm_info: PROCESS_MEMORY_COUNTERS = mem::zeroed();
        let cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        mm_info.cb = cb;
        GetProcessMemoryInfo(GetCurrentProcess(), &mut mm_info, cb);
        mm_info.WorkingSetSize as u64
    }
}

#[cfg(unix)]
fn get_handle_cnt() -> u64 {
    let pid = process::id();
    if let Ok(proc) = Process::new(pid as i32) {
        match proc.fd_count() {
            Ok(fd) => return fd as u64,
            Err(err) => error!("get_handle_cnt {}", err),
        }
    }
    return 0;
}

#[cfg(unix)]
fn get_mem_size() -> u64 {
    let pid = process::id();
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if let Ok(proc) = Process::new(pid as i32) {
        match proc.statm() {
            Ok(statm) => return statm.resident * page_size as u64,
            Err(err) => error!("get_mem_size {}", err),
        }
    }
    return 0;
}

#[cfg(unix)]
fn get_zoom_process() -> u32 {
    let pid = process::id() as i32;
    let mut nz: u32 = 0;
    let items = fs::read_dir(Path::new("/proc")).unwrap();
    for item in items {
        let Ok(entry) = item else { continue };
        if !matches!(entry.metadata(), Ok(meta) if meta.is_dir() ) {
            continue;
        }

        let status_path = entry.path().join("status");
        if matches!(fs::metadata(status_path.as_path()), Ok(metadata) if !metadata.is_file()) {
            continue;
        }

        let mut ppid: Option<i32> = None;
        let mut state = "".to_string();
        if let Ok(file) = File::open(status_path) {
            let mut reader = std::io::BufReader::new(file);
            loop {
                let mut linebuf = String::new();
                if reader.read_line(&mut linebuf).is_err() {
                    break;
                }
                if linebuf.is_empty() {
                    break;
                }
                let parts: Vec<&str> = linebuf[..].splitn(2, ':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim();
                    let value = parts[1].trim();
                    match key {
                        "PPid" => ppid = value.parse().ok(),
                        "State" => state = value.to_string(),
                        _ => (),
                    }
                }
            }
        }

        if ppid.is_some() && ppid.unwrap() == pid && state.contains("Z") {
            nz = nz + 1;
        }
    }
    nz
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn test_get_zoom_prcesss() {
        use super::*;
        use crate::common::logger::init_test_log;
        use std::process::Command;
        init_test_log();
        let mut nz = get_zoom_process();
        assert_eq!(0, nz);
        let mut cmd = Command::new("pwd");
        let mut child = cmd.spawn().unwrap();
        nz = get_zoom_process();
        assert_eq!(1, nz);
        let _ = child.wait();
        nz = get_zoom_process();
        assert_eq!(0, nz);
    }
}
