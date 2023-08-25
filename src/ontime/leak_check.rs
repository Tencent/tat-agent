use crate::network::InvokeAPIAdapter;
use crate::ontime::self_update::try_restart_agent;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{atomic::AtomicU64, Mutex};

use log::{error, info, warn};
use once_cell::sync::Lazy;
use ringbuffer::{AllocRingBuffer, RingBufferExt, RingBufferWrite};
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
    static MEM_RES_RF: Lazy<Mutex<AllocRingBuffer<u64>>> =
        Lazy::new(|| Mutex::new(AllocRingBuffer::with_capacity(64)));
    static FD_RF: Lazy<Mutex<AllocRingBuffer<u64>>> =
        Lazy::new(|| Mutex::new(AllocRingBuffer::with_capacity(64)));

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
            error!("try restart agent failed: {:?}", e)
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

        let adapter = InvokeAPIAdapter::new();
        let requester = adapter.report_resource(fd_avg, mem_avg, zp_cnt);
        info!(
            "ReportResource mem {} handle {} zp_cnt {}",
            mem_avg, fd_avg, zp_cnt
        );
        // let _ = Builder::new_current_thread()
        let _ = Builder::new().basic_scheduler()
            .enable_all()
            .build()
            .unwrap()
            .block_on(requester);
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
        let mut state: String = "".to_string();
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
    use super::*;
    use crate::common::logger::init_test_log;

    #[cfg(unix)]
    #[test]
    fn test_get_zoom_prcesss() {
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

    #[test]
    fn test_get_handle_cnt() {
        init_test_log();
        let fd_cnt_1 = get_handle_cnt();
        let file = std::fs::File::create("test_fd_cnt").unwrap();
        let fd_cnt_2 = get_handle_cnt();
        assert_eq!(1, fd_cnt_2 - fd_cnt_1);
        std::mem::drop(file);
        let _ = std::fs::remove_file("test_fd_cnt");
        let fd_cnt_3 = get_handle_cnt();
        assert_eq!(fd_cnt_3, fd_cnt_1);
    }

    #[cfg(unix)]
    #[test]
    fn test_get_mem_size() {
        use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
        use std::ptr::null_mut;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mem_size_1 = get_mem_size();

        unsafe {
            //do not free _ptr, just for debug
            let _ptr = libc::mmap(
                null_mut(),
                page_size - 100,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut u32;
            *_ptr = 1024; //load in mem
        }

        let mem_size_2 = get_mem_size();
        assert_eq!(mem_size_1 + page_size as u64, mem_size_2);
        unsafe {
            //do not free _ptr, just for debug
            let _ptr = libc::mmap(
                null_mut(),
                page_size - 100,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut u32;
        }

        let mem_size_3 = get_mem_size();
        assert_eq!(mem_size_2 + page_size as u64, mem_size_3)
    }

    #[cfg(windows)]
    #[test]
    fn test_get_mem_size() {
        use std::ptr::null_mut;
        use winapi::um::memoryapi::VirtualAlloc;
        use winapi::um::sysinfoapi::GetSystemInfo;
        use winapi::um::sysinfoapi::SYSTEM_INFO;
        use winapi::um::winnt::{MEM_COMMIT, PAGE_READWRITE};

        let mut info: SYSTEM_INFO = unsafe { mem::zeroed() };
        unsafe {
            GetSystemInfo(&mut info);
        }

        let size = get_mem_size();
        unsafe {
            VirtualAlloc(null_mut(), 4000, MEM_COMMIT, PAGE_READWRITE);
        }

        let size1 = get_mem_size();
        assert_eq!(size + info.dwPageSize as u64, size1);
        print!("");
    }
}
