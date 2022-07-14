use log::info;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use tokio::runtime::Builder;

use crate::{
    common::{consts::ONTIME_LEAK_REPORT_FREQUENCY, envs},
    http::InvokeAPIAdapter,
};

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::{
            fs::{self, File},
            io::BufRead,
            path::Path,
            process,
        };
        use procfs::process::Process;
    } else if #[cfg(windows)] {
        use winapi::um::processthreadsapi::{GetProcessHandleCount, GetCurrentProcess};
        use winapi::um::psapi::{GetProcessMemoryInfo,PROCESS_MEMORY_COUNTERS};
        use std::mem;
    }
}

pub(crate) fn check_resource_leak() {
    static CHECK_CNT: AtomicU64 = AtomicU64::new(0);
    static FD_CNT: AtomicU64 = AtomicU64::new(0);
    static MEM_CNT: AtomicU64 = AtomicU64::new(0);

    let fd_total = FD_CNT.fetch_add(get_handle_cnt(), SeqCst);
    let mem_total = MEM_CNT.fetch_add(get_mem_size(), SeqCst);

    let check_cnt = CHECK_CNT.fetch_add(1, SeqCst);
    if check_cnt != 0 && check_cnt % ONTIME_LEAK_REPORT_FREQUENCY == 0 {
        FD_CNT.store(0, SeqCst);
        MEM_CNT.store(0, SeqCst);

        let fd_avg = (fd_total / ONTIME_LEAK_REPORT_FREQUENCY) as u32;
        let mem_avg = (mem_total / ONTIME_LEAK_REPORT_FREQUENCY) as u32;
        #[cfg(unix)]
        let zp_cnt = get_zoom_prcesss() as u32;
        #[cfg(windows)]
        let zp_cnt = 0 as u32;

        let adapter = InvokeAPIAdapter::build(envs::get_invoke_url().as_str());
        let requester = adapter.report_resource(fd_avg, mem_avg, zp_cnt);
        info!(
            "ReportResource mem {} handle {} zp_cnt {}",
            mem_avg, fd_avg, zp_cnt
        );
        let _ = Builder::new()
            .basic_scheduler()
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
        (mm_info.WorkingSetSize + mm_info.PagefileUsage) as u64
    }
}

#[cfg(unix)]
fn get_handle_cnt() -> u64 {
    let pid = process::id();
    let proc = Process::new(pid as i32).unwrap();
    proc.fd_count().unwrap() as u64
}

#[cfg(unix)]
fn get_mem_size() -> u64 {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let pid = process::id();
    let proc = Process::new(pid as i32).unwrap();
    let statm = proc.statm().unwrap();
    statm.size * page_size as u64
}

#[cfg(unix)]
fn get_zoom_prcesss() -> u32 {
    let pid = process::id() as i32;
    let mut nz: u32 = 0;
    let items = fs::read_dir(Path::new("/proc")).unwrap();
    for item in items {
        if let Ok(entry) = item {
            let entry_path = entry.path();
            if !entry.metadata().unwrap().is_dir() {
                continue;
            }

            let status_path = entry_path.join("status");
            if let Ok(metadata) = fs::metadata(status_path.as_path()) {
                if !metadata.is_file() {
                    continue;
                }
            }

            let mut ppid: Option<i32> = None;
            let mut state: String = "".to_string();
            if let Ok(file) = File::open(status_path) {
                let mut reader = std::io::BufReader::new(file);
                loop {
                    let mut linebuf = String::new();
                    match reader.read_line(&mut linebuf) {
                        Ok(_) => {
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
                        Err(_) => break,
                    }
                }
            }

            if ppid.is_some() && ppid.unwrap() == pid && state.contains("Z") {
                nz = nz + 1;
            }
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
        let mut nz = get_zoom_prcesss();
        assert_eq!(0, nz);
        let mut cmd = Command::new("pwd");
        let mut child = cmd.spawn().unwrap();
        nz = get_zoom_prcesss();
        assert_eq!(1, nz);
        let _ = child.wait();
        nz = get_zoom_prcesss();
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
