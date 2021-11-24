use std::env;
use std::process::Command;
use std::ptr;
use winapi::shared::minwindef::{DWORD, LPVOID, FALSE};
use winapi::shared::ntdef::NULL;
use winapi::um::winnt::{LPWSTR, PVOID, SERVICE_WIN32_OWN_PROCESS};
use winapi::um::winsvc::*;
use winapi::um::wow64apiset::*;
use winapi::um::synchapi::*;
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::errhandlingapi::GetLastError;
use log::error;

//static var if not start with upper case, cargo build will report warn
static mut HANDLE: SERVICE_STATUS_HANDLE = 0 as SERVICE_STATUS_HANDLE;
static mut TAT_ENTRY: fn() = || {};

fn str2wstr(name: &str) -> Vec<u16> {
    let mut result: Vec<u16> = name.chars().map(|c| c as u16).collect();
    result.push(0);
    result
}

fn create_service_status(current_state: DWORD) -> SERVICE_STATUS {
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    }
}

unsafe extern "system" fn service_main(
    _: DWORD,       // dw_num_services_args
    _: *mut LPWSTR, // lp_service_arg_vectors
) {
    let service_name = str2wstr("TAT_AGENT");
    HANDLE = RegisterServiceCtrlHandlerExW(
        service_name.as_ptr(),
        Some(service_handler),
        ptr::null_mut(),
    );
    std::thread::spawn(TAT_ENTRY);
    let service_status = &mut create_service_status(SERVICE_RUNNING);
    SetServiceStatus(HANDLE, service_status);
}

unsafe extern "system" fn service_handler(
    dw_control: DWORD,
    _: DWORD,
    _: LPVOID,
    _: LPVOID,
) -> DWORD {
    match dw_control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            SetServiceStatus(HANDLE, &mut create_service_status(SERVICE_STOPPED));
            // exit after this function return,void sc report err
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                std::process::exit(0);
            });
        }
        _ => {}
    };
    return 0;
}

fn  try_start_service(entry: fn()) {
    unsafe {
        TAT_ENTRY = entry;
        let service_name = str2wstr("TAT_AGENT");
        let service_table: &[*const SERVICE_TABLE_ENTRYW] = &[
            &SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name.as_ptr(),
                lpServiceProc: Some(service_main),
            },
            ptr::null(),
        ];

        match StartServiceCtrlDispatcherW(*service_table.as_ptr()) {
            0 => {
                TAT_ENTRY();
            }
            _ => {}
        };

        let service_table: &[*const SERVICE_TABLE_ENTRYW] = &[
            &SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name.as_ptr(),
                lpServiceProc: Some(service_main),
            },
            ptr::null(),
        ];
        StartServiceCtrlDispatcherW(*service_table.as_ptr());
        return;
    }
}

fn clean_update_files() {
    wow64_disable_exc(|| {
        Command::new("cmd.exe")
            .args(&[
                "/C",
                "del",
                "C:\\Program Files\\qcloud\\tat_agent\\temp_*.exe",
            ])
            .spawn().map_err(|_|error!("clean_update_files fail")).ok();
    })
}

fn set_work_dir() {
    let exe_path = env::current_exe().unwrap();
    let work_dir = exe_path.parent().unwrap();
    wow64_disable_exc(|| {
        env::set_current_dir(work_dir).map_err(|_| error!("set_work_dir fail")).ok();
    })
}

pub fn wow64_disable_exc<F, T>(func: F) -> T
where
    F: Fn() -> T,
{
    let result: T;
    let mut old: PVOID = NULL;
    unsafe {
        if Wow64DisableWow64FsRedirection(&mut old) != 0 {
            result = func();
            Wow64RevertWow64FsRedirection(old);
        } else {
            result = func();
        };
    }
    result
}

 fn  already_start()->bool {
     unsafe {
         let event_name = str2wstr("Global\\tatsvc");
         CreateEventW(NULL as LPSECURITY_ATTRIBUTES,
                      FALSE,FALSE, event_name.as_ptr());
         //ERROR_ALREADY_EXISTS=183, ERROR_ACCESS_DENIED=05 get these value from vs winerror.h
         let err= GetLastError();
         return  err == 183 || err == 5
     }
}

pub fn daemonize(entry: fn()) {
    clean_update_files();
    set_work_dir();

    if already_start() {
        std::process::exit(183);
    }
    try_start_service(entry);
}
