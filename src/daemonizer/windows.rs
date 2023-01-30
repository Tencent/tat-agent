use crate::common::utils::str2wsz;
use log::error;
use ntapi::ntrtl::RtlAdjustPrivilege;
use ntapi::ntseapi::{SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, SE_TCB_PRIVILEGE};
use std::process::{Command, Stdio};
use std::ptr;
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID};
use winapi::shared::ntdef::{NULL, TRUE};
use winapi::shared::winerror::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::synchapi::*;
use winapi::um::winnt::{BOOLEAN, LPWSTR, PVOID, SERVICE_WIN32_OWN_PROCESS};
use winapi::um::winsvc::*;
use winapi::um::wow64apiset::*;

static mut HANDLE: SERVICE_STATUS_HANDLE = 0 as SERVICE_STATUS_HANDLE;
static mut TAT_ENTRY: fn() = || {};

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
    let service_name = str2wsz("TAT_AGENT");
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
            // exit after this function return,avoid sc report err
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                std::process::exit(0);
            });
        }
        _ => {}
    };
    return 0;
}

fn try_start_service(entry: fn()) {
    unsafe {
        TAT_ENTRY = entry;
        let service_name = str2wsz("TAT_AGENT");
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
        return;
    }
}

fn clean_update_files() {
    wow64_disable_exc(|| {
        Command::new("cmd.exe")
            .args(&[
                "/C",
                "del",
                "/f",
                "C:\\Program Files\\qcloud\\tat_agent\\temp_*.*",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| error!("clean_update_files fail"))
            .ok();
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

fn already_start() -> bool {
    unsafe {
        let event_name = str2wsz("Global\\tatsvc");
        CreateEventW(
            NULL as LPSECURITY_ATTRIBUTES,
            FALSE,
            FALSE,
            event_name.as_ptr(),
        );
        let err = GetLastError();
        return err == ERROR_ALREADY_EXISTS || err == ERROR_ACCESS_DENIED;
    }
}

fn adjust_privileges() {
    unsafe {
        let mut enabled: BOOLEAN = FALSE as u8;
        RtlAdjustPrivilege(
            SE_ASSIGNPRIMARYTOKEN_PRIVILEGE as u32,
            TRUE,
            FALSE as u8,
            &mut enabled,
        );
        RtlAdjustPrivilege(SE_TCB_PRIVILEGE as u32, TRUE, FALSE as u8, &mut enabled);
    }
}

pub fn daemonize(entry: fn()) {
    if already_start() {
        std::process::exit(183);
    }
    clean_update_files();
    adjust_privileges();
    try_start_service(entry);
}
