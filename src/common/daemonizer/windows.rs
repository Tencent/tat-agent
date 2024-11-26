use crate::common::{get_now_secs, str2wsz, wsz2string};

use std::process::{Command, Stdio};
use std::time::Duration;
use std::{mem, ptr};

use log::{error, info};
use ntapi::ntrtl::RtlAdjustPrivilege;
use ntapi::ntseapi::{SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, SE_TCB_PRIVILEGE};
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID, MAKEWORD};
use winapi::shared::ntdef::{NULL, TRUE};
use winapi::shared::winerror::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::synchapi::*;
use winapi::um::winnt::{BOOLEAN, KEY_QUERY_VALUE, KEY_READ, LPWSTR, SERVICE_WIN32_OWN_PROCESS};
use winapi::um::winreg::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE};
use winapi::um::winsock2::{WSAStartup, WSADATA};
use winapi::um::winsvc::*;
use winapi::um::wow64apiset::*;

const IMAGE_STATE_COMPLETE: &str = "IMAGE_STATE_COMPLETE";
const WAIT_STATE_COMPLETE_MAX_TIME: u64 = 60 * 3;

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
    let service_status = &mut create_service_status(SERVICE_RUNNING);
    SetServiceStatus(HANDLE, service_status);
    std::thread::spawn(|| {
        wait_image_state_complete(WAIT_STATE_COMPLETE_MAX_TIME);
        TAT_ENTRY();
    });
}

unsafe extern "system" fn service_handler(
    dw_control: DWORD,
    _: DWORD,
    _: LPVOID,
    _: LPVOID,
) -> DWORD {
    if matches!(dw_control, SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN) {
        SetServiceStatus(HANDLE, &mut create_service_status(SERVICE_STOPPED));
        // exit after this function return, avoid sc report err
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            std::process::exit(0);
        });
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

        if 0 == StartServiceCtrlDispatcherW(*service_table.as_ptr()) {
            wait_image_state_complete(WAIT_STATE_COMPLETE_MAX_TIME);
            TAT_ENTRY()
        };
    }
}

fn clean_update_files() {
    wow64_disable_exc(|| {
        let _ = Command::new("cmd.exe")
            .args(&[
                "/C",
                "del",
                "/f",
                "C:\\Program Files\\qcloud\\tat_agent\\temp_*.*",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .inspect_err(|_| error!("clean_update_files failed"));
    })
}

pub fn wow64_disable_exc<T>(func: impl Fn() -> T) -> T {
    let mut old = NULL;
    if unsafe { Wow64DisableWow64FsRedirection(&mut old) } != 0 {
        let result = func();
        unsafe { Wow64RevertWow64FsRedirection(old) };
        return result;
    }
    func()
}

unsafe fn already_start() -> bool {
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

unsafe fn adjust_privileges() {
    let mut enabled: BOOLEAN = FALSE as u8;
    RtlAdjustPrivilege(
        SE_ASSIGNPRIMARYTOKEN_PRIVILEGE as u32,
        TRUE,
        FALSE as u8,
        &mut enabled,
    );
    RtlAdjustPrivilege(SE_TCB_PRIVILEGE as u32, TRUE, FALSE as u8, &mut enabled);
}

pub fn daemonize(entry: fn()) {
    if unsafe { already_start() } {
        std::process::exit(183);
    }

    // Init Winsock
    let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
    let result = unsafe { WSAStartup(MAKEWORD(2, 2), &raw mut wsa_data) };
    if result != 0 {
        error!("WSAStartup fail,GetLastError {}", unsafe { GetLastError() })
    }

    clean_update_files();
    unsafe { adjust_privileges() };
    try_start_service(entry);
}

// https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-states
unsafe fn read_image_state() -> Option<String> {
    let mut h_key = ptr::null_mut();
    let mut buffer = [0u16; 256];
    let mut buffer_size = (buffer.len() * mem::size_of::<u16>()) as u32;

    RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        str2wsz("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State").as_ptr(),
        0,
        KEY_READ | KEY_QUERY_VALUE,
        &mut h_key,
    );

    RegQueryValueExW(
        h_key,
        str2wsz("ImageState").as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        buffer.as_mut_ptr() as *mut u8,
        &mut buffer_size,
    );
    RegCloseKey(h_key);

    let image_state = wsz2string(buffer.as_ptr());
    return Some(image_state);
}

fn wait_image_state_complete(timeout: u64) {
    info!("wait_image_state");
    let start_time = get_now_secs();
    loop {
        let elapsed = get_now_secs() - start_time;
        if let Some(state) = unsafe { read_image_state() } {
            if elapsed % 10 == 0 {
                info!("current state: {}", state);
            }
            if state == IMAGE_STATE_COMPLETE {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
        if elapsed > timeout {
            info!("wait_image_state timeout");
            break;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::common::daemonizer::windows::IMAGE_STATE_COMPLETE;

    use super::read_image_state;
    #[test]
    fn test_read_image_state() {
        let opt_state = unsafe { read_image_state() };
        assert_eq!(true, opt_state.is_some());
        let state = opt_state.unwrap();
        assert_eq!(state, IMAGE_STATE_COMPLETE)
    }
}
