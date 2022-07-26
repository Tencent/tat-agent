use crate::common::strwsz::{str2wsz, wsz2string};
use crate::conpty::bind::{
    winpty_agent_process, winpty_config_free, winpty_config_new, winpty_config_set_initial_size,
    winpty_conin_name, winpty_conout_name, winpty_error_free, winpty_error_msg, winpty_error_ptr_t,
    winpty_free, winpty_open, winpty_set_size, winpty_spawn, winpty_spawn_config_free,
    winpty_spawn_config_new, winpty_t,
};
use crate::conpty::{PtySession, PtySystem};
use crate::executor::powershell_command::{get_user_token, load_environment};
use crate::executor::proc::BaseCommand;
use log::info;
use ntapi::ntpsapi::{
    NtResumeProcess, NtSetInformationProcess, ProcessAccessToken, PROCESS_ACCESS_TOKEN,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::os::windows::prelude::AsRawHandle;
use std::os::windows::raw::HANDLE;
use std::sync::{Arc, Mutex};
use std::{mem, ptr};
use winapi::shared::minwindef::{DWORD, LPDWORD};
use winapi::shared::ntdef::{LPCWSTR, NULL};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::CloseHandle;
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::GetProcessId;
use winapi::um::userenv::GetUserProfileDirectoryW;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, LPWSTR, PVOID,
};

struct Inner {
    pty_ptr: Arc<Mutex<Box<winpty_t>>>,
}

fn build_envp(token: HANDLE) -> Vec<u16> {
    let mut envp: Vec<u16> = Vec::new();
    let mut env_map: HashMap<String, String> = HashMap::new();

    load_environment(token, &mut env_map);
    if env_map.is_empty() {
        envp.push(0);
    } else {
        for (k, v) in env_map {
            let mut kdata = OsStr::new(&k).encode_wide().collect::<Vec<_>>();
            envp.append(&mut kdata);
            envp.push('=' as u16);
            let mut vdata = OsStr::new(&v).encode_wide().collect::<Vec<_>>();
            envp.append(&mut vdata);
            envp.push(0);
        }
    }
    envp.push(0);
    envp
}

fn get_cwd(token: HANDLE) -> Vec<u16> {
    unsafe {
        let mut len: DWORD = 1024;
        let mut cwd: Vec<u16> = Vec::new();
        cwd.resize(len as usize, 0);
        GetUserProfileDirectoryW(token, cwd.as_ptr() as LPWSTR, &mut len as LPDWORD);
        cwd.set_len(len as usize);
        cwd
    }
}

fn openpty(token: HANDLE, cols: u16, rows: u16) -> Result<Inner, String> {
    unsafe {
        let mut err_ptr: *mut winpty_error_ptr_t = ptr::null_mut();
        let config = winpty_config_new(8u64, err_ptr);
        if config.is_null() {
            let err = wsz2string(winpty_error_msg(err_ptr));
            winpty_error_free(err_ptr);
            return Err(err);
        }

        winpty_config_set_initial_size(config, cols as i32, rows as i32);
        err_ptr = ptr::null_mut();
        let pty_ptr = winpty_open(config, err_ptr);
        winpty_config_free(config);
        if pty_ptr.is_null() {
            let err = wsz2string(winpty_error_msg(err_ptr));
            winpty_error_free(err_ptr);
            return Err(err);
        }

        let cmdline = str2wsz("powershell.exe");
        let envp = build_envp(token);
        let cwdp = get_cwd(token);

        let spawn_config = winpty_spawn_config_new(
            3u64,
            ptr::null_mut(),
            cmdline.as_ptr(),
            cwdp.as_ptr(),
            envp.as_ptr(),
            err_ptr,
        );
        if spawn_config.is_null() {
            let err = wsz2string(winpty_error_msg(err_ptr));
            winpty_error_free(err_ptr);
            return Err(err);
        }

        err_ptr = ptr::null_mut();
        let mut process: HANDLE = 0 as HANDLE;
        let succ = winpty_spawn(
            pty_ptr,
            spawn_config,
            &mut process,
            ptr::null_mut::<_>(),
            ptr::null_mut::<u32>(),
            err_ptr,
        );
        winpty_spawn_config_free(spawn_config);
        if !succ {
            let err = wsz2string(winpty_error_msg(err_ptr));
            winpty_error_free(err_ptr);
            return Err(err);
        }

        //change process token
        let mut access_token = PROCESS_ACCESS_TOKEN {
            Token: token as HANDLE,
            Thread: 0 as HANDLE,
        };
        let status = NtSetInformationProcess(
            process,
            ProcessAccessToken,
            &mut access_token as *mut PROCESS_ACCESS_TOKEN as PVOID,
            mem::size_of::<PROCESS_ACCESS_TOKEN>() as u32,
        );
        info!("NtSetInformationProcess result is {}", status);
        NtResumeProcess(process);

        CloseHandle(process);

        Ok(Inner {
            pty_ptr: Arc::new(Mutex::new(Box::from_raw(pty_ptr))),
        })
    }
}

#[derive(Default)]
pub struct ConPtySystem {}

impl PtySystem for ConPtySystem {
    fn openpty(
        &self,
        user_name: &str,
        cols: u16,
        rows: u16,
        _flag: u32,
    ) -> Result<Arc<dyn PtySession + Send + Sync>, String> {
        let token = get_user_token(user_name)?;
        let inner = openpty(token.as_raw_handle(), cols, rows)?;
        let session = Arc::new(WinPtySession {
            inner: Arc::new(Mutex::new(inner)),
        });
        Ok(session)
    }
}

pub struct WinPtySession {
    inner: Arc<Mutex<Inner>>,
}

impl PtySession for WinPtySession {
    fn resize(&self, cols: u16, rows: u16) -> Result<(), String> {
        unsafe {
            let err_ptr: *mut winpty_error_ptr_t = ptr::null_mut();
            winpty_set_size(
                self.inner.lock().unwrap().pty_ptr.lock().unwrap().as_mut(),
                cols as i32,
                rows as i32,
                err_ptr,
            );
        }
        return Ok(());
    }

    fn get_reader(&self) -> Result<std::fs::File, std::string::String> {
        unsafe {
            let conin_name =
                winpty_conout_name(self.inner.lock().unwrap().pty_ptr.lock().unwrap().as_mut());

            let empty_handle = 0 as HANDLE;
            let conin = CreateFileW(
                conin_name as LPCWSTR,
                FILE_GENERIC_READ,
                0,
                NULL as LPSECURITY_ATTRIBUTES,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                empty_handle,
            );
            return Ok(File::from_raw_handle(conin));
        }
    }

    fn get_writer(&self) -> Result<std::fs::File, std::string::String> {
        unsafe {
            let conin_name =
                winpty_conin_name(self.inner.lock().unwrap().pty_ptr.lock().unwrap().as_mut());

            let empty_handle = 0 as HANDLE;
            let conin = CreateFileW(
                conin_name as LPWSTR,
                FILE_GENERIC_WRITE,
                0,
                NULL as LPSECURITY_ATTRIBUTES,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                empty_handle,
            );
            return Ok(File::from_raw_handle(conin));
        }
    }
}

impl Drop for WinPtySession {
    fn drop(&mut self) {
        unsafe {
            let process =
                winpty_agent_process(self.inner.lock().unwrap().pty_ptr.lock().unwrap().as_mut())
                    as HANDLE;
            let pid = GetProcessId(process);
            BaseCommand::kill_process_group(pid);
            winpty_free(self.inner.lock().unwrap().pty_ptr.lock().unwrap().as_mut());
        }
    }
}
