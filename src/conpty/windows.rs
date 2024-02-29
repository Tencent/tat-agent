use super::gather::PtyGather;
use super::parser::{do_parse, AnsiItem, EscapeItem};
use super::{
    PtyAdapter, PtyBase, PtyExecCallback, PtyResult, PTY_FLAG_ENABLE_BLOCK, PTY_INSPECT_WRITE,
};
use crate::common::utils::{str2wsz, wsz2string};
use crate::conpty::bind::{
    winpty_agent_process, winpty_config_free, winpty_config_new, winpty_config_set_initial_size,
    winpty_conin_name, winpty_conout_name, winpty_error_free, winpty_error_msg, winpty_error_ptr_t,
    winpty_free, winpty_open, winpty_set_size, winpty_spawn, winpty_spawn_config_free,
    winpty_spawn_config_new, winpty_t,
};
use crate::executor::proc::BaseCommand;
use crate::executor::windows::{anon_pipe, get_user_token, load_environment};

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::os::windows::prelude::AsRawHandle;
use std::os::windows::raw::HANDLE;
use std::process::Command;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{mem, ptr};

use log::{error, info};
use ntapi::ntpsapi::{
    NtResumeProcess, NtSetInformationProcess, ProcessAccessToken, PROCESS_ACCESS_TOKEN,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use winapi::shared::minwindef::{DWORD, LPDWORD};
use winapi::shared::ntdef::{LPCWSTR, NULL};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::GetProcessId;
use winapi::um::securitybaseapi::{ImpersonateLoggedOnUser, RevertToSelf};
use winapi::um::userenv::GetUserProfileDirectoryW;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, LPWSTR, PVOID,
};

struct Inner {
    pty_ptr: Arc<Mutex<Box<winpty_t>>>,
    token: Arc<File>,
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
    let mut len: DWORD = 1024;
    let mut cwd = vec![0u16; len as usize];
    unsafe {
        GetUserProfileDirectoryW(token, cwd.as_ptr() as LPWSTR, &mut len as LPDWORD);
        cwd.set_len(len as usize);
    }
    cwd
}

fn openpty(user_name: &str, cols: u16, rows: u16) -> PtyResult<Inner> {
    unsafe {
        let token = get_user_token(user_name)?;
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
        let envp = build_envp(token.as_raw_handle());
        let cwdp = get_cwd(token.as_raw_handle());

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
            Token: token.as_raw_handle(),
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
            token: Arc::new(token),
        })
    }
}

#[derive(Default)]
pub struct ConPtyAdapter {}

impl PtyAdapter for ConPtyAdapter {
    fn openpty(
        &self,
        user_name: &str,
        cols: u16,
        rows: u16,
        flag: u32,
    ) -> PtyResult<Arc<dyn PtyBase + Send + Sync>> {
        let inner = openpty(user_name, cols, rows)?;
        let session = Arc::new(WinPtySession {
            inner: Arc::new(Mutex::new(inner)),
            enable_block: flag & PTY_FLAG_ENABLE_BLOCK != 0,
        });
        Ok(session)
    }
}

pub struct WinPtySession {
    inner: Arc<Mutex<Inner>>,
    enable_block: bool,
}

impl PtyBase for WinPtySession {
    fn resize(&self, cols: u16, rows: u16) -> PtyResult<()> {
        let err_ptr: *mut winpty_error_ptr_t = ptr::null_mut();
        unsafe {
            winpty_set_size(
                self.inner.lock().unwrap().pty_ptr.lock().unwrap().as_mut(),
                cols as i32,
                rows as i32,
                err_ptr,
            );
        }
        return Ok(());
    }

    fn get_reader(&self) -> PtyResult<File> {
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

            if !self.enable_block {
                return Ok(File::from_raw_handle(conin));
            } else {
                let input = File::from_raw_handle(conin);
                let (read_pipe, write_pipe) = anon_pipe(true)?;
                PtyGather::runtime().spawn(async move {
                    let mut maker = BlockMarker::new(input, write_pipe);
                    maker.work().await;
                });
                return Ok(read_pipe);
            }
        }
    }

    fn get_writer(&self) -> PtyResult<File> {
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

    fn get_pid(&self) -> PtyResult<u32> {
        unsafe {
            let process =
                winpty_agent_process(self.inner.lock().unwrap().pty_ptr.lock().unwrap().as_mut())
                    as HANDLE;
            let pid = GetProcessId(process);
            return Ok(pid);
        }
    }

    fn inspect_access(&self, path: &str, access: u8) -> PtyResult<()> {
        unsafe {
            let desired_access = if access == PTY_INSPECT_WRITE {
                FILE_GENERIC_WRITE
            } else {
                FILE_GENERIC_READ
            };

            let file_name = str2wsz(path);
            let handle = CreateFileW(
                file_name.as_ptr() as LPCWSTR,
                desired_access,
                FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            );

            if handle != INVALID_HANDLE_VALUE {
                CloseHandle(handle);
                return Ok(());
            } else {
                return Err("access deny".to_string());
            }
        }
    }

    fn execute(&self, f: &dyn Fn() -> PtyResult<Vec<u8>>) -> PtyResult<Vec<u8>> {
        unsafe {
            let handle = self.inner.lock().unwrap().token.as_raw_handle();
            ImpersonateLoggedOnUser(handle);
            let result = f();
            RevertToSelf();
            return result;
        };
    }

    fn execute_stream(
        &self,
        _cmd: Command,
        _callback: Option<PtyExecCallback>,
        _timeout: Option<u64>,
    ) -> PtyResult<()> {
        // Windows system not supported currently.
        todo!()
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

struct BlockMarker {
    readf: tokio::fs::File,
    writef: tokio::fs::File,
    history: Vec<AnsiItem>,
    state: String,
}

const PS_STATE_INPUT: &str = "0";
const PS_STATE_EXEC: &str = "1";

impl BlockMarker {
    fn new(input: File, output: File) -> Self {
        BlockMarker {
            readf: tokio::fs::File::from_std(input),
            writef: tokio::fs::File::from_std(output),
            history: vec![],
            state: PS_STATE_INPUT.to_string(),
        }
    }

    async fn work(&mut self) {
        let duration = Duration::from_millis(100);
        let pre_marker = "\u{1b}]1337;PreExecMarker;\u{7}".to_string();
        let _ = self.writef.write(pre_marker.as_bytes()).await;

        loop {
            let mut buffer: [u8; 4096] = [0; 4096];
            let read_fut = self.readf.read(&mut buffer[..]);
            let timeout_read = timeout(duration, read_fut).await;
            if timeout_read.is_err() {
                continue; //timeout
            }

            match timeout_read.unwrap() {
                Ok(0) => break info!("pty session plain2block read size is 0 close"),
                Ok(size) => {
                    let read_data = String::from_utf8_lossy(&buffer[0..size]);
                    let sequences = do_parse(&read_data);
                    let mut output: Vec<u8> = Vec::new();
                    for it in sequences {
                        info!("item: {}", it.to_string());
                        match self.state.as_str() {
                            PS_STATE_INPUT => self.input_handler(it, &mut output).await,
                            PS_STATE_EXEC => self.exec_handler(it, &mut output).await,
                            _ => continue,
                        }
                    }
                    let _ = self.writef.write(&output).await;
                }
                Err(e) => break error!("pty session plain2block error: {}", e),
            }
        }
    }

    async fn input_handler(&mut self, item: AnsiItem, output: &mut Vec<u8>) {
        let _ = Write::write(output, item.to_string().as_bytes());
        if let AnsiItem::Text(data) = &item {
            if data.eq("\r\n")
                && self.history.last().unwrap().to_string() == EscapeItem::HideCursor.to_string()
            {
                self.state = PS_STATE_EXEC.to_owned();
                let pre_marker = "\u{1b}]1337;PreExecMarker;\u{7}".to_string();
                let _ = Write::write(output, pre_marker.as_bytes());
                return;
            }
            if data.starts_with("\rPS ") && data.ends_with("> ") {
                let input_marker = "\u{1b}]1337;InputMarker;\u{7}".to_string();
                let _ = Write::write(output, input_marker.as_bytes());
            }
        }
        self.save_history(item);
    }

    async fn exec_handler(&mut self, item: AnsiItem, output: &mut Vec<u8>) {
        if let AnsiItem::Text(data) = &item {
            if (data.starts_with("\r\nPS ") || data.starts_with("PS ")) && data.ends_with(">") {
                let pwd = &data[3..data.len() - 2].to_string();
                let post_marker = format!("\u{1b}]1337;PostExecMarker;CurrentDir={}\u{7}", pwd);
                let _ = Write::write(output, post_marker.as_bytes());
                self.state = PS_STATE_INPUT.to_owned();
            }
        }
        let _ = Write::write(output, item.to_string().as_bytes());
        self.save_history(item);
        return;
    }

    fn save_history(&mut self, item: AnsiItem) {
        if self.history.len() > 5 {
            self.history.remove(0);
        }
        self.history.push(item);
    }
}
