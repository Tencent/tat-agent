use super::bind::{
    winpty_agent_process, winpty_config_free, winpty_config_new, winpty_config_set_initial_size,
    winpty_conin_name, winpty_conout_name, winpty_error_free, winpty_error_msg, winpty_error_ptr_t,
    winpty_free, winpty_open, winpty_set_size, winpty_spawn, winpty_spawn_config_free,
    winpty_spawn_config_new, winpty_t,
};
use super::parser::{do_parse, AnsiItem, EscapeItem};
use super::{execute_stream, PtyExecCallback};
use crate::common::{str2wsz, wsz2string};
use crate::executor::windows::{anon_pipe, configure_command, kill_process_group, load_envs, User};
use crate::tssh::{session::PluginComp, PTY_FLAG_ENABLE_BLOCK, PTY_INSPECT_WRITE};

use std::ffi::OsStr;
use std::fs::File as StdFile;
use std::io::{Error, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::os::windows::prelude::AsRawHandle;
use std::os::windows::raw::HANDLE;
use std::ptr::null_mut;
use std::sync::Arc;
use std::{mem, ptr};

use anyhow::{anyhow, bail, Result};
use log::{error, info};
use ntapi::ntpsapi::{
    NtResumeProcess, NtSetInformationProcess, ProcessAccessToken, PROCESS_ACCESS_TOKEN,
};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
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

const DEFAULT_WORK_DIR: &str = "C:\\Program Files\\QCloud\\tat_agent\\";

pub struct Pty {
    pty_ptr: Mutex<Box<winpty_t>>,
    writer: File,
    enable_block: bool,
    pub user: Arc<User>,
}

impl Pty {
    pub fn new(username: &str, cols: u16, rows: u16, flag: u32) -> Result<Pty> {
        let (mut pty_ptr, user) = openpty(username, cols, rows)?;
        let writer = unsafe {
            let conin_name = winpty_conin_name(pty_ptr.as_mut());
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
            if conin == INVALID_HANDLE_VALUE {
                let err = Error::last_os_error();
                Err(anyhow!("CreateFileW error: {}", err))?
            }
            StdFile::from_raw_handle(conin)
        };
        Ok(Pty {
            pty_ptr: Mutex::new(pty_ptr),
            writer: File::from_std(writer),
            enable_block: flag & PTY_FLAG_ENABLE_BLOCK != 0,
            user: Arc::new(user),
        })
    }

    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        unsafe {
            winpty_set_size(
                self.pty_ptr.lock().await.as_mut(),
                cols as i32,
                rows as i32,
                ptr::null_mut(),
            );
        }
        Ok(())
    }

    pub async fn get_reader(&self) -> Result<File> {
        unsafe {
            let conin_name = winpty_conout_name(self.pty_ptr.lock().await.as_mut());

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
            }
            let input = StdFile::from_raw_handle(conin);
            let (read_pipe, write_pipe) = anon_pipe(true)?;
            tokio::spawn(async move {
                let mut maker = BlockMarker::new(input, write_pipe);
                maker.work().await;
            });
            return Ok(read_pipe);
        }
    }

    pub async fn get_writer(&self) -> Result<File> {
        Ok(self.writer.try_clone().await?)
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            let pty_ptr = std::mem::take(&mut self.pty_ptr);
            tokio::spawn(async move {
                let process = winpty_agent_process(pty_ptr.lock().await.as_mut()) as HANDLE;
                let pid = GetProcessId(process);
                kill_process_group(pid);
                winpty_free(pty_ptr.lock().await.as_mut());
            });
        }
    }
}

impl PluginComp {
    pub async fn inspect_access(&self, path: &str, access: u8) -> Result<()> {
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
            }
            return Err(anyhow!("access deny"));
        }
    }

    pub fn execute(&self, f: &dyn Fn() -> Result<Vec<u8>>) -> Result<Vec<u8>> {
        unsafe {
            let handle = self.get_user()?.token.as_raw_handle();
            ImpersonateLoggedOnUser(handle);
            let result = f();
            RevertToSelf();
            return result;
        };
    }

    pub async fn execute_stream(
        &self,
        mut cmd: Command,
        callback: Option<PtyExecCallback>,
        timeout: Option<u64>,
    ) -> Result<()> {
        let user = self.get_user()?;
        let mut work_dir = unsafe { wsz2string(get_cwd(user.token.as_raw_handle()).as_ptr()) };
        if work_dir.trim().is_empty() {
            work_dir = DEFAULT_WORK_DIR.to_owned();
        }
        let (receiver, sender) = unsafe { anon_pipe(true)? };
        configure_command(&mut cmd, &user, &work_dir, sender).await?;

        let callback = callback.unwrap_or_else(|| Box::new(|_, _, _, _| Box::pin(async {})));
        let timeout = timeout.unwrap_or(60);
        execute_stream(cmd, &callback, timeout, receiver, &user).await
    }
}

struct BlockMarker {
    readf: File,
    writef: File,
    history: Vec<AnsiItem>,
    state: String,
}

const PS_STATE_INPUT: &str = "0";
const PS_STATE_EXEC: &str = "1";
const BLOCK_MARKER_BUF_SIZE: usize = 4096;

impl BlockMarker {
    fn new(input: StdFile, output: StdFile) -> Self {
        BlockMarker {
            readf: File::from_std(input),
            writef: File::from_std(output),
            history: vec![],
            state: PS_STATE_INPUT.to_string(),
        }
    }

    async fn work(&mut self) {
        let pre_marker = "\u{1b}]1337;PreExecMarker;\u{7}".to_string();
        let _ = self.writef.write(pre_marker.as_bytes()).await;
        let mut buffer = [0u8; BLOCK_MARKER_BUF_SIZE];
        loop {
            match self.readf.read(&mut buffer[..]).await {
                Ok(0) => break info!("pty plain2block read size is 0 close"),
                Ok(size) => {
                    let read_data = String::from_utf8_lossy(&buffer[..size]);
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
                Err(e) => break error!("pty plain2block error: {}", e),
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

fn build_envp(token: HANDLE) -> Vec<u16> {
    let mut envp = Vec::new();
    let env_map = unsafe { load_envs(token) };
    if env_map.is_empty() {
        envp.push(0);
    }
    for (k, v) in env_map {
        let mut kdata = OsStr::new(&k).encode_wide().collect();
        envp.append(&mut kdata);
        envp.push('=' as u16);
        let mut vdata = OsStr::new(&v).encode_wide().collect();
        envp.append(&mut vdata);
        envp.push(0);
    }
    envp.push(0);
    envp
}

fn get_cwd(token: HANDLE) -> Vec<u16> {
    let mut len: DWORD = 1024;
    let mut cwd = vec![0u16; len as usize];
    unsafe {
        GetUserProfileDirectoryW(token, cwd.as_ptr() as LPWSTR, &raw mut len as LPDWORD);
        cwd.set_len(len as usize);
    }
    cwd
}

fn openpty(username: &str, cols: u16, rows: u16) -> Result<(Box<winpty_t>, User)> {
    unsafe {
        let user = User::new(username)?;
        let mut err_ptr: *mut winpty_error_ptr_t = ptr::null_mut();
        let config = winpty_config_new(8u64, err_ptr);
        if config.is_null() {
            let err = wsz2string(winpty_error_msg(err_ptr));
            winpty_error_free(err_ptr);
            bail!(err);
        }

        winpty_config_set_initial_size(config, cols as i32, rows as i32);
        err_ptr = ptr::null_mut();
        let pty_ptr = winpty_open(config, err_ptr);
        winpty_config_free(config);
        if pty_ptr.is_null() {
            let err = wsz2string(winpty_error_msg(err_ptr));
            winpty_error_free(err_ptr);
            bail!(err);
        }

        let cmdline = str2wsz("powershell.exe");
        let envp = build_envp(user.token.as_raw_handle());
        let cwdp = get_cwd(user.token.as_raw_handle());

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
            bail!(err);
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
            bail!(err);
        }

        //change process token
        let mut access_token = PROCESS_ACCESS_TOKEN {
            Token: user.token.as_raw_handle(),
            Thread: 0 as HANDLE,
        };
        let status = NtSetInformationProcess(
            process,
            ProcessAccessToken,
            &raw mut access_token as PVOID,
            mem::size_of::<PROCESS_ACCESS_TOKEN>() as u32,
        );
        info!("NtSetInformationProcess result is {}", status);
        NtResumeProcess(process);

        CloseHandle(process);

        Ok((Box::from_raw(pty_ptr), user))
    }
}
