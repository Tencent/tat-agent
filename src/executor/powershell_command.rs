use crate::daemonizer::wow64_disable_exc;
use crate::executor::proc::{BaseCommand, MyCommand};
use crate::start_failed_err_info;
use async_trait::async_trait;
use codepage_strings::Coding;
use core::mem;
use log::{debug, error, info};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::ffi::OsStr;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Stdio;
use std::ptr::null_mut;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use winapi::shared::winerror::ERROR_ACCESS_DENIED;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::namedpipeapi::CreateNamedPipeW;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winbase::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use winapi::um::winnls::GetOEMCP;
use winapi::um::winnt::HANDLE;

pub struct PowerShellCommand {
    base: Arc<BaseCommand>,
}

impl PowerShellCommand {
    pub fn new(
        cmd_path: &str,
        username: &str,
        work_dir: &str,
        timeout: u64,
        bytes_max_report: u64,
        log_file_path: &str,
        cos_bucket: &str,
        cos_prefix: &str,
        task_id: &str,
    ) -> PowerShellCommand {
        let cmd_path = String::from(cmd_path).replace(" ", "` ");
        PowerShellCommand {
            base: Arc::new(BaseCommand::new(
                cmd_path.as_str(),
                username,
                work_dir,
                timeout,
                bytes_max_report,
                log_file_path,
                cos_bucket,
                cos_prefix,
                task_id,
            )),
        }
    }

    fn work_dir_check(&self) -> Result<(), String> {
        if !wow64_disable_exc(|| Path::new(self.base.work_dir.as_str()).exists()) {
            let ret = format!(
                "PowerShellCommand {} start fail, working_directory:{}, username: {}: working directory not exists",
                self.base.cmd_path, self.base.work_dir, self.base.username
            );
            *self.base.err_info.lock().unwrap() =
                start_failed_err_info!(ERR_WORKING_DIRECTORY_NOT_EXISTS, self.base.work_dir);
            return Err(ret);
        };
        Ok(())
    }

    fn prepare_cmd(&self, theirs: File) -> Result<Command, String> {
        let std_out = theirs.try_clone().map_err(|e| {
            error!("prepare_cmd,clone pipe  std_out fail {}", e);
            e.to_string()
        })?;

        let std_err = theirs.try_clone().map_err(|e| {
            error!("prepare_cmd,clone pipe  std_err fail {}", e);
            e.to_string()
        })?;

        let mut comand = Command::new("PowerShell.exe");
        comand
            .args(&[self.base.cmd_path.as_str()])
            .stdin(Stdio::null())
            .stdout(std_out)
            .stderr(std_err)
            .current_dir(self.base.work_dir.as_str());

        Ok(comand)
    }
}

#[async_trait]
impl MyCommand for PowerShellCommand {
    /* TODO:
    1. support set username
    2. support kill process when cancelled or timout.
    3. support set process group.
     */
    async fn run(&mut self) -> Result<(), String> {
        info!("=>PowerShellCommand::run()");
        // store path check
        self.store_path_check()?;

        // work dir check
        self.work_dir_check()?;

        let log_file = self.open_log_file()?;

        // create pipe
        let (our_pipe, their_pipe) = anon_pipe(true)?;

        // start child
        let mut cmd = self.prepare_cmd(their_pipe)?;
        let mut child = cmd.spawn().map_err(|e| {
            *self.base.err_info.lock().unwrap() = e.to_string();
            format!(
                "PowerShellCommand {}, working_directory:{}, start fail: {}",
                self.base.cmd_path, self.base.work_dir, e
            )
        })?;

        *self.base.pid.lock().unwrap() = Some(child.id());
        let base = self.base.clone();
        info!("=>PowerShellCommand::tokio::spawn");
        // async read output.
        tokio::spawn(async move {
            base.add_timeout_timer();
            base.read_ps1_output(our_pipe, log_file).await;
            base.del_timeout_timer();
            base.process_finish(&mut child).await;
        });
        Ok(())
    }

    fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt(f)
    }
    fn get_base(&self) -> Arc<BaseCommand> {
        self.base.clone()
    }
}

impl BaseCommand {
    async fn read_ps1_output(&self, file: File, mut log_file: File) {
        let pid = self.pid.lock().unwrap().unwrap();
        const BUF_SIZE: usize = 1024;
        let mut buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];

        let mut file = tokio::fs::File::from_std(file);
        let codepage = unsafe { GetOEMCP() };
        loop {
            let size = file.read(&mut buffer[..]).await;
            if size.is_err() {
                error!("read output err:{}, pid:{}", size.unwrap_err(), pid);
                break;
            }
            let len = size.unwrap();
            if len > 0 {
                let decoded_string = Coding::new(codepage as u16)
                    .unwrap()
                    .decode(&buffer[..len])
                    .unwrap();
                debug!("output:[{}], pid:{}, len:{}", decoded_string, pid, len);
                if let Err(e) = log_file.write(decoded_string.as_bytes()) {
                    error!("write output file fail: {:?}", e)
                }
                unsafe {
                    self.append_output(String::from(decoded_string).as_mut_vec());
                }
            } else {
                info!("read output finished normally, pid:{}", pid);
                break;
            }
        }

        if let Err(e) = log_file.sync_all() {
            error!("sync in-memory data to file fail: {:?}", e)
        }

        self.finish_logging().await;
    }

    pub fn kill_process_group(pid: u32) {
        let pid = pid.to_string();
        let mut child = std::process::Command::new("TASKKILL")
            .args(&["/F", "/PID", pid.as_str(), "/T"])
            .spawn()
            .expect("failed kill_process_group");

        child
            .wait()
            .map_err(|_| error!("kill_process_group fail"))
            .ok();
    }
}

impl Debug for PowerShellCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.base.fmt(f)
    }
}

fn anon_pipe(ours_readable: bool) -> Result<(File, File), String> {
    unsafe {
        let mut tries = 0;
        let mut name;
        let ours: File;
        loop {
            tries += 1;
            name = format!(
                r"\\.\pipe\__tat_anon_pipe__.{}.{}",
                GetCurrentProcessId(),
                thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(10)
                    .collect::<String>(),
            );

            let wide_name = OsStr::new(&name)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();

            let mut flags = FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
            if ours_readable {
                flags |= PIPE_ACCESS_INBOUND;
            } else {
                flags |= PIPE_ACCESS_OUTBOUND;
            }

            let handle = CreateNamedPipeW(
                wide_name.as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                let err = GetLastError();
                if tries < 10 {
                    if err == ERROR_ACCESS_DENIED {
                        continue;
                    }
                }
                error!("creat namepipe fail,{}", err);
                return Err(format!("creat namepipe fail,{}", err));
            }
            ours = mem::transmute::<HANDLE, File>(handle);
            break;
        }

        let mut opts = OpenOptions::new();
        opts.write(ours_readable);
        opts.read(!ours_readable);

        let theirs = opts.open(Path::new(&name)).map_err(|e| e.to_string())?;
        Ok((ours, theirs))
    }
}

#[cfg(test)]
mod test {
    use crate::executor::powershell_command::anon_pipe;
    use std::io::{Read, Write};
    #[test]
    fn test() {
        let (mut ours, mut theirs) = anon_pipe(true).unwrap();
        theirs.write("test".as_bytes()).unwrap();
        let mut buffer = [0; 1024];
        let size = ours.read(&mut buffer).unwrap();
        let result = String::from_utf8_lossy(&buffer[0..size]);
        assert_eq!(result, "test".to_string());
        return;
    }
}
