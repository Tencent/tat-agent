use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::{env, fmt, io};

use crate::common::consts::PIPE_BUF_DEFAULT_SIZE;
use crate::executor::proc::{self, BaseCommand, MyCommand};
use crate::start_failed_err_info;
use async_trait::async_trait;
use libc;
use log::{debug, error, info};
use procfs::process::Process;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use users::os::unix::UserExt;
use users::{get_user_by_name, User};

pub struct ShellCommand {
    base: Arc<BaseCommand>,
}
impl ShellCommand {
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
    ) -> ShellCommand {
        ShellCommand {
            base: Arc::new(BaseCommand::new(
                cmd_path,
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

    fn user_check(&self) -> Result<User, String> {
        let user = get_user_by_name(self.base.username.as_str());
        return match user {
            Some(user) => Ok(user),
            None => {
                let ret = format!(
                    "ShellCommand {} start fail, working_directory:{}, username: {}: user not exists",
                    self.base.cmd_path, self.base.work_dir, self.base.username
                );
                *self.base.err_info.lock().unwrap() =
                    start_failed_err_info!(ERR_USER_NOT_EXISTS, self.base.username);
                Err(ret)
            }
        };
    }

    fn work_dir_check(&self) -> Result<(), String> {
        if !working_directory_exists(self.base.work_dir.as_str()) {
            let ret = format!(
                "ShellCommand {} start fail, working_directory:{}, username: {}: working directory not exists",
                self.base.cmd_path, self.base.work_dir, self.base.username
            );
            *self.base.err_info.lock().unwrap() =
                start_failed_err_info!(ERR_WORKING_DIRECTORY_NOT_EXISTS, self.base.work_dir);
            return Err(ret);
        }
        Ok(())
    }

    fn prepare_cmd(&self, user: User) -> Command {
        let mut envs = HashMap::new();
        match user.home_dir().to_str() {
            Some(dir) => {
                envs.insert("HOME", dir);
            }
            None => {}
        };
        envs.insert("USER", self.base.username.as_str());
        envs.insert("LOGNAME", self.base.username.as_str());

        let mut shell = "bash";
        let mut login_init = ". ~/.bash_profile 2> /dev/null || . ~/.bashrc 2> /dev/null ; ";
        if !cmd_exists(shell) {
            shell = "sh";
            login_init = "";
        };
        let entrypoint = format!("{}{}", login_init, self.base.cmd_path());

        let mut cmd = Command::new(shell);
        cmd.args(&["-c", entrypoint.as_str()])
            .uid(user.uid())
            .gid(user.primary_group_id())
            .current_dir(self.base.work_dir.clone())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(envs);

        unsafe {
            // Redirect stderr to stdout, thus the output order will be exactly same with origin
            cmd.pre_exec(dup2_1_2);
            // The command and its sub-processes will be in an independent process group,
            // thus we can kill them cleanly by kill the whole process group when we need.
            cmd.pre_exec(own_process_group);
        }
        cmd
    }
}

#[async_trait]
impl MyCommand for ShellCommand {
    async fn run(&mut self) -> Result<(), String> {
        // pre check before spawn cmd
        self.store_path_check()?;

        self.work_dir_check()?;

        let user = self.user_check()?;

        let log_file = self.open_log_file()?;

        // start the process async
        let mut child = self.prepare_cmd(user).spawn().map_err(|e| {
            *self.base.err_info.lock().unwrap() = e.to_string();
            format!(
                "ShellCommand {}, working_directory:{}, start fail: {}",
                self.base.cmd_path, self.base.work_dir, e
            )
        })?;

        *self.base.pid.lock().unwrap() = Some(child.id());
        let base = self.base.clone();
        // async read output.
        tokio::spawn(async move {
            base.add_timeout_timer();
            base.read_shl_output(&mut child, log_file).await;
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

impl Debug for ShellCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.base.fmt(f)
    }
}

impl BaseCommand {
    async fn read_shl_output(&self, child: &mut Child, mut log_file: File) {
        let pid = child.id();
        const BUF_SIZE: usize = 1024;
        let mut buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];
        let stdout = child.stdout.take();
        let mut reader = BufReader::new(stdout.unwrap());
        let mut byte_after_finish = 0;
        let proc = match Process::new(pid as i32) {
            Ok(proc)=> proc,
            Err(_)=>  return ,
        };
        loop {
            let process_finish = !proc.is_alive();
            let timeout_read =
                timeout(Duration::from_millis(100), reader.read(&mut buffer[..])).await;

            if timeout_read.is_err() {
                if process_finish {
                    info!("read time out ,and process already finish,break");
                    break;
                }
                continue;
            }

            let read_size = timeout_read.unwrap();
            if read_size.is_err() {
                error!("read output err:{} , pid:{}", read_size.unwrap_err(), pid);
                break;
            }

            let len = read_size.unwrap();
            if len > 0 {
                if let Err(e) = log_file.write(&buffer) {
                    error!("write output file fail: {:?}", e)
                }

                if process_finish {
                    byte_after_finish = byte_after_finish + len
                }
                debug!(
                    "output:[{}], may_contain_binary:{}, pid:{}, len:{}",
                    String::from_utf8_lossy(&buffer[..len]),
                    String::from_utf8(Vec::from(&buffer[..len])).is_err(),
                    pid,
                    len
                );
                // type convert
                let mut new_out: Vec<u8> = Vec::from(&buffer[..len]);
                self.append_output(&mut new_out);
                if process_finish && len < BUF_SIZE {
                    info!("process finish and len < BUF_SIZE,break");
                    break;
                }
            } else {
                info!("read output finished normally, pid:{}", pid);
                break;
            }
            if process_finish && byte_after_finish > PIPE_BUF_DEFAULT_SIZE {
                info!("byte_after_finish > PIPE_BUF_DEFAULT_SIZE,break");
                break;
            }
        }

        if let Err(e) = log_file.sync_all() {
            error!("sync in-memory data to file fail: {:?}", e)
        }

        self.finish_logging().await;
    }

    pub fn kill_process_group(pid: u32) {
        let pid = pid as i32;
        unsafe {
            // send SIGKILL to the process group of pid, note the -1
            // see more details at man 2 kill
            libc::kill(pid * -1, 9);
        }
    }
}

fn working_directory_exists(path: &str) -> bool {
    return Path::new(path).exists();
}

fn dup2_1_2() -> Result<(), io::Error> {
    unsafe {
        if libc::dup2(1, 2) != -1 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn own_process_group() -> Result<(), io::Error> {
    unsafe {
        if libc::setpgid(0, 0) == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn cmd_exists(cmd: &str) -> bool {
    if let Ok(path) = env::var("PATH") {
        for p in path.split(":") {
            let p_str = format!("{}/{}", p, cmd);
            if Path::new(&p_str).exists() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_cmd() {
        let cmd = ShellCommand::new("./a.sh", "root", "./", 60, 10240, "", "", "", "");
        println!("fmt cmd:{:?}", cmd);
    }

    #[test]
    fn test_working_directory_exists() {
        assert_eq!(working_directory_exists("/etc"), true);
    }
}
