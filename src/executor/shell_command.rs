use std::env;
use std::fmt::Debug;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use async_trait::async_trait;
use libc;
use log::{debug, error, info};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use users::get_user_by_name;

use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{DUP2_1_2, OWN_PROCESS_GROUP, TASK_STORE_PATH,PIPE_BUF_DEFAULT_SIZE};
use crate::executor::proc::{BaseCommand, MyCommand};
use crate::start_failed_err_info;

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
    ) -> ShellCommand {
        ShellCommand {
            base: Arc::new(BaseCommand::new(
                cmd_path,
                username,
                work_dir,
                timeout,
                bytes_max_report,
            )),
        }
    }

    fn cmd_path_check(&self) -> Result<(), String> {
        if self.base.cmd_path.is_empty() {
            let ret = format!("ShellCommand start fail because script file store failed.");
            *self.base.err_info.lock().unwrap() =
                start_failed_err_info!(ERR_SCRIPT_FILE_STORE_FAILED, TASK_STORE_PATH);
            return Err(ret);
        }
        Ok(())
    }

    fn sudo_check(&self) -> Result<(), String> {
        if !cmd_exists("sudo") {
            let ret = format!(
                "ShellCommand {} start fail, working_directory:{}, username: {}: sudo not exists",
                self.base.cmd_path, self.base.work_dir, self.base.username
            );
            *self.base.err_info.lock().unwrap() = start_failed_err_info!(ERR_SUDO_NOT_EXISTS);
            return Err(ret);
        }
        Ok(())
    }

    fn user_check(&self) -> Result<(), String> {
        if !user_exists(self.base.username.as_str()) {
            let ret = format!(
                "ShellCommand {} start fail, working_directory:{}, username: {}: user not exists",
                self.base.cmd_path, self.base.work_dir, self.base.username
            );
            *self.base.err_info.lock().unwrap() =
                start_failed_err_info!(ERR_USER_NOT_EXISTS, self.base.username);
            return Err(ret);
        }
        Ok(())
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

    fn work_dir_permission_check(&self) -> Result<(), String> {
        if !working_directory_permission(self.base.work_dir.as_str(), self.base.username.as_str()) {
            let ret = format!(
                "ShellCommand {} start fail, working_directory:{}, username: {}: user has no permission to working_directory.",
                self.base.cmd_path, self.base.work_dir, self.base.username
            );
            *self.base.err_info.lock().unwrap() = start_failed_err_info!(
                ERR_USER_NO_PERMISSION_OF_WORKING_DIRECTORY,
                self.base.username,
                self.base.work_dir
            );
            return Err(ret);
        }
        Ok(())
    }

    fn prepare_cmd(&self) -> Command {
        let mut shell = "sh";
        let mut entrypoint = format!(
            "cd {} && {}",
            self.base.work_dir.as_str(),
            self.base.cmd_path.as_str()
        );
        if cmd_exists("bash") {
            shell = "bash";
            entrypoint = format!(
                ". ~/.bash_profile 2> /dev/null || . ~/.bashrc 2> /dev/null ; {}",
                entrypoint
            );
        }
        let mut cmd = Command::new("sudo");
        cmd.args(&[
            "-Hu",
            self.base.username.as_str(),
            shell,
            "-c",
            entrypoint.as_str(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        // Redirect stderr to stdout, thus the output order will be exactly same with origin
        pre_exec_for_cmd(&mut cmd, DUP2_1_2);
        // The command and its sub-processes will be in an independent process group,
        // thus we can kill them cleanly by kill the whole process group when we need.
        pre_exec_for_cmd(&mut cmd, OWN_PROCESS_GROUP);
        cmd
    }
}

#[async_trait]
impl MyCommand for ShellCommand {
    async fn run(&mut self) -> Result<(), String> {
        // pre check before spawn cmd
        self.cmd_path_check()?;

        self.sudo_check()?;

        self.user_check()?;

        self.work_dir_check()?;

        self.work_dir_permission_check()?;

        // start the process async
        let mut child = self.prepare_cmd().spawn().map_err(|e| {
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
            base.read_shl_output(&mut child).await;
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
    async fn read_shl_output(&self, child: &mut Child) {
        let pid = child.id();
        const BUF_SIZE: usize = 1024;
        let mut buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];
        let stdout = child.stdout.take();
        let mut reader = BufReader::new(stdout.unwrap());
        let mut byte_after_finish = 0;
        loop {
            let process_finish = is_process_finish(pid);
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

fn is_process_finish(pid: u32) -> bool {
    let result = procinfo::pid::stat(pid as i32);
    return match result {
        Ok(stat) => {
            if stat.state == procinfo::pid::State::Zombie {
                true
            } else {
                false
            }
        }
        Err(_) => true,
    };
}

fn pre_exec_for_cmd(cmd: &mut Command, func_name: &str) {
    let func = match func_name {
        DUP2_1_2 => dup2_1_2,
        OWN_PROCESS_GROUP => own_process_group,
        _ => Err("").unwrap_or_exit(
            format!("invalid func_name of pre_exec_for_cmd: {}", func_name).as_str(),
        ),
    };
    unsafe {
        cmd.pre_exec(func);
    }
}

fn working_directory_exists(path: &str) -> bool {
    return Path::new(path).exists();
}

fn working_directory_permission(dir: &str, username: &str) -> bool {
    let ret = std::process::Command::new("sudo")
        .args(&["-u", username, "sh", "-c", "cd", dir])
        .status();
    match ret {
        Ok(status) => return status.success(),
        Err(e) => {
            error!(
                "check working_directory permission err:{}, username:{}, dir: {}",
                e, username, dir
            );
            false
        }
    }
}

fn user_exists(username: &str) -> bool {
    if let None = get_user_by_name(username) {
        return false;
    }
    true
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_cmd() {
        let cmd = ShellCommand::new("./a.sh", "root", "./", 60, 10240);
        println!("fmt cmd:{:?}", cmd);
    }

    #[test]
    fn test_user_exists() {
        assert_eq!(user_exists("root"), true);
        assert_eq!(user_exists("hacker-neo"), false);
    }

    #[test]
    fn test_working_directory_exists() {
        assert_eq!(working_directory_exists("/etc"), true);
        assert_eq!(user_exists("/etcdefg"), false);
    }

    #[test]
    fn test_cmd_exists() {
        assert_eq!(cmd_exists("pwd"), true);
        assert_eq!(cmd_exists("pwd110"), false);
    }
}
