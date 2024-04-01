use crate::executor::proc::{BaseCommand, MyCommand};
use std::collections::HashMap;
use std::fs::{read_to_string, remove_file};
use std::ops::Deref;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::{env, io};

use async_trait::async_trait;
use libc;
use log::warn;
use tokio::process::{Child, Command};
use users::os::unix::UserExt;
use users::{get_user_by_name, User};

pub struct UnixCommand {
    base: Arc<BaseCommand>,
}

impl UnixCommand {
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
    ) -> UnixCommand {
        UnixCommand {
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
        let user = get_user_by_name(self.username.as_str());
        match user {
            Some(user) => Ok(user),
            None => {
                let ret = format!(
                    "UnixCommand {} start failed, working_directory: {}, username: {}, user not exists",
                    self.cmd_path, self.work_dir, self.username
                );
                *self.err_info.lock().unwrap() =
                    format!("UserNotExists: user `{}` not exists", self.username);
                Err(ret)
            }
        }
    }

    fn work_dir_check(&self) -> Result<(), String> {
        if !working_directory_exists(self.work_dir.as_str()) {
            let ret = format!(
                "UnixCommand {} start failed, working_directory: {}, username: {}, working directory not exists",
                self.cmd_path, self.work_dir, self.username
            );
            *self.err_info.lock().unwrap() = format!(
                "DirectoryNotExists: working_directory `{}` not exists",
                self.work_dir
            );
            return Err(ret);
        }
        Ok(())
    }

    fn prepare_cmd(&self, user: User) -> Command {
        let cmd = init_cmd(&self.cmd_path);
        prepare_cmd(cmd, &user, &self.work_dir)
    }

    fn spawn_cmd(&self, user: User) -> Result<Child, String> {
        let child = self.prepare_cmd(user).spawn().map_err(|e| {
            *self.err_info.lock().unwrap() = e.to_string();
            // remove log_file when process run failed.
            if let Err(e) = remove_file(self.log_file_path.as_str()) {
                warn!("remove log file failed: {:?}", e)
            }
            format!(
                "UnixCommand {}, working_directory: {}, start failed: {}",
                self.cmd_path, self.work_dir, e
            )
        })?;
        // *self.pid.lock().unwrap() = Some(child.id().unwrap());
        *self.pid.lock().unwrap() = Some(child.id());
        Ok(child)
    }
}

#[async_trait]
impl MyCommand for UnixCommand {
    async fn run(&mut self) -> Result<(), String> {
        // pre check before spawn cmd
        self.store_path_check()?;
        self.work_dir_check()?;

        let user = self.user_check()?;
        let log_file = self.open_log_file()?;
        let mut child = self.spawn_cmd(user)?;
        let base = self.base.clone();
        // async read output.
        tokio::spawn(async move {
            let reader = child.stdout.take().unwrap();
            base.read_output(reader, log_file).await;
            base.process_finish(&mut child).await;
        });
        Ok(())
    }
}

#[cfg(test)]
impl std::fmt::Debug for UnixCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.base.fmt(f)
    }
}

impl Deref for UnixCommand {
    type Target = BaseCommand;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

pub fn init_cmd(script: &str) -> Command {
    let (shell, _, login_init) = find_shell();
    let entrypoint = format!("{} {}", login_init, script);
    let mut cmd = Command::new(shell);
    cmd.args(&["-c", &entrypoint]);
    cmd
}

pub fn prepare_cmd(mut cmd: Command, user: &User, work_dir: &str) -> Command {
    // let shell_path = cmd_path(cmd.as_std().get_program())
    let (_, shell_path, _) = find_shell();
    let home_path = user.home_dir().to_str().unwrap_or("/tmp").to_owned();
    let envs = build_envs(user.name().to_str().unwrap(), &home_path, &shell_path);

    cmd.uid(user.uid())
        .gid(user.primary_group_id())
        .current_dir(work_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(envs);
    unsafe {
        // Redirect stderr to stdout, thus the output order will be exactly same with origin
        cmd.pre_exec(redirect_stderr_to_stdout);
        // The command and its sub-processes will be in an independent process group,
        // thus we can kill them cleanly by kill the whole process group when we need.
        cmd.pre_exec(own_process_group);
    }
    cmd
}

pub fn kill_process_group(pid: u32) {
    let pid = pid as i32;
    unsafe {
        // send SIGKILL to the process group of pid, note the -1
        // see more details at man 2 kill
        libc::kill(pid * -1, 9);
    }
}

fn working_directory_exists(path: &str) -> bool {
    Path::new(path).exists()
}

fn redirect_stderr_to_stdout() -> Result<(), io::Error> {
    if unsafe { libc::dup2(1, 2) } != -1 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn own_process_group() -> Result<(), io::Error> {
    if unsafe { libc::setpgid(0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn cmd_path(cmd: &str) -> Option<String> {
    if let Ok(path) = env::var("PATH") {
        for p in path.split(":") {
            let p_str = format!("{}/{}", p, cmd);
            if Path::new(&p_str).exists() {
                return Some(p_str);
            }
        }
    }
    None
}

fn load_envs(content: String) -> HashMap<String, String> {
    content
        .lines()
        .map(|l| l.trim_start())
        .filter(|l| !(l.starts_with('#') || l.is_empty()))
        .map(|l| l.strip_prefix("export ").unwrap_or(l))
        .map_while(|l| l.split_once('='))
        .map(|(k, mut v)| {
            if v.starts_with('"') && v.ends_with('"') || v.starts_with("'") && v.ends_with("'") {
                v = &v[1..v.len() - 1]
            }
            (k.trim_start().to_owned(), v.to_owned())
        })
        .collect()
}

pub fn build_envs(username: &str, home_path: &str, shell_path: &str) -> HashMap<String, String> {
    let envs = [
        ("SHELL", shell_path),
        ("HOME", home_path),
        ("USER", username),
        ("LOGNAME", username),
        ("USERNAME", username),
        ("MAIL", &format!("/var/spool/mail/{username}")),
        ("TERM", "xterm-color"),
    ];
    let etc_envs = load_envs(read_to_string("/etc/environment").unwrap_or("".to_owned()));
    envs.iter()
        .map(|&(k, v)| (k.to_owned(), v.to_owned()))
        .chain(etc_envs)
        .collect()
}

pub fn find_shell() -> (String, String, String) {
    let bash_login_init =
        ". /etc/profile 2> /dev/null; . ~/.bash_profile 2> /dev/null || . ~/.bashrc 2> /dev/null;";
    let (shell, shell_path, login_init) = cmd_path("bash")
        .map(|p| ("bash".to_owned(), p, bash_login_init.to_owned()))
        .unwrap_or_else(|| ("sh".to_owned(), cmd_path("sh").unwrap(), "".to_owned()));
    (shell, shell_path, login_init)
}

pub fn decode_output(v: &[u8]) -> &[u8] {
    // Unix does not need decode
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_cmd() {
        let cmd = UnixCommand::new("./a.sh", "root", "./", 60, 10240, "", "", "", "");
        println!("fmt cmd:{:?}", cmd);
    }

    #[test]
    fn test_working_directory_exists() {
        assert_eq!(working_directory_exists("/etc"), true);
    }

    #[test]
    fn test_load_envs() {
        let content = "# \n B=b\n D=d=d\n C= \"x\n";
        let envs = load_envs(content.to_string());
        assert!(envs.keys().len() == 3);
        assert!(envs.get("B").unwrap() == "b");
        assert!(envs.get("D").unwrap() == "d=d");
        assert!(envs.get("C").unwrap() == " \"x");
    }
}
