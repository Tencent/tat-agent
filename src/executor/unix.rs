use crate::executor::proc::Cmd;
use std::collections::HashMap;
use std::fs::{read_to_string, remove_file};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::{env, io};

use anyhow::{anyhow, Context, Result};
use libc::{self, SIGKILL};
use log::warn;
use tokio::process::{Child, Command};
use users::os::unix::UserExt;
use users::{get_user_by_name, User};

impl Cmd {
    fn user_check(&self) -> Result<User> {
        get_user_by_name(&self.username)
            .context("user not exists")
            .inspect_err(|_| {
                *self.err_info.lock().unwrap() =
                    format!("UserNotExists: user `{}` not exists", self.username)
            })
    }

    fn work_dir_check(&self) -> Result<()> {
        if !self.working_directory_exists() {
            *self.err_info.lock().unwrap() = format!(
                "DirectoryNotExists: working_directory `{}` not exists",
                self.work_dir
            );
            return Err(anyhow!("working directory not exists"));
        }
        Ok(())
    }

    fn prepare_cmd(&self, user: User) -> Command {
        let cmd = init_cmd(&self.cmd_path);
        prepare_cmd(cmd, &user, &self.work_dir)
    }

    fn spawn_cmd(&self, user: User) -> Result<Child> {
        let child = self.prepare_cmd(user).spawn().inspect_err(|e| {
            *self.err_info.lock().unwrap() = e.to_string();
            // remove log_file when process run failed.
            let _ = remove_file(self.log_file_path.as_str())
                .inspect_err(|e| warn!("remove log file failed: {}", e));
        })?;
        *self.pid.lock().unwrap() = Some(child.id().unwrap());
        Ok(child)
    }

    pub async fn run(self: &Arc<Self>) -> Result<()> {
        // pre check before spawn cmd
        self.store_path_check()?;
        self.work_dir_check()?;

        let user = self.user_check()?;
        let log_file = self.open_log_file().await?;
        let mut child = self.spawn_cmd(user)?;
        let base = self.clone();
        // async read output.
        tokio::spawn(async move {
            let reader = child.stdout.take().unwrap();
            base.read_output(reader, log_file).await;
            base.process_finish(&mut child).await;
        });
        Ok(())
    }

    fn working_directory_exists(&self) -> bool {
        Path::new(&self.work_dir).exists()
    }
}

pub fn init_cmd(script: &str) -> Command {
    let (shell, _, login_init) = find_shell();
    let entrypoint = format!("{} {}", login_init, script);
    let mut cmd = Command::new(shell);
    cmd.args(&["-c", &entrypoint]);
    cmd
}

pub fn prepare_cmd(mut cmd: Command, user: &User, work_dir: impl AsRef<Path>) -> Command {
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
        libc::kill(pid * -1, SIGKILL);
    }
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
    let Ok(path) = env::var("PATH") else {
        return None;
    };
    path.split(":")
        .map(|p| format!("{}/{}", p, cmd))
        .find(|p| Path::new(p).exists())
}

fn load_envs(content: &str) -> HashMap<String, String> {
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
    let etc_envs = load_envs(read_to_string("/etc/environment").as_deref().unwrap_or(""));
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
        let cmd = Cmd::new("./a.sh", "root", "./", 60, 10240, "", "", "", "");
        println!("fmt cmd:{:?}", cmd);
    }

    #[test]
    fn test_load_envs() {
        let content = "# \n B=b\n D=d=d\n C= \"x\n";
        let envs = load_envs(content);
        assert!(envs.keys().len() == 3);
        assert!(envs.get("B").unwrap() == "b");
        assert!(envs.get("D").unwrap() == "d=d");
        assert!(envs.get("C").unwrap() == " \"x");
    }
}
