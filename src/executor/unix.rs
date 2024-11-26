use super::task::{Task, TaskInfo};
use crate::EXE_DIR;

use std::collections::HashMap;
use std::env;
use std::fs::Permissions;
use std::io;
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{anyhow, bail, Result};
use tokio::fs::{read_to_string, set_permissions, try_exists};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use users::get_user_by_name;
use users::os::unix::UserExt;

const CMD_TYPE_SHELL: &str = "SHELL";
const EXTENSION_SHELL: &str = "sh";
pub const EXEC_MODE: u32 = 0o755;

pub struct User(users::User);

impl Task {
    pub async fn spawn(&mut self) -> Result<(Child, impl AsyncReadExt + Unpin)> {
        let mut cmd = init_command(&self.info.script_path()?.as_os_str().to_str().unwrap()).await;
        configure_command(&mut cmd, &self.info.user, &self.info.working_directory).await;

        let mut child = cmd.spawn()?;
        let reader = child.stdout.take().unwrap();
        Ok((child, reader))
    }
}

impl TaskInfo {
    pub fn script_extension(&self) -> Result<&'static str> {
        let extension = match self.command_type.as_str() {
            CMD_TYPE_SHELL => EXTENSION_SHELL,
            _ => bail!("invalid `{}` type in Unix.", self.command_type),
        };
        Ok(extension)
    }

    // set permissions for path recursively, to make task-xxx.sh available for non-root user.
    pub async fn set_permissions_recursively(&self) -> Result<()> {
        let perm = Permissions::from_mode(EXEC_MODE);
        for path in PathBuf::from(self.script_path()?).ancestors() {
            if path == *EXE_DIR {
                break;
            }
            set_permissions(path, perm.clone()).await?;
        }
        Ok(())
    }

    pub async fn check_working_directory(&self) -> Result<()> {
        let dir = &self.working_directory;
        match try_exists(dir).await {
            Ok(exist) if exist => Ok(()),
            Ok(_) => bail!("working_directory `{dir}` not exists"),
            Err(e) => bail!("working_directory `{dir}` check failed: `{e}`"),
        }
    }
}

impl User {
    pub fn new(username: &str) -> Result<Self> {
        let user = get_user(username)?;
        Ok(Self(user))
    }
}

pub async fn init_command(script: &str) -> Command {
    let (shell, init_script) = get_available_shell().await;
    let script = format!("{} {}", init_script, script);
    let mut cmd = Command::new(shell);
    cmd.args(&["-c", &script]);
    cmd
}

pub async fn configure_command(cmd: &mut Command, user: &User, work_dir: impl AsRef<Path>) {
    let (shell, _) = get_available_shell().await;
    let home = user.home_dir().to_str().unwrap_or("/tmp").to_owned();
    let envs = load_envs(user.name().to_str().unwrap(), &home, &shell).await;

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
}

pub fn get_user(username: &str) -> Result<users::User> {
    get_user_by_name(username).ok_or(anyhow!("user `{}` not exists", username))
}

async fn get_available_shell() -> (String, &'static str) {
    let bash_init_script =
        ". /etc/profile 2>/dev/null; . ~/.bash_profile 2>/dev/null || . ~/.bashrc 2>/dev/null;";
    match find_program_in_path("bash").await {
        Some(bash) => (bash, bash_init_script),
        None => (find_program_in_path("sh").await.unwrap(), ""),
    }
}

async fn find_program_in_path(program: &str) -> Option<String> {
    let path = env::var("PATH").ok()?;
    for p in path.split(":").map(|path| format!("{}/{}", path, program)) {
        if let Ok(true) = try_exists(&p).await {
            return Some(p);
        }
    }
    None
}

pub async fn load_envs(username: &str, home: &str, shell: &str) -> HashMap<String, String> {
    let envs = [
        ("SHELL", shell),
        ("HOME", home),
        ("USER", username),
        ("LOGNAME", username),
        ("USERNAME", username),
        ("MAIL", &format!("/var/spool/mail/{username}")),
        ("TERM", "xterm-color"),
    ];
    envs.iter()
        .map(|&(k, v)| (k.to_owned(), v.to_owned()))
        .chain(parse_env_file().await)
        .collect()
}

async fn parse_env_file() -> HashMap<String, String> {
    read_to_string("/etc/environment")
        .await
        .unwrap_or_default()
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

fn redirect_stderr_to_stdout() -> Result<(), io::Error> {
    if unsafe { libc::dup2(1, 2) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn own_process_group() -> Result<(), io::Error> {
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub unsafe fn kill_process_group(pid: u32) {
    // send SIGKILL to the process group of pid, note the -1
    // see more details at man 2 kill
    libc::kill(pid as i32 * -1, libc::SIGKILL);
}

pub fn decode_output(v: &[u8]) -> &[u8] {
    // Unix does not need decode
    v
}

impl Deref for User {
    type Target = users::User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
