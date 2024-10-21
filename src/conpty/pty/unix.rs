use super::{execute_stream, PtyExecCallback};
use crate::conpty::{session::PluginComp, PTY_INSPECT_READ};
use crate::executor::unix::{build_envs, prepare_cmd};

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File as StdFile;
use std::io::{Read, Write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::prelude::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::{env, io, ptr};

use anyhow::{anyhow, Context, Result};
use libc::{self, getsid, pid_t, ttyname, uid_t, winsize, STDIN_FILENO, TIOCSCTTY};
use log::{error, info};
use tokio::fs::{metadata, File};
use tokio::process::Command;
use tokio::sync::oneshot::{channel, Sender};
use unix_mode::{is_allowed, Access, Accessor};
use users::os::unix::UserExt;
use users::{get_user_by_name, User};

const LOGIN_SHELL_SUPPORTED: [&str; 4] = ["bash", "zsh", "fish", "tcsh"];

pub struct Pty {
    _kill_on_drop: Sender<()>,
    master: File,
    user: User,
    pid: i32,
}

impl Pty {
    pub async fn new(
        user_name: &str,
        cols: u16,
        rows: u16,
        envs: HashMap<String, String>,
    ) -> Result<Pty> {
        let user = get_user_by_name(user_name).context(format!("user {} not exist", user_name))?;
        let shell_path = user.shell();
        let shell_name = Path::new(shell_path)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("bash"))
            .to_string_lossy()
            .to_string();

        let home_path = user.home_dir().to_str().unwrap_or_else(|| "/tmp");
        let local_envs = build_envs(user_name, home_path, &shell_path.to_string_lossy());
        let (master, slave) = openpty(user.clone(), cols, rows)?;
        let mut cmd = Command::new(&shell_name);
        if LOGIN_SHELL_SUPPORTED.contains(&shell_name.as_str()) {
            cmd.arg("-l");
        }
        unsafe {
            let uid = user.uid();
            let gid = user.primary_group_id();
            cmd.pre_exec(move || {
                audit_setloginuid(uid)?;
                libc::setgid(gid);
                libc::setuid(uid);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP);
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                libc::ioctl(STDIN_FILENO, TIOCSCTTY, 0);
                libc::tcsetpgrp(STDIN_FILENO, libc::getpid());
                Ok(())
            });
        }
        let mut child = cmd
            .stdin(slave.try_clone().expect(""))
            .stdout(slave.try_clone().expect(""))
            .stderr(slave.try_clone().expect(""))
            .envs(local_envs.into_iter().chain(envs))
            .current_dir(home_path)
            .spawn()?;

        let pid = child.id().unwrap() as pid_t;
        let sid = unsafe { getsid(pid) };
        let utmx_type = "LOGIN";
        let tty_name = unsafe {
            let tty_name_c = ttyname(slave.as_raw_fd());
            CStr::from_ptr(tty_name_c).to_string_lossy().to_string()
        };
        call_utmpx(&tty_name, user_name, pid, sid, &utmx_type).await;

        // Kill terminal process when Pty is dropped
        let (send, mut recv) = channel::<()>();
        let user_name = user_name.to_owned();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = child.wait() => {},
                _ = &mut recv => child.kill().await.unwrap_or_default(),
            }
            let _ = child.wait().await; // Release zombie process after kill
            let utmx_type = "EXIT";
            call_utmpx(&tty_name, &user_name, pid, sid, &utmx_type).await;
        });

        return Ok(Pty {
            _kill_on_drop: send,
            master,
            user,
            pid,
        });
    }

    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let size = winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &size) == 0 } {
            return Ok(());
        }
        Err(io::Error::last_os_error())?
    }

    pub async fn get_reader(&self) -> Result<File> {
        self.get_writer().await
    }

    pub async fn get_writer(&self) -> Result<File> {
        Ok(self.master.try_clone().await?)
    }

    pub fn get_cwd(&self) -> PathBuf {
        let pid = self.pid;
        let cwd_path = format!("/proc/{}/cwd", pid);
        if let Ok(path) = std::fs::read_link(&cwd_path) {
            return path;
        };
        "/tmp".into()
    }
}

impl PluginComp {
    pub async fn inspect_access(&self, path: &str, access: u8) -> Result<()> {
        let metadata = metadata(path).await?;
        let user = self.get_user()?;
        let access = match access {
            PTY_INSPECT_READ => Access::Read,
            _ => Access::Write,
        };

        let is_allowed_by = |by| is_allowed(by, access, metadata.st_mode());

        //check owner
        if metadata.st_uid() == user.uid() && is_allowed_by(Accessor::User) {
            return Ok(());
        }

        //check group
        if user.primary_group_id() == metadata.st_gid() && is_allowed_by(Accessor::Group) {
            return Ok(());
        }
        if let Some(groups) = user.groups() {
            for group in groups {
                if group.gid() == metadata.st_gid() && is_allowed_by(Accessor::Group) {
                    return Ok(());
                }
            }
        }

        //check others
        if is_allowed_by(Accessor::Other) {
            return Ok(());
        }

        Err(anyhow!("access denied"))?
    }

    pub fn execute(&self, f: &dyn Fn() -> Result<Vec<u8>>) -> Result<Vec<u8>> {
        let user = self.get_user()?;
        let cwd_path = self.get_cwd(&user);

        unsafe {
            let mut pipefd: [i32; 2] = [0, 0];
            libc::pipe(pipefd.as_mut_ptr());
            let pid = libc::fork();
            if pid == 0 {
                let _ = env::set_current_dir(cwd_path);
                libc::setgid(user.primary_group_id());
                libc::setuid(user.uid());
                let mut stdin = StdFile::from_raw_fd(pipefd[1]);
                match f() {
                    Ok(output) => {
                        let _ = stdin.write_all(&output);
                        libc::exit(0);
                    }
                    Err(e) => {
                        //error!("[child] work_as_user func exit failed: {}", e);
                        let _ = stdin.write_all(e.to_string().as_bytes());
                        libc::exit(1);
                    }
                }
            } else {
                libc::close(pipefd[1]);
                let mut output: Vec<u8> = Vec::new();
                let mut stdout = StdFile::from_raw_fd(pipefd[0]);
                let _ = stdout.read_to_end(&mut output);
                let mut exit_code = 0 as i32;
                libc::waitpid(pid, &mut exit_code, 0);
                if exit_code == 0 {
                    return Ok(output);
                }
                let err_msg = String::from_utf8_lossy(&output).to_string();
                error!("[parent] work_as_user func exit failed: {}", err_msg);
                return Err(anyhow!(err_msg));
            }
        }
    }

    pub async fn execute_stream(
        &self,
        cmd: Command,
        callback: Option<PtyExecCallback>,
        timeout: Option<u64>,
    ) -> Result<()> {
        let user = self.get_user()?;
        let cwd_path = self.get_cwd(&user);
        let cmd = prepare_cmd(cmd, &user, cwd_path);

        let callback = callback.unwrap_or_else(|| Box::new(|_, _, _, _| Box::pin(async {})));
        let timeout = timeout.unwrap_or(60);
        execute_stream(cmd, &callback, timeout).await
    }

    fn get_user(&self) -> Result<User> {
        let user = match self {
            Self::Pty(pty) => pty.user.clone(),
            Self::Nil { username } => {
                get_user_by_name(username).context(format!("user {} not exist", username))?
            }
            _ => Err(anyhow!("unsupported channel plugin"))?,
        };
        Ok(user)
    }

    fn get_cwd(&self, user: &User) -> PathBuf {
        match self {
            Self::Pty(pty) => pty.get_cwd(),
            _ => user.home_dir().to_owned(),
        }
    }
}

fn openpty(user: User, cols: u16, rows: u16) -> Result<(File, StdFile)> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    let mut size = winsize {
        ws_col: cols,
        ws_row: rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    unsafe {
        if 0 != libc::openpty(
            &mut master,
            &mut slave,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        ) {
            return Err(anyhow!("openpty failed: {}", io::Error::last_os_error()));
        };

        libc::fchown(slave, user.uid(), user.primary_group_id());
    }

    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { StdFile::from_raw_fd(slave) };
    Ok((master, slave))
}

async fn call_utmpx(ttyname: &str, username: &str, pid: pid_t, sid: pid_t, ut_type: &str) {
    info!(
        "=>call_utmpx tty:{}, user:{}, pid:{}, sid:{}, type:{}",
        ttyname, username, pid, sid, ut_type
    );
    let current_bin = env::current_exe().expect("current path failed");
    let current_path = current_bin.parent().expect("parent path failed");
    let utmpx_path = format!("{}/utmpx", current_path.to_string_lossy());
    match Command::new(utmpx_path)
        .arg(ttyname)
        .arg(username)
        .arg(pid.to_string())
        .arg(sid.to_string())
        .arg(ut_type)
        .output()
        .await
    {
        Ok(output) => info!(
            "stdout:{}, stderr:{}",
            String::from_utf8_lossy(&output.stdout).escape_debug(),
            String::from_utf8_lossy(&output.stderr).escape_debug(),
        ),
        Err(err) => info!("call_utmpx err:{}", err),
    }
}

fn audit_setloginuid(uid: uid_t) -> io::Result<()> {
    info!("=>audit_setloginuid {}", uid);
    let loginuid = format!("{}", uid);
    let loginuid_path = format!("/proc/self/loginuid");

    let mut file = StdFile::create(loginuid_path)?;
    file.write_all(loginuid.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{common::utils::get_current_username, conpty::session::PluginComp};

    #[tokio::test]
    async fn test_work_as_user() {
        let username = get_current_username();
        let plugin = PluginComp::Nil { username };

        let result = plugin.execute(&|| Ok("foo".to_string().into_bytes()));
        let foo = String::from_utf8_lossy(&result.unwrap()).to_string();
        assert_eq!(foo, "foo");
    }
}
