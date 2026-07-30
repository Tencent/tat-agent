use super::{PtyExecCallback, execute_stream};
use crate::EXE_DIR;
use crate::executor::unix::{User, configure_command, init_command, load_envs};
use crate::network::types::ws_msg::Program;
use crate::tssh::{PTY_INSPECT_READ, session::PluginComp};

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File as StdFile;
use std::io::{Read, Write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::prelude::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::{env, io, ptr};

use anyhow::{Result, bail};
use libc::{self, STDIN_FILENO, TIOCSCTTY, getsid, pid_t, ttyname, uid_t, winsize};
use log::{error, info};
use tokio::fs::metadata;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::process::Command;
use tokio::sync::oneshot::{Sender, channel};
use unix_mode::{Access, Accessor, is_allowed};
use uzers::os::unix::UserExt;

const LOGIN_SHELL_SUPPORTED: [&str; 4] = ["bash", "zsh", "fish", "tcsh"];

pub struct Pty {
    _kill_on_drop: Sender<()>,
    master: Arc<AsyncFd<OwnedFd>>,
    pid: i32,
    pub user: Arc<User>,
}

impl Pty {
    pub async fn new(
        username: &str,
        cols: u16,
        rows: u16,
        envs: &HashMap<String, String>,
        prog: &Option<Program>,
        cwd: Option<&str>,
    ) -> Result<Pty> {
        let user = Arc::new(User::new(username)?);
        let shell_path = user.shell();
        let shell_name: &str = &shell_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("bash"))
            .to_string_lossy();

        let home_path = user.home_dir().to_str().unwrap_or("/tmp");
        let work_dir = cwd.unwrap_or(home_path);
        let local_envs = load_envs(username, home_path, &shell_path.to_string_lossy()).await;
        let (master, slave) = openpty(&user, cols, rows)?;

        let (program, args): (&str, &[String]) = match prog {
            Some(p) => (&p.program, &p.args),
            None if LOGIN_SHELL_SUPPORTED.contains(&shell_name) => (shell_name, &["-l".to_owned()]),
            None => (shell_name, &[]),
        };
        let mut cmd = Command::new(program);
        cmd.args(args);

        unsafe {
            let uid = user.uid();
            let gid = user.primary_group_id();
            let groups: Vec<libc::gid_t> = {
                let gs = user.groups().unwrap_or_default();
                gs.iter().map(|g| g.gid()).collect()
            };
            cmd.pre_exec(move || {
                audit_setloginuid(uid)?;
                libc::setgroups(groups.len(), groups.as_ptr());
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
            .envs(local_envs.iter().chain(envs))
            .current_dir(work_dir)
            .spawn()?;

        let pid = child.id().unwrap() as pid_t;
        let sid = unsafe { getsid(pid) };
        let utmx_type = "LOGIN";
        let tty_name = unsafe {
            let tty_name_c = ttyname(slave.as_raw_fd());
            CStr::from_ptr(tty_name_c).to_string_lossy().to_string()
        };
        call_utmpx(&tty_name, username, pid, sid, utmx_type).await;

        // Kill terminal process when Pty is dropped
        let (send, mut recv) = channel::<()>();
        let username = username.to_owned();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = child.wait() => {},
                _ = &mut recv => child.kill().await.unwrap_or_default(),
            }
            let _ = child.wait().await; // Release zombie process after kill
            let utmx_type = "EXIT";
            call_utmpx(&tty_name, &username, pid, sid, utmx_type).await;
        });

        Ok(Pty {
            _kill_on_drop: send,
            master,
            user,
            pid,
        })
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

    pub async fn get_reader(&self) -> Result<PtyIo> {
        self.get_writer().await
    }

    pub async fn get_writer(&self) -> Result<PtyIo> {
        Ok(PtyIo(self.master.clone()))
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

/// Async, non-blocking, cancel-safe I/O over the pty master fd, built on
/// `AsyncFd::async_io` instead of `tokio::fs::File` (which offloads every
/// read/write to the blocking-thread pool and never registers with the
/// reactor). Cloning is cheap: it just bumps the `Arc` refcount, no fd dup.
#[derive(Clone)]
pub struct PtyIo(Arc<AsyncFd<OwnedFd>>);

impl PtyIo {
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .async_io(Interest::READABLE, |fd| read_raw(fd.as_raw_fd(), buf))
            .await
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = self
                .0
                .async_io(Interest::WRITABLE, |fd| {
                    write_raw(fd.as_raw_fd(), &buf[off..])
                })
                .await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
            }
            off += n;
        }
        Ok(())
    }
}

/// Retry `libc::read` on EINTR, return the result (WouldBlock is handled by
/// `AsyncFd::async_io`'s outer retry loop).
fn read_raw(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `fd` is a valid, open fd for the duration of this call;
        // `buf`'s pointer and length describe a valid, writable byte range.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Retry `libc::write` on EINTR, return the number of bytes written.
fn write_raw(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `fd` is a valid, open fd for the duration of this call;
        // `buf`'s pointer and length describe a valid, readable byte range.
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

impl PluginComp {
    pub async fn inspect_access(&self, path: &str, access: u8) -> Result<()> {
        let metadata = metadata(path).await?;
        let user = self.get_user()?;

        // check root
        if user.uid() == 0 {
            return Ok(());
        }

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

        bail!("access denied");
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
                let mut exit_code = 0_i32;
                libc::waitpid(pid, &mut exit_code, 0);
                if exit_code == 0 {
                    return Ok(output);
                }
                let err_msg = String::from_utf8_lossy(&output).to_string();
                error!("[parent] work_as_user func exit failed: {}", err_msg);
                bail!(err_msg);
            }
        }
    }

    pub async fn execute_stream(
        &self,
        cmd: &str,
        callback: Option<PtyExecCallback>,
        timeout: Option<u64>,
    ) -> Result<()> {
        let user = self.get_user()?;
        let cwd_path = self.get_cwd(&user);
        let mut cmd = init_command(cmd, Some(user.as_ref()), false).await;
        configure_command(&mut cmd, &user, cwd_path).await;

        let callback = callback.unwrap_or_else(|| Box::new(|_, _, _, _| Box::pin(async {})));
        let timeout = timeout.unwrap_or(60);
        execute_stream(cmd, &callback, timeout).await
    }

    fn get_cwd(&self, user: &User) -> PathBuf {
        match self {
            Self::Pty(pty, ..) => pty.get_cwd(),
            _ => user.home_dir().to_owned(),
        }
    }
}

fn openpty(user: &User, cols: u16, rows: u16) -> Result<(Arc<AsyncFd<OwnedFd>>, StdFile)> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    let size = winsize {
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
            &size,
        ) {
            bail!("openpty failed: {}", io::Error::last_os_error());
        };

        libc::fchown(slave, user.uid(), user.primary_group_id());

        // The master must be non-blocking before it's wrapped in AsyncFd, or the
        // raw read()/write() calls inside AsyncFd::async_io's closure would block
        // the executor thread instead of returning EWOULDBLOCK.
        let flags = libc::fcntl(master, libc::F_GETFL);
        if flags == -1 || libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
            bail!(
                "failed to set O_NONBLOCK on pty master: {}",
                io::Error::last_os_error()
            );
        }
    }

    // SAFETY: `master` is a just-opened, valid, unique fd returned by openpty() above.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let master = Arc::new(AsyncFd::new(master)?);

    let slave = unsafe { StdFile::from_raw_fd(slave) };
    Ok((master, slave))
}

async fn call_utmpx(ttyname: &str, username: &str, pid: pid_t, sid: pid_t, ut_type: &str) {
    info!(
        "=>call_utmpx tty:{}, user:{}, pid:{}, sid:{}, type:{}",
        ttyname, username, pid, sid, ut_type
    );
    let utmpx_path = format!("{}/utmpx", EXE_DIR.to_string_lossy());
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
    let loginuid = format!("{}", uid);
    let path = "/proc/self/loginuid";

    let Ok(mut file) = StdFile::create(path) else {
        info!("audit_setloginuid {} not found, ignore audit", path);
        return Ok(());
    };
    file.write_all(loginuid.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        common::get_current_username,
        network::types::ws_msg::{Empty, JsonData, MsgId},
        tssh::session::PluginComp,
    };

    #[tokio::test]
    async fn test_work_as_user() {
        let username = get_current_username();
        let id = MsgId::<_, _> {
            session_id: "session".to_owned(),
            channel_id: "channel".to_owned(),
            inner: JsonData(Empty),
        };
        let plugin = PluginComp::Nil { username, id };

        let result = plugin.execute(&|| Ok("foo".to_string().into_bytes()));
        let foo = String::from_utf8_lossy(&result.unwrap()).to_string();
        assert_eq!(foo, "foo");
    }
}
