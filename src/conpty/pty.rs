use crate::common::consts::{
    PTY_FLAG_ENABLE_BLOCK, PTY_REMOVE_INTERVAL, SLOT_PTY_BIN, SLOT_PTY_CMD, WS_MSG_TYPE_PTY_ERROR,
    WS_MSG_TYPE_PTY_EXEC_CMD, WS_MSG_TYPE_PTY_INPUT, WS_MSG_TYPE_PTY_OUTPUT, WS_MSG_TYPE_PTY_READY,
    WS_MSG_TYPE_PTY_RESIZE, WS_MSG_TYPE_PTY_START, WS_MSG_TYPE_PTY_STOP,
};
use crate::common::evbus::EventBus;
use crate::common::utils::{get_current_username, get_now_secs};
use crate::conpty::{PtyAdapter, PtyBase};

use crate::network::types::ws_msg::{
    ExecCmdReq, PtyBinErrMsg, PtyError, PtyInput, PtyOutput, PtyReady, PtyResize, PtyStart, PtyStop,
};
use log::{error, info};
use std::fs::File;
use std::io::Write;

use super::gather::PtyGather;
use super::handler::{BsonHandler, Handler, JsonHandler};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

#[cfg(unix)]
use super::unix::ConPtyAdapter;
#[cfg(unix)]
use crate::network::types::ws_msg::ExecCmdResp;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::{Command, Stdio};

#[cfg(windows)]
use super::windows::ConPtyAdapter;

pub(crate) fn register_pty_handlers(event_bus: &Arc<EventBus>) {
    event_bus
        .slot_register(SLOT_PTY_CMD, WS_MSG_TYPE_PTY_START, move |value| {
            JsonHandler::<PtyStart>::dispatch(value, false);
        })
        .slot_register(SLOT_PTY_CMD, WS_MSG_TYPE_PTY_STOP, move |value| {
            JsonHandler::<PtyStop>::dispatch(value, false);
        })
        .slot_register(SLOT_PTY_CMD, WS_MSG_TYPE_PTY_RESIZE, move |value| {
            JsonHandler::<PtyResize>::dispatch(value, true);
        })
        .slot_register(SLOT_PTY_CMD, WS_MSG_TYPE_PTY_INPUT, move |value| {
            JsonHandler::<PtyInput>::dispatch(value, true);
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_EXEC_CMD, move |value| {
            BsonHandler::<ExecCmdReq>::dispatch(value);
        });
}

impl Handler for JsonHandler<PtyStart> {
    fn process(self) {
        let pty_start: &PtyStart = &self.request;
        info!("pty_start {} {}", pty_start.session_id, pty_start.user_name);

        let user_name = if pty_start.user_name.len() == 0 {
            get_current_username()
        } else {
            pty_start.user_name.clone()
        };

        let mut flag: u32 = 0;
        if pty_start.init_block {
            flag = flag | PTY_FLAG_ENABLE_BLOCK
        }

        let session_id = pty_start.session_id.clone();

        let pty_base = match ConPtyAdapter::default().openpty(
            &user_name,
            pty_start.cols,
            pty_start.rows,
            flag,
        ) {
            Ok(session) => session,
            Err(e) => {
                error!("=>open pty err {}", e.to_string());
                let pty_error = PtyError {
                    session_id,
                    reason: e.to_string(),
                };
                PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_ERROR, pty_error);
                return;
            }
        };

        let writer = pty_base.get_writer().expect("GetWriterFail");
        let session = Arc::new(PtySession {
            session_id: session_id.clone(),
            pty_base,
            last_time: Arc::new(AtomicU64::new(get_now_secs())),
            is_stopped: Arc::new(AtomicBool::new(false)),
            writer: Arc::new(Mutex::new(writer)),
        });

        PtyGather::add_session(&session_id, session.clone());

        let pty_ready = PtyReady { session_id };
        self.reply(WS_MSG_TYPE_PTY_READY, pty_ready);

        PtyGather::runtime().spawn(async move { session.process_output().await });
        info!("handle_pty_start success");
    }
}

impl Handler for JsonHandler<PtyStop> {
    fn process(self) {
        info!("handle_pty_stop {}", self.request.session_id);
        let session_id = self.request.session_id.clone();
        if let Some(session) = self.associate_session {
            session.is_stopped.store(true, SeqCst);
        }
        PtyGather::remove_session(&session_id);
    }
}

impl Handler for JsonHandler<PtyResize> {
    fn process(self) {
        info!("handle_pty_resize {}", self.request.session_id);
        let _ = self
            .associate_session
            .as_ref()
            .expect("GetSessionFail")
            .pty_base
            .resize(self.request.cols, self.request.rows);
    }
}

impl Handler for JsonHandler<PtyInput> {
    fn process(self) {
        let data = match base64::decode(&self.request.input) {
            Ok(data) => data,
            Err(e) => {
                let pty_error = PtyError {
                    session_id: self.request.session_id.clone(),
                    reason: e.to_string(),
                };
                return self.reply(WS_MSG_TYPE_PTY_ERROR, pty_error);
            }
        };

        let _ = self
            .associate_session
            .as_ref()
            .expect("GetSessionFail")
            .writer
            .lock()
            .expect("LockWriterFail")
            .write(&data[..]);
    }
}

#[derive(Clone)]
pub(crate) struct PtySession {
    pub(crate) session_id: String,
    pub(crate) pty_base: Arc<dyn PtyBase + Send + Sync>,
    pub(crate) writer: Arc<Mutex<File>>,
    pub(crate) last_time: Arc<AtomicU64>,
    pub(crate) is_stopped: Arc<AtomicBool>,
}

impl PtySession {
    async fn process_output(&self) {
        info!("=>process_output {}", self.session_id);
        let duration = Duration::from_millis(100);
        let mut reader =
            tokio::fs::File::from_std(self.pty_base.get_reader().expect("get_reader Fail"));

        loop {
            if self.is_stopped.load(SeqCst) {
                info!("process_output  {}  stopped;break", self.session_id);
                break;
            }

            //no input about 3 minutes, break
            if !self.check_last_time() {
                info!("process_output {}  timeout; break", self.session_id);
                break;
            }

            let mut buffer: [u8; 1024] = [0; 1024];

            let result = match timeout(duration, reader.read(&mut buffer[..])).await {
                Ok(v) => v,
                Err(_) => {
                    continue;
                }
            };

            match result {
                Ok(size) => {
                    if size > 0 {
                        let data = base64::encode(&mut buffer[0..size]);
                        let pty_output = PtyOutput {
                            session_id: self.session_id.clone(),
                            output: data,
                        };
                        PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_OUTPUT, pty_output)
                    } else {
                        info!("process_output {} read size is 0 close", self.session_id);
                        break;
                    }
                }
                Err(e) => {
                    info!("process_output {}  err, {}", self.session_id, e);
                    let pty_error = PtyError {
                        session_id: self.session_id.clone(),
                        reason: format!("session {} error {}", self.session_id, e),
                    };
                    PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_ERROR, pty_error);
                    break;
                }
            }
        }
        PtyGather::remove_session(&self.session_id);
        info!("process_output {} finished", self.session_id);
    }

    fn check_last_time(&self) -> bool {
        let last = self.last_time.load(SeqCst);
        let now = get_now_secs();
        return if now - last > PTY_REMOVE_INTERVAL {
            false //time out
        } else {
            true
        };
    }
}

#[cfg(windows)]
impl Handler for BsonHandler<ExecCmdReq> {
    fn process(self) {
        return self.reply(PtyBinErrMsg {
            error: "not support on windows".to_owned(),
        });
    }
}

#[cfg(unix)]
impl Handler for BsonHandler<ExecCmdReq> {
    fn process(self) {
        let param = &self.request.data;
        let session_id = self.request.session_id.clone();
        info!("=>pty exec {} {}", session_id, param.cmd);
        let exec_result = self.associate_pty.execute(&|| -> Result<Vec<u8>, String> {
            let mut command = Command::new("bash");
            unsafe {
                command
                    .args(&["-c", param.cmd.as_str()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .pre_exec(|| {
                        libc::dup2(1, 2);
                        Ok(())
                    });
            }
            match command.output() {
                Ok(output) => {
                    let output = String::from_utf8_lossy(&output.stdout);
                    Ok(output.as_bytes().to_vec())
                }
                Err(err) => Err(format!("err_msg:{}", err.to_string())),
            }
        });

        match exec_result {
            Ok(output) => {
                let output = String::from_utf8_lossy(&output).to_string();
                info!("{} exec success output {}", session_id, output);
                self.reply(ExecCmdResp { output })
            }
            Err(err) => {
                error!("{} exec fail {}", session_id, err.to_string());
                return self.reply(PtyBinErrMsg {
                    error: err.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::common::utils::get_current_username;
    #[cfg(unix)]
    use crate::conpty::unix::ConPtyAdapter;
    #[cfg(windows)]
    use crate::conpty::windows::ConPtyAdapter;
    use crate::conpty::PtyAdapter;
    use log::info;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    #[tokio::test]
    async fn test() {
        let user_name = get_current_username();

        let session = ConPtyAdapter::default()
            .openpty(&user_name, 200, 100, 0)
            .unwrap();

        let mut reader = tokio::fs::File::from_std(session.get_reader().unwrap());
        let mut writer = tokio::fs::File::from_std(session.get_writer().unwrap());

        //consume data
        loop {
            let mut temp: [u8; 1024] = [0; 1024];
            let duration = Duration::from_secs(10);
            let timeout_read = timeout(duration, reader.read(&mut temp[..])).await;
            if timeout_read.is_err() {
                break;
            }
        }

        writer.write("echo \"test\" \r".as_bytes()).await.unwrap();
        let mut buffer: [u8; 1024] = [0; 1024];
        let mut len = 0;

        //read pwd output
        loop {
            let duration = Duration::from_secs(4);
            let timeout_read = timeout(duration, reader.read(&mut buffer[len..])).await;
            if timeout_read.is_err() {
                break;
            }
            len += timeout_read.unwrap().unwrap()
        }

        let output = String::from_utf8_lossy(&buffer[..len]);
        info!("output is {}", output);
        let result = output.to_string().contains("test");
        std::mem::drop(session);
        assert!(result);
    }
}
