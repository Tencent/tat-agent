use super::handler::{BsonHandler, Handler, JsonHandler};
use super::{gather::PtyGather, ConPtyAdapter};
use crate::common::evbus::EventBus;
use crate::common::utils::{get_current_username, get_now_secs};
use crate::conpty::{PtyAdapter, PtyBase, PtyExecCallback, PtyResult};
use crate::executor::{decode_output, init_cmd, kill_process_group};
use crate::network::types::ws_msg::{
    ExecCmdReq, ExecCmdStreamReq, ExecCmdStreamResp, PtyBinErrMsg, PtyError, PtyInput, PtyOutput,
    PtyReady, PtyResize, PtyStart, PtyStop,
};

use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use log::{error, info};
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Instant};

use super::{
    PTY_EXEC_DATA_SIZE, PTY_FLAG_ENABLE_BLOCK, SLOT_PTY_BIN, WS_MSG_TYPE_PTY_ERROR,
    WS_MSG_TYPE_PTY_EXEC_CMD, WS_MSG_TYPE_PTY_EXEC_CMD_STREAM, WS_MSG_TYPE_PTY_INPUT,
    WS_MSG_TYPE_PTY_OUTPUT, WS_MSG_TYPE_PTY_READY, WS_MSG_TYPE_PTY_RESIZE, WS_MSG_TYPE_PTY_START,
    WS_MSG_TYPE_PTY_STOP,
};
const SLOT_PTY_CMD: &str = "event_slot_pty_cmd";
const PTY_REMOVE_INTERVAL: u64 = 3 * 60;

#[cfg(windows)]
use crate::executor::windows::resume_as_user;
#[cfg(unix)]
use crate::network::types::ws_msg::ExecCmdResp;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::Stdio;

pub fn register_pty_handlers(event_bus: &Arc<EventBus>) {
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
        })
        .slot_register(
            SLOT_PTY_BIN,
            WS_MSG_TYPE_PTY_EXEC_CMD_STREAM,
            move |value| {
                BsonHandler::<ExecCmdStreamReq>::dispatch(value);
            },
        );
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

        let pty_base =
            match ConPtyAdapter::openpty(&user_name, pty_start.cols, pty_start.rows, flag) {
                Ok(session) => session,
                Err(e) => {
                    error!("=>open pty err: {}", e);
                    let pty_error = PtyError {
                        session_id,
                        reason: e.to_string(),
                    };
                    PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_ERROR, pty_error);
                    return;
                }
            };

        let writer = pty_base.get_writer().expect("GetWriterFailed");
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
            .expect("GetSessionFailed")
            .pty_base
            .resize(self.request.cols, self.request.rows);
    }
}

impl Handler for JsonHandler<PtyInput> {
    fn process(self) {
        let data = match STANDARD.decode(&self.request.input) {
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
            .expect("GetSessionFailed")
            .writer
            .lock()
            .expect("LockWriterFailed")
            .write(&data[..]);
    }
}

#[derive(Clone)]
pub struct PtySession {
    pub session_id: String,
    pub pty_base: Arc<dyn PtyBase + Send + Sync>,
    pub writer: Arc<Mutex<File>>,
    pub last_time: Arc<AtomicU64>,
    pub is_stopped: Arc<AtomicBool>,
}

impl PtySession {
    async fn process_output(&self) {
        info!("=>process_output {}", self.session_id);
        let duration = Duration::from_millis(100);
        let mut reader =
            tokio::fs::File::from_std(self.pty_base.get_reader().expect("get_reader Failed"));

        loop {
            if self.is_stopped.load(SeqCst) {
                break info!("process_output {} stopped; break", self.session_id);
            }

            //no input about 3 minutes, break
            if self.is_timeout() {
                break info!("process_output {} timeout; break", self.session_id);
            }

            let mut buffer: [u8; 1024] = [0; 1024];

            let Ok(result) = timeout(duration, reader.read(&mut buffer[..])).await else {
                continue;
            };

            match result {
                Ok(0) => break info!("process_output {} read size is 0 close", self.session_id),
                Ok(size) => {
                    let data = STANDARD.encode(&mut buffer[0..size]);
                    let pty_output = PtyOutput {
                        session_id: self.session_id.clone(),
                        output: data,
                    };
                    PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_OUTPUT, pty_output)
                }
                Err(e) => {
                    info!("process_output {} err: {}", self.session_id, e);
                    let pty_logintout = PtyError {
                        session_id: self.session_id.clone(),
                        reason: format!("loginout"),
                    };
                    break PtyGather::reply_json_msg(WS_MSG_TYPE_PTY_ERROR, pty_logintout);
                }
            }
        }
        PtyGather::remove_session(&self.session_id);
        info!("process_output {} finished", self.session_id);
    }

    fn is_timeout(&self) -> bool {
        let elapse = get_now_secs() - self.last_time.load(SeqCst);
        elapse > PTY_REMOVE_INTERVAL
    }
}

#[cfg(windows)]
impl Handler for BsonHandler<ExecCmdReq> {
    fn process(self) {
        self.reply(PtyBinErrMsg::new("not support on windows"));
    }
}

#[cfg(unix)]
impl Handler for BsonHandler<ExecCmdReq> {
    fn process(self) {
        let param = &self.request.data;
        let session_id = self.request.session_id.clone();
        info!("=>pty exec {} {}", session_id, param.cmd);
        let exec_result = self.associate_pty.execute(&|| -> Result<Vec<u8>, String> {
            let mut command = std::process::Command::new("bash");
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

            command
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).as_bytes().to_vec())
                .map_err(|err| format!("err_msg: {}", err))
        });

        match exec_result {
            Ok(output) => {
                let output = String::from_utf8_lossy(&output).to_string();
                info!("{} exec success, output: {}", session_id, output);
                self.reply(ExecCmdResp { output })
            }
            Err(err) => {
                error!("{} exec failed: {}", session_id, err);
                self.reply(PtyBinErrMsg::new(err))
            }
        }
    }
}

impl Handler for BsonHandler<ExecCmdStreamReq> {
    fn process(self) {
        let param = &self.request.data;
        let session_id = self.request.session_id.clone();

        info!("=>pty exec {} {}", session_id, param.cmd);
        let self_c = self.clone();
        let cb = Box::new(move |index, is_last, exit_code, data: Vec<u8>| {
            self_c.reply(ExecCmdStreamResp {
                index,
                is_last,
                exit_code,
                data,
            })
        });

        let cmd = init_cmd(&param.cmd);
        let exec_result = self
            .associate_pty
            .execute_stream(cmd, Some(cb), param.timeout);
        if let Err(e) = exec_result {
            error!("{} exec failed: {}", session_id, e);
            self.reply(PtyBinErrMsg::new(e))
        }
    }
}

pub fn execute_stream(
    mut cmd: tokio::process::Command,
    callback: &PtyExecCallback,
    timeout: u64,
    #[cfg(windows)] token: &File,
    #[cfg(windows)] pipe: File,
    #[cfg(windows)] username: &str,
) -> PtyResult<()> {
    tokio::runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .expect("runtime build failed")
        .block_on(async move {
            let mut idx = 0u32;
            let mut is_last;
            let timeout_at = Instant::now() + Duration::from_secs(timeout);
            let mut buf = [0u8; PTY_EXEC_DATA_SIZE];

            #[allow(unused_mut)] // Unix needs MUT, Windows does not.
            let mut child = cmd.spawn().map_err(|_| "command start failed")?;
            let pid = child.id();

            #[cfg(windows)]
            let mut reader = {
                drop(cmd); // move pipe sender
                resume_as_user(pid, username, &token);
                tokio::fs::File::from_std(pipe)
            };
            #[cfg(unix)]
            let mut reader = child.stdout.take().unwrap();

            loop {
                tokio::select! {
                    len = reader.read(&mut buf) => {
                        let len = len.map_err(|_| "buffer read failed")?;
                        is_last = len == 0;
                        if is_last {
                            break;
                        }
                        let output = decode_output(&buf[..len]);
                        callback(idx, is_last, None, output.into());
                        idx += 1;
                    }
                    _ = tokio::time::delay_until(timeout_at) => {
                        error!("work_as_user func timeout");
                        kill_process_group(pid);
                        Err("command timeout, process killed")?;
                    }
                };
            }

            let exit_status = child
                .wait_with_output()
                .await
                .map_err(|_| "wait command failed")?
                .status;
            if !exit_status.success() {
                error!("work_as_user func exit failed: {}", exit_status);
            }
            let exit_code = exit_status.code().ok_or("command terminated abnormally")?;
            callback(idx, is_last, Some(exit_code), Vec::new());
            Ok(())
        })
}

#[cfg(test)]
mod test {
    use crate::common::utils::get_current_username;
    use crate::conpty::*;
    use crate::executor::init_cmd;

    use std::collections::HashMap;
    use std::time::Duration;

    use log::info;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_pty_session() {
        let user_name = get_current_username();
        let session = ConPtyAdapter::openpty(&user_name, 200, 100, 0).unwrap();

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
        info!("output: {}", output);
        let result = output.to_string().contains("test");
        std::mem::drop(session);
        assert!(result);
    }

    #[test]
    fn test_execute_stream() {
        let params = test_execute_stream_data();
        for p in params {
            test_execute_stream_template(p.0, p.1, p.2, p.3);
        }
    }

    fn test_execute_stream_template(
        script: &str,
        timeout: Option<u64>,
        data_map: HashMap<u32, (bool, Option<i32>, Vec<u8>)>,
        expect_result: PtyResult<()>,
    ) {
        let name = get_current_username();
        let pty_session = ConPtyAdapter::openpty(&name, 100, 100, 0).unwrap();

        let cb = Box::new(
            move |idx: u32, is_last: bool, exit_code: Option<i32>, data: Vec<u8>| {
                let (expect_is_last, expect_exit_code, expect_data) = data_map
                    .get(&idx)
                    .expect(&format!("idx `{idx}` not expect"));
                // info!("idx:{idx}, is_last:{is_last}, exit_code:{exit_code:?}, data:{data:?}");
                assert_eq!(*expect_is_last, is_last);
                assert_eq!(*expect_exit_code, exit_code);
                assert_eq!(*expect_data, data);
            },
        );
        let cmd = init_cmd(script);
        let res = pty_session.execute_stream(cmd, Some(cb), timeout);
        assert_eq!(expect_result, res);
    }

    fn test_execute_stream_data() -> Vec<(
        &'static str,
        Option<u64>,
        HashMap<u32, (bool, Option<i32>, Vec<u8>)>,
        PtyResult<()>,
    )> {
        #[cfg(unix)]
        let cmd_timeout = [
            // Below data length with stderr
            ("echo -n foo >&2", None),
            // Below data length multiple outputs
            ("echo -n foo; sleep 0.5; echo -n foo", None),
            // Exceeding data length
            ("echo -n foo; echo -n foo", None),
            // Timeout without output
            ("while true; do sleep 100; done", Some(1)),
            // Timeout with exceeding data length multiple output
            ("while true; do echo -n foofoo; sleep 0.7; done", Some(1)),
            // Failed without output
            ("exit 1", None),
            // Failed with output
            ("echo -n foo; exit 1", None),
        ];
        #[cfg(windows)]
        let cmd_timeout = [
            // Below data length with stderr
            (r#"[Console]::Error.Write("foo")"#, None),
            // Below data length multiple outputs
            (
                r#"[Console]::Write("foo"); Start-Sleep -Seconds 0.5; [Console]::Error.Write("foo")"#,
                None,
            ),
            // Exceeding data length
            (r#"[Console]::Write("foofoo")"#, None),
            // Timeout without output
            ("while ($true) { Start-Sleep -Seconds 100 }", Some(1)),
            // Timeout with exceeding data length multiple output
            (
                r#"while ($true) { [Console]::Write("foofoo"); Start-Sleep -Seconds 0.7 }"#,
                Some(1),
            ),
            // Failed without output
            ("exit 1", None),
            // Failed with output
            (r#"[Console]::Write("foo"); exit 1"#, None),
        ];

        let expect = vec![
            (
                // Below data length with stderr
                HashMap::from([
                    (0, (false, None, b"foo".to_vec())),
                    (1, (true, Some(0), vec![])),
                ]),
                Ok(()),
            ),
            (
                // Below data length multiple outputs
                HashMap::from([
                    (0, (false, None, b"foo".to_vec())),
                    (1, (false, None, b"foo".to_vec())),
                    (2, (true, Some(0), vec![])),
                ]),
                Ok(()),
            ),
            (
                // Exceeding data length
                HashMap::from([
                    (0, (false, None, b"foofo".to_vec())),
                    (1, (false, None, b"o".to_vec())),
                    (2, (true, Some(0), vec![])),
                ]),
                Ok(()),
            ),
            (
                // Timeout without output
                HashMap::new(),
                Err("command timeout, process killed".to_owned()),
            ),
            (
                // Timeout with exceeding data length multiple output
                HashMap::from([
                    (0, (false, None, b"foofo".to_vec())),
                    (1, (false, None, b"o".to_vec())),
                    (2, (false, None, b"foofo".to_vec())),
                    (3, (false, None, b"o".to_vec())),
                ]),
                Err("command timeout, process killed".to_owned()),
            ),
            (
                // Failed without output
                HashMap::from([(0, (true, Some(1), vec![]))]),
                Ok(()),
            ),
            (
                // Failed with output
                HashMap::from([
                    (0, (false, None, b"foo".to_vec())),
                    (1, (true, Some(1), vec![])),
                ]),
                Ok(()),
            ),
        ];

        cmd_timeout
            .iter()
            .zip(expect)
            .map(|(&(a, b), (c, d))| (a, b, c, d))
            .collect()
    }
}
