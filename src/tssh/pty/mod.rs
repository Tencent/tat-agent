use super::handler::{BsonHandler, Handler, HandlerExt, JsonHandler};
use super::session::{Channel, Plugin, PluginComp, PluginCtrl, PluginData, Session};
use super::Tssh;
use crate::common::{get_current_username, incomplete_utf8_bytes};
use crate::executor::kill_process_group;
use crate::network::*;

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use log::{error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{process::Command, time::sleep};

use super::{PTY_EXEC_DATA_SIZE, WS_MSG_TYPE_PTY_ERROR, WS_MSG_TYPE_PTY_OUTPUT};
const PTY_TTL: Duration = Duration::from_secs(60 * 3); // 3 min
const PTY_BUF_SIZE: usize = 1024;
const PTY_LOGOUT_MSG: &str = "logout"; // Required by OrcaTerm. DO NOT modify.
const PTY_SHELL_EXIT_ERR: &str = "I/O error (os error 5)";

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub use unix::Pty;

        use crate::network::ExecCmdResp;
        use std::os::unix::process::CommandExt;
        use std::process::{Command as StdCommand, Stdio};
    } else if #[cfg(windows)] {
        mod bind;
        mod parser;
        mod windows;
        pub use windows::Pty;

        use crate::executor::windows::{resume_as_user, User};
        use super::PTY_FLAG_ENABLE_BLOCK;
        use tokio::fs::File;
    }
}

type PtyExecCallback = Box<
    dyn Fn(u32, bool, Option<i32>, Vec<u8>) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

pub async fn register_pty_handlers() {
    JsonHandler::<PtyStart>::register().await;
    JsonHandler::<PtyStop>::register().await;
    JsonHandler::<PtyResize>::register().await;
    JsonHandler::<PtyInput>::register().await;
    JsonHandler::<PtyMaxRate>::register().await;
    JsonHandler::<PtyPing>::register().await;

    BsonHandler::<ExecCmdReq>::register().await;
    BsonHandler::<ExecCmdStreamReq>::register().await;
}

impl Handler for JsonHandler<PtyStart> {
    const MSG_TYPE: &str = "PtyStart";
    const NEED_CHANNEL: bool = false;

    async fn process(self) {
        let req = &self.request.data;
        let session_id = &self.request.session_id;
        let channel_id = &self.request.channel_id;
        let mut username = req.user_name.clone();
        let id = self.id();
        info!("=>pty_start `{id}`, username: {username}");

        if username.is_empty() {
            username = get_current_username();
        }

        let comp = if req.no_shell {
            PluginComp::Nil { username }
        } else {
            #[cfg(windows)]
            let pty_res = {
                let mut flag: u32 = 0;
                if req.init_block {
                    flag |= PTY_FLAG_ENABLE_BLOCK
                }
                Pty::new(&username, req.cols, req.rows, flag)
            };

            #[cfg(unix)]
            let pty_res = {
                if let Some(Program { program, args }) = req.prog.as_ref() {
                    info!("Pty `{id}` start with program: {program}, args: {args:?}");
                }
                Pty::new(&username, req.cols, req.rows, &req.envs, &req.prog).await
            };

            let pty = match pty_res {
                Ok(pty) => pty,
                Err(e) => {
                    error!("pty_start `{id}` failed, open pty err: {e:#}");
                    return self.reply(PtyError::new(e)).await;
                }
            };
            PluginComp::Pty(pty)
        };
        let plugin = Plugin {
            component: comp,
            data: (&self.request).into(),
            controller: PluginCtrl::new(PTY_TTL),
        };

        let channel = Arc::new(Channel::new(session_id, channel_id, plugin));
        let session = match Tssh::get_session(session_id).await {
            Some(s) => s,
            None => {
                let s = Arc::new(Session::new(session_id));
                let _ = Tssh::add_session(session_id, s.clone()).await;
                s
            }
        };

        if let Err(e) = session.add_channel(channel_id, channel).await {
            return self.reply(PtyError::new(e)).await;
        }

        info!("pty_start `{}` success", self.id());
        self.reply(PtyReady {}).await
    }
}

impl Handler for JsonHandler<PtyStop> {
    const MSG_TYPE: &str = "PtyStop";
    const NEED_CHANNEL: bool = false;

    async fn process(self) {
        let session_id = &self.request.session_id;
        let channel_id = &self.request.channel_id;
        info!("=>pty_stop `{}`", self.id());

        let Some(session) = Tssh::get_session(session_id).await else {
            return;
        };
        if channel_id.is_empty() {
            Tssh::remove_session(session_id).await;
        } else if self.channel.is_some() {
            session.remove_channel(channel_id).await;
        }
    }
}

impl Handler for JsonHandler<PtyResize> {
    const MSG_TYPE: &str = "PtyResize";

    async fn process(self) {
        info!("=>pty_resize `{}`", self.id());
        let channel = &self.channel;
        let Some(pty) = channel.as_ref().unwrap().plugin.try_get_pty() else {
            error!("channel `{}` pty not found", self.id());
            return self.reply(PtyError::new("pty not found")).await;
        };
        let d = &self.request.data;
        if let Err(e) = pty.resize(d.cols, d.rows).await {
            error!("pty_resize `{}` error: {}", self.id(), e);
        };
    }
}

impl Handler for JsonHandler<PtyInput> {
    const MSG_TYPE: &str = "PtyInput";
    const NEED_SYNC_DISPATCH: bool = true;

    async fn process(self) {
        // info!("=>pty_input `{}`", self.id());
        let data = match STANDARD.decode(&self.request.data.input) {
            Ok(data) => data,
            Err(e) => return self.reply(PtyError::new(e)).await,
        };
        let channel = &self.channel;
        let Some(pty) = channel.as_ref().unwrap().plugin.try_get_pty() else {
            error!("channel `{}` pty not found", self.id());
            return self.reply(PtyError::new("pty not found")).await;
        };
        let mut writer = match pty.get_writer().await {
            Ok(w) => w,
            Err(e) => return error!("pty_input `{}` error: {}", self.id(), e),
        };
        if let Err(e) = writer.write_all(&data[..]).await {
            error!("pty_input `{}` error: {}", self.id(), e);
        };
    }
}

#[cfg(windows)]
impl Handler for BsonHandler<ExecCmdReq> {
    const MSG_TYPE: &str = "PtyExecCmd";

    async fn process(self) {
        self.reply(PtyBinErrMsg::new("not support on windows"))
            .await
    }
}

#[cfg(unix)]
impl Handler for BsonHandler<ExecCmdReq> {
    const MSG_TYPE: &str = "PtyExecCmd";

    async fn process(self) {
        let data = &self.request.data;
        info!(
            "=>exec_cmd `{}`, command: {}",
            self.id(),
            data.cmd.escape_debug()
        );

        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        let result = plugin.execute(&|| unsafe {
            let output = StdCommand::new("bash")
                .args(["-c", data.cmd.as_str()])
                .stdin(Stdio::null())
                .pre_exec(|| {
                    libc::dup2(1, 2);
                    Ok(())
                })
                .output()?;
            Ok(String::from_utf8_lossy(&output.stdout).as_bytes().to_vec())
        });

        match result {
            Ok(output) => {
                let output = String::from_utf8_lossy(&output).to_string();
                info!(
                    "exec_cmd `{}` success, output: {}",
                    self.id(),
                    output.escape_debug()
                );
                self.reply(ExecCmdResp { output }).await
            }
            Err(err) => {
                error!("exec_cmd `{}` failed: {}", self.id(), err);
                self.reply(PtyBinErrMsg::new(err)).await
            }
        }
    }
}

impl Handler for BsonHandler<ExecCmdStreamReq> {
    const MSG_TYPE: &str = "PtyExecCmdStream";

    async fn process(self) {
        let data = &self.request.data;
        info!(
            "=>exec_cmd_stream `{}`, command: {}",
            self.id(),
            data.cmd.escape_debug()
        );

        let sid = self.request.session_id.clone();
        let cid = self.request.channel_id.clone();
        let cdata = self.request.custom_data.clone();
        let op = self.op_type.clone();
        let cb: PtyExecCallback = Box::new(move |index, is_last, exit_code, data| {
            let msg = PtyBinBase {
                session_id: sid.clone(),
                channel_id: cid.clone(),
                custom_data: cdata.clone(),
                data: ExecCmdStreamResp {
                    index,
                    is_last,
                    exit_code,
                    data,
                },
            };
            let op = op.clone();
            Box::pin(async move { Tssh::reply_bson_msg(&op, msg).await })
        });

        let plugin = &self.channel.as_ref().unwrap().plugin;
        plugin.controller.timer.freeze();
        let result = plugin
            .component
            .execute_stream(&data.cmd, Some(cb), data.timeout)
            .await;
        plugin.controller.timer.unfreeze();
        if let Err(e) = result {
            error!("exec_cmd_stream `{}` failed: {:#}", self.id(), e);
            self.reply(PtyBinErrMsg::new(e)).await
        }
    }
}

impl Handler for JsonHandler<PtyMaxRate> {
    const MSG_TYPE: &str = "PtyMaxRate";
    const NEED_CHANNEL: bool = false;

    async fn process(self) {
        let rate = self.request.data.rate;
        info!("=>pty_max_rate: {} B/s", rate);
        Tssh::set_limiter(rate).await
    }
}

impl Handler for JsonHandler<PtyPing> {
    const MSG_TYPE: &str = "PtyPing";

    async fn process(self) {
        self.reply(PtyPong {}).await
    }
}

impl Pty {
    pub async fn process(&self, id: &str, data: &PluginData, ctrl: &PluginCtrl) {
        let PluginData {
            session_id,
            channel_id,
        } = data;
        let mut stopper_rx = ctrl
            .stopper
            .get_receiver()
            .await
            .expect("get_receiver failed");
        let mut buffer = [0u8; PTY_BUF_SIZE];
        let mut remnant = 0;
        let mut reader = self.get_reader().await.expect("get_reader Failed");

        loop {
            tokio::select! {
                res = reader.read(&mut buffer[remnant..]) => match res.map(|l| l + remnant) {
                    Ok(0) => break info!("Pty `{id}` close: read size is 0"),
                    Ok(len) => {
                        let is_finished = len == remnant;
                        remnant = if is_finished {
                            0 // if output finished, append entire buffer to output
                        } else {
                            incomplete_utf8_bytes(&buffer[..len])
                        };

                        let output = &buffer[..len - remnant];
                        if !output.is_empty() {
                            let data = STANDARD.encode(output);
                            let pty_output = PtyJsonBase {
                                session_id: session_id.clone(),
                                channel_id: channel_id.clone(),
                                data: PtyOutput { output: data },
                            };
                            Tssh::reply_json_msg(WS_MSG_TYPE_PTY_OUTPUT, pty_output).await;
                        }
                        if is_finished {
                            break info!("Pty `{id}` close: read size is 0");
                        }
                        buffer.copy_within(len - remnant..len, 0);
                    }
                    Err(e) => {
                        match e.to_string().as_str() {
                            PTY_SHELL_EXIT_ERR => info!("Pty `{id}` shell exited"),
                            _ => error!("Pty `{id}` err: {}", e),
                        }
                        let pty_logout = PtyJsonBase {
                            session_id: session_id.clone(),
                            channel_id: channel_id.clone(),
                            data: PtyError::new(PTY_LOGOUT_MSG),
                        };
                        break Tssh::reply_json_msg(WS_MSG_TYPE_PTY_ERROR, pty_logout).await;
                    }
                },
                _ = &mut stopper_rx => break info!("Pty `{id}` stopped"),
                _ = ctrl.timer.timeout() => break info!("Pty `{id}` timeout"),
            };
        }
    }
}

pub async fn execute_stream(
    mut cmd: Command,
    callback: &PtyExecCallback,
    timeout: u64,
    #[cfg(windows)] pipe: File,
    #[cfg(windows)] user: &User,
) -> Result<()> {
    let mut idx = 0u32;
    let mut buffer = [0u8; PTY_EXEC_DATA_SIZE];
    let mut remnant = 0;

    #[allow(unused_mut)] // Unix needs MUT, Windows does not.
    let mut child = cmd.spawn().context("command start failed")?;
    let pid = child.id().unwrap();

    #[cfg(windows)]
    let mut reader = {
        drop(cmd); // move pipe sender
        unsafe { resume_as_user(pid, user) };
        pipe
    };
    #[cfg(unix)]
    let mut reader = child.stdout.take().unwrap();
    let timeout = sleep(Duration::from_secs(timeout));
    tokio::pin!(timeout);

    let res = loop {
        tokio::select! {
            len = reader.read(&mut buffer[remnant..]) => {
                let (buf, len) = match len.map(|l| l + remnant) {
                    Err(e) => break Err(anyhow!("buffer read failed: {e:#}")),
                    Ok(0) => break Ok(()),
                    Ok(len) => (&buffer[..len], len),
                };
                let is_finished = len == remnant;
                remnant = if is_finished {
                    0 // if output finished, append entire buffer to output
                } else {
                    incomplete_utf8_bytes(&buffer[..len])
                };

                let output = &buf[..len - remnant];
                if !output.is_empty() {
                    callback(idx, false, None, output.into()).await;
                    idx += 1;
                }
                if is_finished {
                    break Ok(());
                }
                buffer.copy_within(len - remnant..len, 0);
            }
            _ = &mut timeout => {
                info!("execute_stream func timeout");
                unsafe { kill_process_group(pid) };
                break Err(anyhow!("command timeout, process killed"));
            }
        };
    };

    let Ok(exit_status) = child.wait().await else {
        callback(idx, true, Some(-1), Vec::new()).await;
        return res.and(Err(anyhow!("wait command failed")));
    };
    if !exit_status.success() {
        info!("execute_stream func exit failed: {}", exit_status);
    }
    let Some(exit_code) = exit_status.code() else {
        callback(idx, true, Some(-1), Vec::new()).await;
        return res.and(Err(anyhow!("command exit abnormally")));
    };
    callback(idx, true, Some(exit_code), Vec::new()).await;
    res
}

#[cfg(test)]
mod test {
    use super::Pty;
    use crate::common::get_current_username;
    use crate::common::logger::init_test_log;
    use crate::tssh::pty::PtyExecCallback;
    use crate::tssh::session::PluginComp;

    use std::collections::HashMap;
    use std::time::Duration;

    use log::info;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    async fn test_pty() {
        init_test_log();
        let username = get_current_username();
        #[cfg(windows)]
        let pty = Pty::new(&username, 200, 100, 0).unwrap();
        #[cfg(unix)]
        let pty = Pty::new(&username, 200, 100, &HashMap::new(), &None)
            .await
            .unwrap();
        let mut reader = pty.get_reader().await.unwrap();
        let mut writer = pty.get_writer().await.unwrap();

        //consume data
        loop {
            let mut temp: [u8; 1024] = [0; 1024];
            let duration = Duration::from_secs(10);
            let timeout_read = timeout(duration, reader.read(&mut temp[..])).await;
            if timeout_read.is_err() {
                break;
            }
        }

        writer
            .write_all("echo \"test\" \r".as_bytes())
            .await
            .unwrap();
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
        std::mem::drop(pty);
        sleep(Duration::from_secs(1)).await; // yield to let pty drop
        assert!(result);
    }

    #[tokio::test]
    async fn test_execute_stream() {
        let params = test_execute_stream_data();
        for p in params {
            test_execute_stream_template(p.0, p.1, p.2, p.3).await;
        }
    }

    async fn test_execute_stream_template(
        script: &str,
        timeout: Option<u64>,
        data_map: HashMap<u32, (bool, Option<i32>, Vec<u8>)>,
        expect_result: Result<(), String>,
    ) {
        let username = get_current_username();
        let plugin = PluginComp::Nil { username };

        let cb: PtyExecCallback = Box::new(move |idx, is_last, exit_code, data| {
            let (expect_is_last, expect_exit_code, expect_data) = data_map
                .get(&idx)
                .unwrap_or_else(|| panic!("idx `{}` not expect", idx));
            assert_eq!(*expect_is_last, is_last);
            assert_eq!(*expect_exit_code, exit_code);
            assert_eq!(*expect_data, data);
            Box::pin(async {})
        });
        let result = plugin.execute_stream(script, Some(cb), timeout).await;
        assert_eq!(expect_result, result.map_err(|e| e.to_string()));
    }

    fn test_execute_stream_data() -> Vec<(
        &'static str,
        Option<u64>,
        HashMap<u32, (bool, Option<i32>, Vec<u8>)>,
        Result<(), String>,
    )> {
        #[cfg(unix)]
        let cmd_timeout = [
            // Below data length with stderr
            ("echo -n foo >&2", None),
            // Below data length multiple outputs
            ("echo -n foo; sleep 1; echo -n foo", None),
            // Exceeding data length
            ("echo -n foo; echo -n foo", None),
            // Timeout without output
            ("while true; do sleep 100; done", Some(1)),
            // Timeout with exceeding data length multiple output
            ("while true; do echo -n foofoo; sleep 2; done", Some(1)),
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
                r#"[Console]::Write("foo"); Start-Sleep -Seconds 1; [Console]::Error.Write("foo")"#,
                None,
            ),
            // Exceeding data length
            (r#"[Console]::Write("foofoo")"#, None),
            // Timeout without output
            ("while ($true) { Start-Sleep -Seconds 100 }", Some(1)),
            // Timeout with exceeding data length multiple output
            (
                r#"while ($true) { [Console]::Write("foofoo"); Start-Sleep -Seconds 2 }"#,
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
                HashMap::from([(0, (true, Some(-1), vec![]))]),
                Err("command timeout, process killed".to_owned()),
            ),
            (
                // Timeout with exceeding data length multiple output
                HashMap::from([
                    (0, (false, None, b"foofo".to_vec())),
                    (1, (false, None, b"o".to_vec())),
                    (2, (true, Some(-1), vec![])),
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
