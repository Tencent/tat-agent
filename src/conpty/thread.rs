use crate::common::consts::{
    EVENT_SLOT_PTY_CMD, PTY_FLAG_INIT_BLOCK, PTY_REMOVE_INTERVAL, PTY_WS_MSG,
    WS_MSG_TYPE_PTY_ERROR, WS_MSG_TYPE_PTY_INPUT, WS_MSG_TYPE_PTY_OUTPUT, WS_MSG_TYPE_PTY_READY,
    WS_MSG_TYPE_PTY_RESIZE, WS_MSG_TYPE_PTY_START, WS_MSG_TYPE_PTY_STOP,
};
use crate::common::evbus::EventBus;
use crate::conpty::{PtySession, PtySystem};

use crate::types::ws_msg::{PtyError, PtyInput, PtyReady, PtyResize, PtyStop, WsMsg};
use crate::types::ws_msg::{PtyOutput, PtyStart};
use log::{error, info};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering, Ordering::SeqCst};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::runtime::Runtime;
use tokio::time::timeout;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use super::unix::install_scripts;
        use super::unix::ConPtySystem;
        use users::get_current_username;
    } else if #[cfg(windows)] {
        use super::windows::ConPtySystem;
        use crate::executor::powershell_command::get_current_user;
    }
}

#[derive(Clone)]
pub(crate) struct Session {
    session_id: String,
    pty_session: Arc<dyn PtySession + Send + Sync>,
    writer: Arc<Mutex<File>>,
    last_input_time: Arc<AtomicU64>,
}

#[derive(Clone)]
pub(crate) struct SessionManager {
    ws_seq_num: Arc<AtomicU64>,
    running_task_num: Arc<AtomicU64>,
    pub(crate) session_map: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    pub(crate) event_bus: Arc<EventBus>,
    runtime: Arc<Runtime>,
}

pub fn run(dispatcher: &Arc<EventBus>, running_task_num: &Arc<AtomicU64>) {
    #[cfg(unix)]
    install_scripts();

    let context = Arc::new(SessionManager {
        event_bus: dispatcher.clone(),
        session_map: Arc::new(RwLock::new(HashMap::default())),
        running_task_num: running_task_num.clone(),
        ws_seq_num: Arc::new(AtomicU64::new(0)),
        runtime: Arc::new(Runtime::new().unwrap()),
    });
    register_pty_hander(context.clone());
}

fn register_pty_hander(sm: Arc<SessionManager>) {
    let self_0 = sm.clone();
    let self_1 = sm.clone();
    let self_2 = sm.clone();
    let self_3 = sm.clone();
    sm.event_bus
        .slot_register(
            EVENT_SLOT_PTY_CMD,
            WS_MSG_TYPE_PTY_START,
            move |value: String| {
                self_0.handle_pty_start(value);
            },
        )
        .slot_register(
            EVENT_SLOT_PTY_CMD,
            WS_MSG_TYPE_PTY_STOP,
            move |value: String| {
                self_1.handle_pty_stop(&value);
            },
        )
        .slot_register(
            EVENT_SLOT_PTY_CMD,
            WS_MSG_TYPE_PTY_RESIZE,
            move |value: String| {
                self_2.handle_pty_resize(value);
            },
        )
        .slot_register(
            EVENT_SLOT_PTY_CMD,
            WS_MSG_TYPE_PTY_INPUT,
            move |value: String| {
                self_3.handle_pty_input(value);
            },
        );
}

impl SessionManager {
    fn handle_pty_start(&self, value: String) {
        info!("=>handle_pty_start {}", value);
        let pty_start: PtyStart = match serde_json::from_str(&value) {
            Ok(v) => v,
            _ => return,
        };

        let session_id = pty_start.session_id;
        let user_name = if pty_start.user_name.len() == 0 {
            #[cfg(unix)]
            {
                let name = get_current_username().unwrap();
                String::from(name.to_str().unwrap())
            }
            #[cfg(windows)]
            get_current_user()
        } else {
            pty_start.user_name
        };

        let mut flag: u32 = 0;
        if pty_start.init_block {
            flag = flag | PTY_FLAG_INIT_BLOCK
        }

        self.running_task_num.fetch_add(1, SeqCst);
        let pty_session =
            match ConPtySystem::default().openpty(&user_name, pty_start.cols, pty_start.rows, flag)
            {
                Ok(session) => session,
                Err(e) => {
                    error!("=>openpty err {}", e.to_string());
                    let msg = self.build_error_msg(session_id.clone(), e);
                    self.event_bus.dispatch(PTY_WS_MSG, msg);
                    self.running_task_num.fetch_sub(1, SeqCst);
                    return;
                }
            };

        let input_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let writer = pty_session.get_writer().unwrap();
        let session = Arc::new(Session {
            session_id: session_id.clone(),
            pty_session,
            writer: Arc::new(Mutex::new(writer)),
            last_input_time: Arc::new(AtomicU64::new(input_time)),
        });

        self.session_map
            .write()
            .unwrap()
            .insert(session_id.clone(), session.clone());

        let msg = self.build_ready_msg(session_id.clone());
        self.event_bus.dispatch(PTY_WS_MSG, msg);

        let self_0 = self.clone();
        self.runtime
            .spawn(async move { self_0.report_output(session).await });
        info!("handle_pty_start success");
    }

    fn handle_pty_stop(&self, value: &str) {
        info!("handle_pty_stop {}", value);
        let pty_stop: PtyStop = match serde_json::from_str(&value) {
            Ok(v) => v,
            _ => return,
        };
        self.remove_session(&pty_stop.session_id);
        info!("handle_pty_stop session {} removed ", &pty_stop.session_id);
    }

    fn handle_pty_resize(&self, value: String) {
        info!("handle_pty_resize {}", value);
        let pty_resize: PtyResize = match serde_json::from_str(&value) {
            Ok(v) => v,
            _ => return,
        };

        let session_id = pty_resize.session_id.clone();
        self.work_in_session(&session_id, move |session| {
            let _ = session.pty_session.resize(pty_resize.cols, pty_resize.rows);
        });
    }

    fn handle_pty_input(&self, value: String) {
        let pty_input: PtyInput = match serde_json::from_str(&value) {
            Ok(v) => v,
            _ => return,
        };

        let input_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Ok(input) = base64::decode(pty_input.input) {
            let session_id = pty_input.session_id.clone();
            self.work_in_session(&session_id, move |session| {
                let _ = session.writer.lock().unwrap().write(&input).unwrap();
                session.last_input_time.store(input_time, SeqCst);
            })
        }
    }

    async fn report_output(&self, session: Arc<Session>) {
        info!("=>report_output {}", session.session_id);
        let duration = Duration::from_millis(100);
        let mut reader = tokio::fs::File::from_std(session.pty_session.get_reader().unwrap());
        loop {
            //no input about five miniutes, break
            if !self.check_last_input_time(&session) {
                info!(
                    "pty session {}  check_last_input_time fail",
                    session.session_id
                );
                break;
            }

            let mut buffer: [u8; 1024] = [0; 1024];
            let timeout_read = timeout(duration, reader.read(&mut buffer[..])).await;
            if timeout_read.is_err() {
                continue;
            }
            match timeout_read.unwrap() {
                Ok(size) => {
                    if size > 0 {
                        let msg =
                            self.build_output_msg(session.session_id.clone(), &mut buffer[0..size]);
                        self.event_bus.dispatch(PTY_WS_MSG, msg);
                    } else {
                        info!("pty session {} read size is 0 close", session.session_id);
                        break;
                    }
                }
                Err(e) => {
                    info!(
                        "pty session {} report_output err, {}",
                        session.session_id, e
                    );
                    break;
                }
            }
        }
        self.remove_session(&session.session_id);
        info!("report_output {} finished", session.session_id);
    }

    fn remove_session(&self, session_id: &str) {
        if self
            .session_map
            .write()
            .unwrap()
            .remove(session_id)
            .is_some()
        {
            info!("remove_session  {} removed", session_id);
            self.running_task_num.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn check_last_input_time(&self, session: &Arc<Session>) -> bool {
        let last = session.last_input_time.load(SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        return if now - last > PTY_REMOVE_INTERVAL {
            false //time out
        } else {
            true
        };
    }

    pub(crate) fn work_in_session<F>(&self, session_id: &str, func: F)
    where
        F: Fn(Arc<Session>) + 'static + Sync + Send,
    {
        if let Some(session) = self.session_map.read().unwrap().get(session_id) {
            func(session.clone());
        } else {
            error!("Session {} not find", session_id);
            let msg = self.build_error_msg(
                session_id.to_string(),
                format!("Session {} not exist", session_id),
            );
            self.event_bus.dispatch(PTY_WS_MSG, msg);
        }
    }

    fn build_output_msg(&self, session_id: String, buf: &mut [u8]) -> String {
        let data = base64::encode(buf);
        let pty_output = PtyOutput {
            session_id,
            output: data,
        };
        self.build_msg(WS_MSG_TYPE_PTY_OUTPUT, pty_output)
    }

    fn build_ready_msg(&self, session_id: String) -> String {
        let pty_ready = PtyReady { session_id };
        self.build_msg(WS_MSG_TYPE_PTY_READY, pty_ready)
    }

    fn build_error_msg(&self, session_id: String, reason: String) -> String {
        let pty_ready = PtyError { session_id, reason };
        self.build_msg(WS_MSG_TYPE_PTY_ERROR, pty_ready)
    }

    fn build_msg<T>(&self, msg_type: &str, msg_body: T) -> String
    where
        T: Serialize,
    {
        let value = serde_json::to_value(msg_body).unwrap();
        let msg = WsMsg {
            r#type: msg_type.to_string(),
            seq: self.ws_seq_num.fetch_add(1, SeqCst),
            data: Some(value),
        };
        serde_json::to_string(&msg).unwrap()
    }
}

#[cfg(test)]
mod test {
    #[cfg(unix)]
    use crate::conpty::unix::ConPtySystem;
    #[cfg(windows)]
    use crate::conpty::windows::ConPtySystem;
    use crate::conpty::PtySystem;
    #[cfg(windows)]
    use crate::executor::powershell_command::get_current_user;
    use log::info;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;
    #[cfg(unix)]
    use users::get_current_username;

    #[tokio::test]
    async fn test() {
        #[cfg(unix)]
        let user_name = String::from(get_current_username().unwrap().to_str().unwrap());
        #[cfg(windows)]
        let user_name = get_current_user();

        let session = ConPtySystem::default()
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
