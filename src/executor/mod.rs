mod task;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

use self::task::{Task, EXIT_CODE_ERROR, TASK_RESULT_START_FAILED};
#[cfg(unix)]
pub use self::unix::{kill_process_group, User};
#[cfg(windows)]
pub use self::windows::{kill_process_group, User};
use crate::common::{evbus, get_now_secs, Stopper};
use crate::network::{InvocationCancelTask, InvocationNormalTask};
use crate::network::{Invoke, InvokeAdapter, EVENT_KICK};
use crate::STOP_COUNTER;

use std::collections::{HashMap, HashSet};
use std::str::from_utf8_unchecked;
use std::sync::{atomic::Ordering, Arc, LazyLock};
use std::time::Duration;

use log::{error, info};
use tokio::{sync::Mutex, time::sleep};

static EXECUTOR: LazyLock<Arc<Executor>> = LazyLock::new(Default::default);

pub async fn run() {
    let handler = |source: Vec<_>| {
        tokio::spawn(async move {
            // Safety: source was originally a String, so conversion back is safe.
            Executor::process::<InvokeAdapter>(unsafe { from_utf8_unchecked(&source) }).await
        })
    };
    evbus::subscribe(EVENT_KICK, handler).await;
}

#[derive(Default)]
struct Executor {
    running: Mutex<HashMap<String, Stopper>>,
    cache: Mutex<HashSet<String>>,
}

impl Executor {
    async fn process<T: Invoke>(source: &str) {
        info!("executor start processing dispatch from: {}", source);
        let resp = match T::describe_tasks().await {
            Ok(resp) => resp,
            Err(e) => return error!("describe task failed: {e:#}"),
        };
        info!("describe task success: {:?}", resp);

        for task in resp.invocation_normal_task_set {
            EXECUTOR.clone().execute::<T>(task).await;
        }
        for cancel in resp.invocation_cancel_task_set {
            EXECUTOR.cancel(cancel).await;
        }
    }

    async fn execute<T: Invoke>(self: Arc<Self>, task: InvocationNormalTask) -> bool {
        let id = task.invocation_task_id.clone();
        if self.cache.lock().await.replace(id.clone()).is_some() {
            return false;
        }

        STOP_COUNTER.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            info!("task `{id}` execute begin");
            let stopper = Stopper::new();
            let rx = stopper.get_receiver().await.unwrap();
            self.running.lock().await.insert(id.clone(), stopper);
            if let Err(e) = T::report_task_start(&id, get_now_secs()).await {
                error!("task `{id}` report_task_start error: {e:#}");
                STOP_COUNTER.fetch_sub(1, Ordering::Relaxed);
                self.running.lock().await.remove(&id);
                self.cache.lock().await.remove(&id); // id is not cached if report_task_start fails
                return;
            }
            if let Err(e) = Task::start::<T>(task, rx).await {
                info!("task `{id}` start failed: {e:#}");
                let r = TASK_RESULT_START_FAILED;
                let e = format!("{e:#}");
                let code = EXIT_CODE_ERROR;
                let ts = get_now_secs();
                if let Err(e) = T::report_task_finish(&id, r, &e, code, None, ts, "", "", 0).await {
                    error!("task `{id}` report_task_finish error: {e:#}")
                }
            };
            STOP_COUNTER.fetch_sub(1, Ordering::Relaxed);
            self.running.lock().await.remove(&id);
            tokio::spawn(async move {
                sleep(Duration::from_secs(120)).await; // cache the id
                self.cache.lock().await.remove(&id);
            });
        });
        true
    }

    async fn cancel(&self, cancel: InvocationCancelTask) -> bool {
        let Some(stopper) = self.running.lock().await.remove(&cancel.invocation_task_id) else {
            return false;
        };
        info!("task `{}` cancel begin", &cancel.invocation_task_id);
        stopper.stop().await;
        true
    }
}

#[cfg(test)]
pub mod test {
    use super::{task::*, *};
    use crate::{common::*, network::*, EXE_DIR};

    use std::{future::pending, iter::repeat_n, sync::Arc};

    use anyhow::{bail, Result};
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[cfg(unix)]
    const SLEEP: &str = "sleep";
    #[cfg(unix)]
    const ECHO: &str = "echo -n";
    #[cfg(windows)]
    const SLEEP: &str = "Start-Sleep -s";
    #[cfg(windows)]
    const ECHO: &str = "Write-Host -NoNewline";

    pub fn new_task(cmd: &str) -> InvocationNormalTask {
        #[cfg(unix)]
        let command_type = "SHELL";
        #[cfg(windows)]
        let command_type = "POWERSHELL";
        InvocationNormalTask {
            invocation_task_id: format!("invt-{}", gen_rand_str_with(10)),
            time_out: 60,
            command: STANDARD.encode(cmd),
            command_type: command_type.to_string(),
            username: get_current_username(),
            working_directory: EXE_DIR.display().to_string(),
            cos_bucket_url: "".to_string(),
            cos_bucket_prefix: "".to_string(),
        }
    }

    macro_rules! impl_invoke {
        ($type:ty, $closure:expr) => {
            impl Invoke for $type {
                async fn report_task_start(_: &str, _: u64) -> Result<ReportTaskStartResponse> {
                    Ok(ReportTaskStartResponse {})
                }
                async fn report_task_finish(
                    _: &str,
                    result: &str,
                    _: &str,
                    exit_code: i32,
                    final_log_index: Option<u32>,
                    _: u64,
                    _: &str,
                    _: &str,
                    dropped: u64,
                ) -> Result<ReportTaskFinishResponse> {
                    let closure = $closure;
                    closure(result, exit_code, final_log_index, dropped)
                }
                async fn upload_task_log(
                    _: &str,
                    _: u32,
                    _: Vec<u8>,
                    _: u64,
                ) -> Result<UploadTaskLogResponse> {
                    Ok(UploadTaskLogResponse {})
                }
            }
        };
    }

    #[tokio::test]
    async fn test_report_task_start_error() {
        struct ReportTaskStartError;
        impl Invoke for ReportTaskStartError {
            async fn report_task_start(_: &str, _: u64) -> Result<ReportTaskStartResponse> {
                bail!("mock report_task_start error")
            }
        }

        let exc = Arc::<Executor>::default();
        let task = new_task("");
        let found_new = exc.clone().execute::<ReportTaskStartError>(task).await;
        assert!(found_new);
        sleep(Duration::from_secs(1)).await;
        assert_eq!(exc.cache.lock().await.len(), 0); // id is not cached if report_task_start fails
    }

    #[tokio::test]
    async fn test_report_task_finish_error() {
        struct ReportTaskFinishError;
        impl_invoke!(ReportTaskFinishError, |_, _, _, _| bail!(""));

        let exc = Arc::<Executor>::default();
        let task = new_task("");
        let found_new = exc.clone().execute::<ReportTaskFinishError>(task).await;
        assert!(found_new);
        sleep(Duration::from_secs(1)).await;
        assert_eq!(exc.cache.lock().await.len(), 1); // id is cached if report_task_start success
    }

    #[tokio::test]
    async fn test_start_failed() {
        struct DoNothing;
        impl_invoke!(DoNothing, |_, _, _, _| Ok(ReportTaskFinishResponse {}));

        let mut task = new_task("");
        task.command_type = "NOT_EXIST_TYPE".to_string();
        let res = Task::start::<DoNothing>(task, pending::<()>()).await;
        assert!(res.is_err());

        let mut task = new_task("");
        task.username = "NOT_EXIST_USERNAME".to_string();
        let res = Task::start::<DoNothing>(task, pending::<()>()).await;
        assert!(res.is_err());

        let mut task = new_task("");
        task.working_directory = "NOT_EXIST_WORKDIR".to_string();
        let res = Task::start::<DoNothing>(task, pending::<()>()).await;
        assert!(res.is_err());

        let mut task = new_task("");
        task.command = "NOT_BASE64_CMD".to_string();
        let res = Task::start::<DoNothing>(task, pending::<()>()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_success() {
        struct Success;
        impl_invoke!(Success, |result, exit_code, _, _| {
            assert_eq!(result, "SUCCESS");
            assert_eq!(exit_code, 0);
            Ok(ReportTaskFinishResponse {})
        });
        let task = new_task("exit 0");
        let res = Task::start::<Success>(task, pending::<()>()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_failed() {
        struct Failed;
        impl_invoke!(Failed, |result, exit_code, _, _| {
            assert_eq!(result, "FAILED");
            assert_eq!(exit_code, 1);
            Ok(ReportTaskFinishResponse {})
        });
        let task = new_task("exit 1");
        let res = Task::start::<Failed>(task, pending::<()>()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_timeout() {
        struct Timeout;
        impl_invoke!(Timeout, |result, exit_code, _, _| {
            assert_eq!(result, "TIMEOUT");
            assert_eq!(exit_code, -1);
            Ok(ReportTaskFinishResponse {})
        });
        let mut task = new_task(&format!("{SLEEP} 10"));
        task.time_out = 1;
        let res = Task::start::<Timeout>(task, pending::<()>()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_cancel() {
        struct Cancel;
        impl_invoke!(Cancel, |result, exit_code, _, _| {
            assert_eq!(result, "TERMINATED");
            assert_eq!(exit_code, -1);
            Ok(ReportTaskFinishResponse {})
        });
        let exc = Arc::<Executor>::default();
        let task = new_task(&format!("{SLEEP} 10"));
        let task_id = task.invocation_task_id.clone();
        let cancel = InvocationCancelTask {
            invocation_task_id: task_id.clone(),
        };
        let stopper = Stopper::new();
        let rx = stopper.get_receiver().await.unwrap();
        exc.running.lock().await.insert(task_id, stopper);
        let jh = tokio::spawn(async move { Task::start::<Cancel>(task, rx).await });
        sleep(Duration::from_secs(1)).await;
        exc.cancel(cancel).await;
        let res = jh.await;
        assert!(res.is_ok()); // no panic
        assert!(res.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_output() {
        struct Output;
        impl_invoke!(Output, |_, _, idx, dropped| {
            assert_eq!(idx, Some(1));
            assert_eq!(dropped, 0);
            Ok(ReportTaskFinishResponse {})
        });

        let task = new_task(&format!("{ECHO} 1\n{SLEEP} 2\n{ECHO} 2"));
        let res = Task::start::<Output>(task, pending::<()>()).await;
        assert!(res.is_ok());

        let long_output = repeat_n('x', MAX_SINGLE_REPORT_BYTES).collect::<String>();
        let script = format!("{ECHO} {long_output}\n{SLEEP} 2\n{ECHO} {long_output}");
        let task = new_task(&script);
        let res = Task::start::<Output>(task, pending::<()>()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_full_and_dropped() {
        struct Full;
        impl_invoke!(Full, |_, _, _, dropped| {
            assert_eq!(dropped, 0);
            Ok(ReportTaskFinishResponse {})
        });
        let long_output = repeat_n('x', MAX_REPORT_BYTES as usize).collect::<String>();
        let task = new_task(&format!("{ECHO} {long_output}"));
        let res = Task::start::<Full>(task, pending::<()>()).await;
        assert!(res.is_ok());

        struct Dropped;
        impl_invoke!(Dropped, |_, _, _, dropped| {
            assert_eq!(dropped, 1);
            Ok(ReportTaskFinishResponse {})
        });
        let long_output = repeat_n('x', MAX_REPORT_BYTES as usize + 1).collect::<String>();
        let task = new_task(&format!("{ECHO} {long_output}"));
        let res = Task::start::<Dropped>(task, pending::<()>()).await;
        assert!(res.is_ok());
    }
}
