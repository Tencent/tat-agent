use crate::common::evbus::EventBus;
use crate::common::utils::get_now_secs;
use crate::executor::proc::{self, MyCommand};
use crate::executor::store::TaskFileStore;
use crate::network::types::ws_msg::WS_MSG_TYPE_KICK;
use crate::network::types::{InvocationCancelTask, InvocationNormalTask};
use crate::network::InvokeAPIAdapter;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio::time::delay_for;

use super::FINISH_RESULT_TERMINATED;
const DEFAULT_OUTPUT_BYTE: u64 = 24 * 1024;

pub fn run(dispatcher: &Arc<EventBus>, running_task_num: &Arc<AtomicU64>) {
    let runtime = Runtime::new().expect("executor-runime build failed");

    let running_task_num = running_task_num.clone();
    dispatcher.register(WS_MSG_TYPE_KICK, move |source| {
        let source = String::from_utf8_lossy(&source).to_string(); //from vec to string
        let running_task_num = running_task_num.clone();
        runtime.spawn(async move {
            let adapter = InvokeAPIAdapter::new();
            let worker = Arc::new(HttpWorker::new(adapter, running_task_num.clone()));
            worker.process(source).await
        });
    });
}

pub struct HttpWorker {
    adapter: InvokeAPIAdapter,
    task_store: TaskFileStore,
    running_tasks: Mutex<HashMap<String, Arc<Mutex<Box<dyn MyCommand + Send>>>>>,
    running_task_num: Arc<AtomicU64>,
}

impl HttpWorker {
    pub fn new(adapter: InvokeAPIAdapter, running_task_num: Arc<AtomicU64>) -> Self {
        let task_store = TaskFileStore::new();
        info!(
            "http worker create success, save tasks to `{}`",
            task_store.get_store_path().as_path().display().to_string()
        );
        HttpWorker {
            adapter,
            task_store,
            running_task_num,
            running_tasks: Mutex::new(HashMap::new()),
        }
    }

    pub async fn process(&self, source: String) {
        info!("http thread processing message from: {}", source);
        for _ in 0..3 {
            let resp = match self.adapter.describe_tasks().await {
                Ok(resp) => resp,
                Err(why) => return error!("describe task failed: {:?}", why),
            };

            info!("describe task success: {:?}", resp);
            if source == "ws"
                && resp.invocation_normal_task_set.is_empty()
                && resp.invocation_cancel_task_set.is_empty()
            {
                delay_for(Duration::from_millis(500)).await;
                continue;
            }
            for task in resp.invocation_normal_task_set.iter() {
                self.running_task_num.fetch_add(1, Ordering::SeqCst);
                let (task_file, log_file) = self.task_store.store(&task).unwrap_or_default();
                self.task_execute(task, &task_file, &log_file).await;
                self.running_task_num.fetch_sub(1, Ordering::SeqCst);
            }
            for task in resp.invocation_cancel_task_set.iter() {
                self.task_cancel(&task).await;
            }
            return;
        }
    }

    async fn read_and_report(
        &self,
        cmd_arc: Arc<Mutex<Box<dyn MyCommand + Send>>>,
        task_id: &str,
    ) -> u32 {
        let mut stop_upload = false;
        let mut final_log_index: u32 = 0;
        let mut first_dropped: u64 = 0;
        let mut finished = cmd_arc.lock().await.is_finished();
        loop {
            // total delay_for max 20 * 50 ms, i.e. 1s
            for _ in 0..20 {
                if finished {
                    break;
                }
                delay_for(Duration::from_millis(50)).await;
                finished = cmd_arc.lock().await.is_finished();
            }
            let mut cmd = cmd_arc.lock().await;
            if cmd.cur_output_len() != 0 && !stop_upload {
                let (out, idx, dropped) = cmd.next_output();
                final_log_index = idx;
                // print output in one line
                info!(
                    "ready to report output length:{:?}, idx:{}, dropped:{}, output_debug:{}",
                    out.len(),
                    idx,
                    dropped,
                    String::from_utf8_lossy(&out[..]).replace("\n", "\\n"),
                );
                // output report task here
                self.upload_task_log(task_id, idx, out, dropped).await;

                if dropped > 0 {
                    stop_upload = true;
                    first_dropped = dropped;
                }
            }
            if stop_upload {
                // Do not report output any more in next loop, because of max report exceed
                info!(
                    "task {}: max log size exceeds, command still running but not report output anymore, only report final dropped bytes when task finished.",
                    task_id
                );
            }
            if finished {
                // report final dropped bytes of output when task is already finished and max report exceed.
                // otherwise check finish flag again after a while
                info!("task {} finished.", task_id);

                if stop_upload {
                    let (out, idx, dropped) = cmd.next_output();
                    // dropped > first_dropped means more output generated after first drop occur,
                    // so need update final idx and drop when cmd finished.
                    let last_index = idx;
                    if dropped > first_dropped {
                        final_log_index = last_index;
                        info!(
                            "ready to report output dropped length:idx:{}, dropped:{}, output_debug:{}",
                            last_index,
                            dropped,
                            String::from_utf8_lossy(&out[..]).replace("\n", "\\n"),
                        );
                        // final dropped bytes report task here
                        self.upload_task_log(task_id, last_index, out, dropped)
                            .await;
                        info!("report final dropped bytes of output.");
                    }
                }
                break;
            }
        }
        final_log_index
    }

    // report task start
    // start Command to execute task
    // upload task log
    // report task finish
    async fn task_execute(
        &self,
        task: &InvocationNormalTask,
        task_file: &str,
        task_log_file: &str,
    ) {
        info!("task execute begin: {:?}", task);
        let task_id = task.invocation_task_id.clone();
        let result = self.create_proc(task_file, task_log_file, task).await;
        if result.is_none() {
            return;
        }
        let cmd_arc = result.unwrap();

        let mut final_log_index = 0;
        if cmd_arc.lock().await.is_started() {
            final_log_index = self.read_and_report(cmd_arc.clone(), &task_id).await;
        }

        let cmd = cmd_arc.lock().await;
        // report finish
        let finish_result = cmd.finish_result();
        let err_info = cmd.err_info();
        let exit_code = cmd.exit_code();
        let finish_time = cmd.finish_time();
        let output_url = cmd.output_url();
        let output_err_info = cmd.output_err_info();

        //remove lock, important
        std::mem::drop(cmd);

        //remove script after finished
        match std::fs::remove_file(&task_file) {
            Ok(_) => info!("delete `{}` success", task_file),
            Err(e) => error!("delete `{}` failed: {}", task_file, e),
        };

        let _ = self
            .adapter
            .report_task_finish(
                &task_id,
                &finish_result,
                &err_info,
                exit_code,
                final_log_index,
                finish_time,
                &output_url,
                &output_err_info,
            )
            .await
            .map(|_| info!("task_execute report_task_finish {} success", task_id))
            .map_err(|e| error!("report task {task_id} finish error: {e:?}"));

        // process finish, remove
        self.running_tasks.lock().await.remove(task_id.as_str());
    }

    async fn task_cancel(&self, task: &InvocationCancelTask) {
        info!("=>task_cancel");
        let cancel_task_id = task.invocation_task_id.clone();
        //mutex with create_proc
        let tasks = self.running_tasks.lock().await;
        let task = tasks.get(cancel_task_id.as_str());
        if let Some(cmd_arc) = task {
            let cmd_arc = cmd_arc.clone();
            //drop lock
            std::mem::drop(tasks);
            let _ = cmd_arc
                .lock()
                .await
                .cancel()
                .map(|_| info!("cancel task {} success", &cancel_task_id))
                .map_err(|e| error!("task {} cancel failed, error: {}", &cancel_task_id, e));
            return;
        } else {
            info!("task {cancel_task_id} not found, may be not start or finished",);
        }

        // report terminated
        let finish_time = get_now_secs();
        self.adapter
            .report_task_finish(
                &cancel_task_id,
                FINISH_RESULT_TERMINATED,
                "",
                0,
                0,
                finish_time,
                "",
                "",
            )
            .await
            .map(|_| info!("task_cancel report_task_finish {} success", cancel_task_id))
            .map_err(|e| {
                error!("report task {} terminate error: {:?}", cancel_task_id, e);
            })
            .ok();
    }

    async fn report_task_start(&self, task_id: &str, timestamp: u64) -> bool {
        self.adapter
            .report_task_start(task_id, timestamp)
            .await
            .map_err(|e| error!("report start error: {:?}", e))
            .is_ok()
    }

    async fn upload_task_log(&self, task_id: &str, idx: u32, out: Vec<u8>, dropped: u64) {
        match self
            .adapter
            .upload_task_log(task_id, idx, out, dropped)
            .await
        {
            Ok(_) => info!("success upload task {}, log index: {}", task_id, idx),
            Err(e) => error!("failed to upload task {} log: {:?}", task_id, e),
        }
    }

    async fn create_proc(
        &self,
        task_file: &str,
        task_log_file: &str,
        task: &InvocationNormalTask,
    ) -> Option<Arc<Mutex<Box<dyn MyCommand + Send>>>> {
        let task_id = task.invocation_task_id.clone();
        //mutex with task_cancel
        let mut tasks = self.running_tasks.lock().await;
        if tasks.contains_key(&task_id) {
            info!("fetch duplicate task, task id {}", task_id);
            return None;
        }

        let start_timestamp = get_now_secs();

        let result = self
            .report_task_start(task.invocation_task_id.as_str(), start_timestamp)
            .await;
        if !result {
            return None;
        }

        // remove suffix '/' of cos_bucket_prefix if exists.
        let cos_bucket_prefix = if let Some(prefix) = task.cos_bucket_prefix.strip_suffix("/") {
            prefix
        } else {
            &task.cos_bucket_prefix
        };
        let proc_result = proc::new(
            task_file,
            &task.username,
            &task.command_type,
            &task.working_directory,
            task.time_out,
            DEFAULT_OUTPUT_BYTE,
            task_log_file,
            &task.cos_bucket_url,
            cos_bucket_prefix,
            &task_id,
        );
        if proc_result.is_err() {
            return None;
        }
        let mut proc_res = proc_result.unwrap();
        proc_res
            .run()
            .await
            .map_err(|e| error!("start process failed: {}", e))
            .ok();
        let cmd_arc = Arc::new(Mutex::new(proc_res));

        tasks.insert(task_id, cmd_arc.clone());
        return Some(cmd_arc);
    }
}

#[cfg(test)]
mod tests {
    use crate::common::logger;
    use crate::common::utils::{gen_rand_str_with, get_current_username};
    use crate::executor::proc::{self, MyCommand};
    use crate::executor::store::TaskFileStore;
    use crate::executor::thread::HttpWorker;
    use crate::executor::FINISH_RESULT_TERMINATED;
    use crate::network::types::{
        AgentError, AgentErrorCode, InvocationCancelTask, InvocationNormalTask,
        ReportTaskFinishResponse, ReportTaskStartResponse,
    };
    use crate::network::InvokeAPIAdapter;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::time::timeout;

    fn gen_rand_str() -> String {
        gen_rand_str_with(10)
    }

    fn create_file(content: &str, filename: &str) {
        File::create(filename)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        #[cfg(unix)]
        std::process::Command::new("chmod")
            .args(&["+x", filename])
            .status()
            .unwrap();
    }

    fn get_http_worker() -> HttpWorker {
        HttpWorker {
            adapter: InvokeAPIAdapter::faux(),
            task_store: TaskFileStore::new(),
            running_tasks: Default::default(),
            running_task_num: Arc::new(Default::default()),
        }
    }

    fn build_invocation(
        task_id: &str,
        cmd: &str,
        time_out: u64,
        cmd_type: &str,
    ) -> InvocationNormalTask {
        InvocationNormalTask {
            invocation_task_id: task_id.to_string(),
            time_out,
            command: cmd.to_string(),
            command_type: cmd_type.to_string(),
            username: get_current_username(),
            working_directory: "./".to_string(),
            cos_bucket_url: "".to_string(),
            cos_bucket_prefix: "".to_string(),
        }
    }

    fn fake_command() -> Arc<Mutex<Box<dyn MyCommand + Send>>> {
        #[cfg(unix)]
        let cmd_type = "SHELL";
        #[cfg(windows)]
        let cmd_type = "POWERSHELL";
        let result = proc::new("", "", cmd_type.as_ref(), "", 10, 1024, "", "", "", "");
        Arc::new(Mutex::new(result.unwrap()))
    }

    #[tokio::test]
    async fn test_report_dup_task() {
        let http_worker = get_http_worker();
        http_worker
            .running_tasks
            .lock()
            .await
            .insert("invt-1111".to_string(), fake_command());

        let task = build_invocation("invt-1111", "", 5, "POWERSHELL");
        let result = http_worker
            .create_proc("/fake_path", "/fake_path", &task)
            .await;
        assert_eq!(result.is_none(), true);
    }

    #[tokio::test]
    async fn test_report_start_failed() {
        #[cfg(unix)]
        let cmd_type = "SHELL";
        #[cfg(windows)]
        let cmd_type = "POWERSHELL";

        let mut http_worker = get_http_worker();
        http_worker
            .running_tasks
            .lock()
            .await
            .insert("invt-1122".to_string(), fake_command());
        let task = build_invocation("invt-1111", "", 5, cmd_type.as_ref());
        faux::when!(http_worker.adapter.report_task_start)
            .then_return(Err(AgentError::new(AgentErrorCode::ResponseReadError, "")));
        let result = http_worker
            .create_proc("/fake_path", "/fake_path", &task)
            .await;
        assert_eq!(result.is_none(), true);
    }

    #[tokio::test]
    async fn test_report_start_success() {
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let filename = format!("./.{}.sh", gen_rand_str());
                let cmd_type = "SHELL";
                create_file("sleep 1", filename.as_str());
            } else if #[cfg(windows)] {
                let filename = format!("./{}.ps1", gen_rand_str());
                let cmd_type = "POWERSHELL";
                create_file(
                    "Start-Sleep -s 1",
                    filename.as_str(),
                );
            }
        }
        let mut http_worker = get_http_worker();
        let task = build_invocation("invt-1133", "", 5, cmd_type);
        faux::when!(http_worker.adapter.report_task_start)
            .then_return(Ok(ReportTaskStartResponse {}));

        let result = http_worker
            .create_proc(filename.as_str(), "/fake_path", &task)
            .await;
        fs::remove_file(filename.as_str()).unwrap();
        assert_eq!(result.is_some(), true);
        assert_eq!(
            http_worker
                .running_tasks
                .lock()
                .await
                .get("invt-1133")
                .is_some(),
            true
        );
    }

    #[tokio::test]
    async fn test_create_mutex() {
        let http_worker = get_http_worker();
        let _lock = http_worker.running_tasks.lock().await;
        #[cfg(unix)]
        let cmd_type = "SHELL";
        #[cfg(windows)]
        let cmd_type = "POWERSHELL";
        let task = build_invocation("invt-1133", "", 5, cmd_type);
        let create_fut = http_worker.create_proc("", "/fake_path", &task);
        let time_out = timeout(Duration::from_secs(1), create_fut).await;
        assert_eq!(time_out.is_err(), true);
    }

    #[tokio::test]
    async fn test_cancel_mutex() {
        let http_worker = get_http_worker();
        let _lock = http_worker.running_tasks.lock().await;
        let task = InvocationCancelTask {
            invocation_task_id: "inv-xxxx".to_string(),
        };
        let create_fut = http_worker.task_cancel(&task);
        let time_out = timeout(Duration::from_secs(1), create_fut).await;
        assert_eq!(time_out.is_err(), true);
    }

    #[tokio::test]
    async fn test_cancel() {
        logger::init_test_log();
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let filename = format!("./.{}.sh", gen_rand_str());
                let cmd_type = "SHELL";
                create_file("sleep 1024", filename.as_str());
            } else if #[cfg(windows)] {
                let filename = format!("./{}.ps1", gen_rand_str());
                let cmd_type = "POWERSHELL";
                create_file(
                    "Start-Sleep -s 1024;",
                    filename.as_str(),
                );
            }
        }
        let mut http_worker = get_http_worker();
        let task = build_invocation("invt-test_cancel", "", 1025, cmd_type);
        faux::when!(http_worker.adapter.report_task_start)
            .then_return(Ok(ReportTaskStartResponse {}));

        faux::when!(http_worker.adapter.report_task_finish)
            .then_return(Ok(ReportTaskFinishResponse {}));

        let log_path = format!("./{}.log", gen_rand_str());
        let cmd = http_worker
            .create_proc(filename.as_str(), log_path.as_str(), &task)
            .await
            .unwrap();
        assert_eq!(cmd.lock().await.is_started(), true);
        let http_worker1 = Arc::new(http_worker);
        let http_worker2 = http_worker1.clone();
        let cmd_clone = cmd.clone();
        tokio::spawn(async move {
            http_worker1
                .read_and_report(cmd_clone, &task.invocation_task_id)
                .await;
        });

        let task = InvocationCancelTask {
            invocation_task_id: "invt-test_cancel".to_string(),
        };
        http_worker2.task_cancel(&task).await;
        tokio::time::delay_for(Duration::from_secs(1)).await;
        fs::remove_file(filename.as_str()).unwrap();
        let finis_result = cmd.lock().await.finish_result();
        assert_eq!(finis_result, FINISH_RESULT_TERMINATED); //need read twice
    }
}
