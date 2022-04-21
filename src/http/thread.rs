use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::{mpsc::Receiver, mpsc::TryRecvError};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::SystemTime;

use async_std::task;
use log::{debug, error, info};
use tokio::runtime::Builder;
use tokio::sync::Mutex;

use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{DEFAULT_OUTPUT_BYTE, FINISH_RESULT_TERMINATED};
use crate::common::envs;
use crate::executor::proc;
use crate::executor::proc::MyCommand;
use crate::http::store::TaskFileStore;
use crate::http::InvokeAPIAdapter;
use crate::types::inner_msg::KickMsg;
use crate::types::{InvocationCancelTask, InvocationNormalTask};

// 实现http线程的启动，内部使用异步runtime
pub fn run(msg_receiver: Receiver<KickMsg>, running_task_num: Arc<AtomicU64>) -> JoinHandle<()> {
   
    let thread_handle = thread::spawn(move || {
        let rt_res = Builder::new().basic_scheduler().enable_all().build();
        match rt_res {
            Ok(mut rt) => loop {
                match msg_receiver.try_recv() {
                    Ok(msg) => {
                        let adapter = InvokeAPIAdapter::build(envs::get_invoke_url().as_str());
                        let worker = Arc::new(HttpWorker::new(adapter, running_task_num.clone()));
                        rt.spawn(async move { worker.process(msg).await });
                    }
                    Err(e) => match e {
                        TryRecvError::Empty => {
                            rt.block_on(async {
                                task::sleep(Duration::from_millis(100)).await;
                            });
                            debug!("http thread channel empty, async await");
                        }
                        TryRecvError::Disconnected => {
                            error!("http thread channel disconnected, break");
                            break;
                        }
                    },
                };
            },
            Err(e) => {
                error!("http thread runtime error: {}", e);
            }
        }
    });
    thread_handle
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
            "http worker create success, save tasks to {}",
            task_store.get_store_path().as_path().display().to_string()
        );
        HttpWorker {
            adapter,
            task_store,
            running_task_num,
            running_tasks: Mutex::new(HashMap::new()),
        }
    }

    pub async fn process(&self, msg: KickMsg) -> Option<u64> {
        info!("http thread processing message from: {}", msg.kick_source);
        match self.adapter.describe_tasks().await {
            Ok(resp) => {
                info!("describe task success: {:?}", resp);
                for task in resp.invocation_normal_task_set.iter() {
                    match self.task_store.store(&task) {
                        Ok((task_file, log_file)) => {
                            // if task is not in command cache, execute it
                            self.task_execute(task, &task_file, &log_file).await;
                        }
                        Err(_) => {
                            // script file store failed, reuse this flow to report start failed
                            self.task_execute(task, "", "").await;
                        }
                    }
                }
                for task in resp.invocation_cancel_task_set.iter() {
                    self.task_cancel(&task).await;
                }
                Some(resp.invocation_normal_task_set.len() as u64)
            }
            Err(why) => {
                error!("describe task failed: {:?}", why);
                None
            }
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
            // total sleep max 20 * 50 ms, i.e. 1s
            for _n in 0..20 {
                if finished {
                    break;
                } else {
                    task::sleep(Duration::from_millis(50)).await;
                    finished = cmd_arc.lock().await.is_finished();
                }
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
                    if dropped > first_dropped {
                        final_log_index = idx;
                        info!(
                            "ready to report output dropped length:idx:{}, dropped:{}, output_debug:{}",
                            idx,
                            dropped,
                            String::from_utf8_lossy(&out[..]).replace("\n", "\\n"),
                        );
                        // final dropped bytes report task here
                        self.upload_task_log(task_id, idx, out, dropped).await;
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
        self.running_task_num.fetch_add(1, Ordering::SeqCst);
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

        self.adapter
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
            .map_err(|e| {
                error!(
                    "report task {} finish error: {:?}",
                    &task.invocation_task_id, e
                );
            })
            .ok();
        self.running_task_num.fetch_sub(1, Ordering::SeqCst);
        // process finish ,remove
        self.running_tasks
            .lock()
            .await
            .remove(task.invocation_task_id.as_str());
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
            let cmd = cmd_arc.lock().await;
            cmd.cancel()
                .map(|_| {
                    info!("cancel task {} success", &cancel_task_id);
                })
                .map_err(|e| {
                    error!("task {} cancel fail, error: {}", &cancel_task_id, e);
                })
                .ok();
            return;
        } else {
            info!(
                "task {} not find, may be not start or finished",
                &cancel_task_id
            );
        }

        // report terminated
        let finish_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_exit("sys time may before 1970")
            .as_secs();
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
        return match self.adapter.report_task_start(task_id, timestamp).await {
            Err(e) => {
                error!("report start error: {:?}", e);
                false
            }
            Ok(_) => true,
        };
    }

    async fn upload_task_log(&self, task_id: &str, idx: u32, out: Vec<u8>, dropped: u64) {
        match self
            .adapter
            .upload_task_log(task_id, idx, out, dropped)
            .await
        {
            Ok(_) => {
                info!("success upload task {} log index: {}", task_id, idx);
            }
            Err(e) => {
                error!("fail to upload task {} log: {:?}", task_id, e);
            }
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
            info!("fetch duplicate task,task id {}", task_id);
            return None;
        }

        let start_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_exit("sys time may before 1970")
            .as_secs();

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
            .map_err(|e| error!("start process fail {}", e))
            .ok();
        let cmd_arc = Arc::new(Mutex::new(proc_res));

        tasks.insert(task_id, cmd_arc.clone());
        return Some(cmd_arc);
    }
}

#[cfg(test)]
mod tests {
    use crate::common::consts::FINISH_RESULT_TERMINATED;
    use crate::common::logger;
    #[cfg(windows)]
    use crate::executor::powershell_command::get_current_user;
    use crate::executor::proc;
    use crate::executor::proc::MyCommand;
    use crate::http::store::TaskFileStore;
    use crate::http::thread::HttpWorker;
    use crate::http::InvokeAPIAdapter;
    use crate::types::{
        AgentError, AgentErrorCode, InvocationCancelTask, InvocationNormalTask,
        ReportTaskFinishResponse, ReportTaskStartResponse,
    };
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::time::timeout;
    #[cfg(unix)]
    use users::get_current_username;

    fn gen_rand_str() -> String {
        thread_rng().sample_iter(&Alphanumeric).take(10).collect()
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
            #[cfg(unix)]
            username: String::from(get_current_username().unwrap().to_str().unwrap()),
            #[cfg(windows)]
            username: get_current_user(),
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
    async fn test_report_start_fail() {
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
    async fn test_report_start_sucess() {
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
