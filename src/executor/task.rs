use super::{decode_output, kill_process_group, User};
use crate::common::{cbs_exist, get_now_secs, Stopper};
use crate::executor::Executor;
use crate::network::urls::get_meta_url;
use crate::network::{COSAdapter, InvocationNormalTask, Invoke, MetadataAdapter};
use crate::EXE_DIR;

use std::fmt::{self, Display};
use std::mem::{swap, take};
use std::{cmp::min, sync::Arc, time::Duration};
use std::{path::PathBuf, process::ExitStatus};

use anyhow::{bail, Context, Result};
use log::{error, info};
use tokio::fs::{create_dir_all, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::{sleep_until, timeout_at, Instant};

#[cfg(windows)]
use super::windows::UTF8_BOM_HEADER;
pub const EXIT_CODE_ERROR: i32 = -1;
pub const MAX_REPORT_BYTES: u64 = 24 * 1024;
pub const MAX_SINGLE_REPORT_BYTES: usize = 4 * 1024;
pub const TASK_RESULT_START_FAILED: &str = "START_FAILED";
const TASK_RESULT_TIMEOUT: &str = "TIMEOUT";
const TASK_RESULT_TERMINATED: &str = "TERMINATED";
const TASK_RESULT_FAILED: &str = "FAILED";
const TASK_RESULT_SUCCESS: &str = "SUCCESS";
const EXTENSION_LOG: &str = "log";
const REPORT_INTERVAL_SECS: u64 = 1;
const BUF_SIZE: usize = 1024;

pub struct Task {
    pub info: TaskInfo,
    status: TaskStatus,
    output: TaskOutput,
    upload_conf: Option<TaskUploadConf>,
}

impl Task {
    async fn init(t: InvocationNormalTask) -> Result<Self> {
        let content = t.decode_command().context("InvalidCommand")?;
        let user = User::new(&t.username).context("InvalidUser")?;
        let info = TaskInfo {
            task_id: t.invocation_task_id,
            command_type: t.command_type,
            working_directory: t.working_directory,
            timeout: t.time_out,
            user,
        };
        info.check_working_directory()
            .await
            .context("InvalidWorkingDirectory")?;
        info.create_script(&content)
            .await
            .context("ScriptStoreFailed")?;

        let mut upload_conf = None;
        if !t.cos_bucket_url.is_empty() {
            let output_file = info
                .create_output_file()
                .await
                .context("OutputFileCreateFailed")?;
            let cos_bucket_prefix = t
                .cos_bucket_prefix
                .strip_suffix("/")
                .unwrap_or(&t.cos_bucket_prefix);
            upload_conf = Some(TaskUploadConf {
                cos_bucket_url: t.cos_bucket_url,
                cos_bucket_prefix: cos_bucket_prefix.to_owned(),
                output_file: Some(output_file),
            });
        };

        let status = TaskStatus::default();
        let output = TaskOutput::default();
        let task = Self {
            info,
            status,
            output,
            upload_conf,
        };
        Ok(task)
    }

    pub async fn start<T: Invoke>(t: InvocationNormalTask, exc: &Arc<Executor>) -> Result<()> {
        let mut task = Task::init(t).await?;
        let (mut child, mut reader) = task.spawn().await.context("TaskSpawnFailed")?;

        let tid = task.info.task_id.clone();
        let pid = child.id().unwrap();
        task.status.pid = Some(pid);
        info!("task `{tid}` start running, pid: {pid}");

        #[cfg(windows)]
        let mut utf8_bom_checked = false;
        let mut buffer = [0u8; BUF_SIZE];
        let stopper = Stopper::new();
        let mut terminator = stopper.get_receiver().await.unwrap();
        exc.running.lock().await.insert(tid.clone(), stopper);

        let report_notify = Notify::new();
        let mut report_deadline = Instant::now() + Duration::from_secs(REPORT_INTERVAL_SECS);
        let timeout = task.info.timeout;
        let task_deadline = Instant::now() + Duration::from_secs(timeout);

        loop {
            tokio::select! {
                biased; // report > cancel > timeout > output > finish

                _ = timeout_at(report_deadline, report_notify.notified()) => {
                    task.on_report::<T>();

                    // if the task output is dropped, it won't report until finished
                    let dropped = task.output.dropped() > 0;
                    let interval = dropped.then_some(timeout).unwrap_or(REPORT_INTERVAL_SECS);
                    report_deadline = Instant::now() + Duration::from_secs(interval);
                },
                _ = &mut terminator => {
                    task.on_cancel();
                    break;
                },
                _ = sleep_until(task_deadline) => {
                    task.on_timeout();
                    break;
                },
                len = reader.read(&mut buffer) => {
                    let buf = match len {
                        Err(e) => break error!("task `{tid}` read error: {e}, pid: {pid}"),
                        Ok(0) => break info!("task `{tid}` read finished normally, pid: {pid}"),
                        #[cfg(windows)]
                        Ok(len) if !utf8_bom_checked => {
                            utf8_bom_checked = true;
                            // win2008 check utf8 bom header, start with 0xEF, 0xBB, 0xBF
                            let contains = buffer.starts_with(&UTF8_BOM_HEADER);
                            let skip = contains.then_some(UTF8_BOM_HEADER.len()).unwrap_or_default();
                            &buffer[skip..len]
                        },
                        Ok(len) => &buffer[..len],
                    };
                    task.on_output(buf).await;

                    if task.output.buffer.len() >= MAX_SINGLE_REPORT_BYTES {
                        report_notify.notify_one();
                    }
                },
                _ = child.wait() => {
                    break;
                },
            }
        }

        let status = child.wait().await.expect("wait child error");
        task.on_report::<T>(); // report remaining output or dropped bytes
        task.on_finish::<T>(status).await;

        exc.running.lock().await.remove(&tid);
        Ok(())
    }

    async fn on_output(&mut self, buf: &[u8]) {
        let output = decode_output(buf);
        self.output.append_output(&output, &self.info.task_id);
        if let Some(conf) = self.upload_conf.as_mut() {
            conf.write_output_file(&output).await;
        }
    }

    fn on_report<T: Invoke>(&mut self) {
        let dropped = self.output.dropped();
        if self.output.buffer.len() == 0 && dropped == 0 {
            return;
        }

        for bytes in self.output.bytes_to_report() {
            let tid = self.info.task_id.clone();
            let idx = self.output.idx();
            tokio::spawn(async move {
                info!(
                    "=>on_report: task:`{tid}`, idx:{idx}, output:{}",
                    String::from_utf8_lossy(&bytes).escape_debug()
                );
                if let Err(e) = T::upload_task_log(&tid, idx, bytes, dropped).await {
                    error!("task `{tid}` upload_task_log {idx} failed: {e:#}");
                };
            });
        }
    }

    fn on_timeout(&mut self) {
        let tid = &self.info.task_id;
        let pid = self.status.pid.unwrap();
        info!("=>on_timeout: task:{tid}, pid:{pid}");

        unsafe { kill_process_group(pid) };
        self.status.set_result(TaskResult::Timeout);

        let timeout = &self.info.timeout;
        info!("task `{tid}` killed because of timeout, pid: {pid}, timeout: {timeout}");
    }

    fn on_cancel(&mut self) {
        let tid = &self.info.task_id;
        let pid = self.status.pid.unwrap();
        info!("=>on_cancel: task:{tid}, pid:{pid}");

        unsafe { kill_process_group(pid) };
        self.status.set_result(TaskResult::Terminate);
        info!("task `{tid}` killed because of cancel, pid: {pid}");
    }

    async fn on_finish<T: Invoke>(&mut self, status: ExitStatus) {
        let tid = &self.info.task_id;
        let pid = self.status.pid.unwrap();
        let idx = self.output.idx.unwrap_or_default();
        let drp = self.output.dropped();
        info!("=>on_finish: task:{tid}, pid:{pid}, idx:{idx}, dropped:{drp}");
        self.status.finish(status);

        let rst = self.status.result.as_ref().unwrap().to_string();
        let code = self.status.exit_code.unwrap();
        let time = get_now_secs();

        let (mut url, mut err) = Default::default();
        if let Some(ref mut conf) = self.upload_conf {
            match conf.upload_cos::<T>(&tid).await {
                Ok(output_url) => url = output_url,
                Err(output_err_info) => err = format!("{output_err_info:#}"),
            }
        }

        match T::report_task_finish(tid, &rst, "", code, idx, time, &url, &err, drp).await {
            Ok(_) => info!("task `{tid}` report_task_finish success"),
            Err(e) => error!("task `{tid}` report_task_finish error: {e:#}"),
        }
    }
}

pub struct TaskInfo {
    pub task_id: String,
    pub user: User,
    pub working_directory: String,
    pub command_type: String,
    timeout: u64,
}

impl TaskInfo {
    pub fn script_path(&self) -> Result<PathBuf> {
        let mut path = EXE_DIR.join("tmp").join(&self.task_id);
        path.set_extension(self.script_extension()?);
        Ok(path)
    }

    fn output_file_path(&self) -> Result<PathBuf> {
        let mut path = self.script_path()?;
        path.set_extension(EXTENSION_LOG);
        Ok(path)
    }

    async fn create_script(&self, content: &[u8]) -> Result<()> {
        let script = self.script_path()?;
        let parent = script.parent().unwrap();
        create_dir_all(parent).await?;

        let mut script = File::create(script).await?;
        script.write_all(content).await?;

        #[cfg(unix)]
        self.set_permissions_recursively().await?;

        Ok(())
    }

    async fn create_output_file(&self) -> Result<File> {
        let output_file = self.output_file_path()?;
        let parent = output_file.parent().unwrap();
        create_dir_all(parent).await?;

        let output_file = File::create(output_file).await?;
        Ok(output_file)
    }

    fn remove_task_file(&self) {
        // Use synchronous remove because it needs to be called in Drop trait
        use std::fs::remove_file;
        if cbs_exist() {
            return;
        }

        if let Ok(script) = self.script_path() {
            let _ = remove_file(script);
        }

        if let Ok(output_file) = self.output_file_path() {
            let _ = remove_file(output_file);
        }
    }
}

impl Drop for TaskInfo {
    fn drop(&mut self) {
        self.remove_task_file()
    }
}

#[derive(Default)]
pub struct TaskStatus {
    pid: Option<u32>,
    exit_code: Option<i32>,
    result: Option<TaskResult>,
}

impl TaskStatus {
    fn finish(&mut self, status: ExitStatus) {
        let code = status.code().unwrap_or(EXIT_CODE_ERROR);
        self.exit_code = Some(code);
        match self.result {
            Some(_) => (),
            None if code == 0 => self.set_result(TaskResult::Success),
            None => self.set_result(TaskResult::Failed),
        };
    }

    fn set_result(&mut self, result: TaskResult) {
        if self.result.is_none() {
            self.result = Some(result)
        }
    }
}

#[derive(Default)]
struct TaskOutput {
    buffer: Vec<u8>,
    total: u64,
    idx: Option<u32>,
}

impl TaskOutput {
    fn append_output(&mut self, data: &[u8], tid: &str) {
        let len = data.len() as u64;
        if self.dropped() > 0 {
            self.total += len;
            return;
        }
        let remain = MAX_REPORT_BYTES - self.total;
        if len > remain {
            info!("task `{tid}` exceeded the max report limit, will keep running without report");
        }
        self.buffer.extend(&data[..min(remain, len) as usize]);
        self.total += len;
    }

    fn bytes_to_report(&mut self) -> Vec<Vec<u8>> {
        let mut v = Vec::with_capacity(self.buffer.capacity());
        swap(&mut self.buffer, &mut v);
        if v.len() <= MAX_SINGLE_REPORT_BYTES {
            return vec![v];
        }
        // like chunks_exact(), but without clone
        let mut output = Vec::new();
        while v.len() >= MAX_SINGLE_REPORT_BYTES {
            let remain = v.split_off(MAX_SINGLE_REPORT_BYTES);
            output.push(take(&mut v));
            v = remain
        }
        self.buffer.append(&mut v);
        output
    }

    fn idx(&mut self) -> u32 {
        let i = self.idx.map(|i| i + 1).unwrap_or_default();
        self.idx = Some(i);
        i
    }

    fn dropped(&self) -> u64 {
        self.total.saturating_sub(MAX_REPORT_BYTES)
    }
}

struct TaskUploadConf {
    cos_bucket_url: String,
    cos_bucket_prefix: String,
    output_file: Option<File>,
}

impl TaskUploadConf {
    async fn upload_cos<T: Invoke>(&mut self, task_id: &str) -> Result<String> {
        let metadata_adapter = MetadataAdapter::build(&get_meta_url());
        let resp = match metadata_adapter.tmp_credential().await {
            Ok(resp) => Ok(resp),
            Err(_) => T::get_cos_credential(task_id).await,
        };
        let credential = resp.context("Get CAM role of instance failed")?;
        let cli = COSAdapter::new(
            &credential.secret_id,
            &credential.secret_key,
            &credential.token,
            &self.cos_bucket_url,
        );
        let instance_id = metadata_adapter.instance_id().await;
        let invocation_id = credential.invocation_id;
        let object_name = self.object_name(&invocation_id, task_id);
        let file = self.output_file.take().unwrap();
        if let Err(e) = cli.put_object_from_file(file, &object_name, None).await {
            error!("pub object to cos failed: {}", e);
            bail!("Upload output to cos failed, please check if {instance_id} has permission to put file to COS");
        }
        Ok(self.output_url(&invocation_id, task_id))
    }

    fn object_name(&self, invocation_id: &str, task_id: &str) -> String {
        IntoIterator::into_iter([
            &self.cos_bucket_prefix,
            invocation_id,
            &format!("{}.log", task_id),
        ])
        .filter(|s| !s.is_empty())
        .map(|s| format!("/{s}"))
        .collect()
    }

    fn output_url(&self, invocation_id: &str, task_id: &str) -> String {
        self.cos_bucket_url.clone() + &self.object_name(invocation_id, task_id)
    }

    async fn write_output_file(&mut self, output: &[u8]) {
        if let Err(e) = self.output_file.as_mut().unwrap().write(output).await {
            error!("write_output_file failed: {}", e)
        }
    }
}

pub enum TaskResult {
    Timeout,
    Terminate,
    Failed,
    Success,
}

impl Display for TaskResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let out = match self {
            TaskResult::Timeout => TASK_RESULT_TIMEOUT,
            TaskResult::Terminate => TASK_RESULT_TERMINATED,
            TaskResult::Failed => TASK_RESULT_FAILED,
            TaskResult::Success => TASK_RESULT_SUCCESS,
        };
        write!(f, "{out}")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{common::get_current_username, executor::init_command};
    use std::{env::set_current_dir, fs::exists};
    const FAKE_COS_URL: &str = "https://fake-cos-url.com";

    fn task_output_with_buffer(buffer: Vec<u8>) -> TaskOutput {
        TaskOutput {
            buffer,
            ..Default::default()
        }
    }

    fn task_upload_conf_with_prefix(prefix: &str) -> TaskUploadConf {
        TaskUploadConf {
            cos_bucket_url: FAKE_COS_URL.to_string(),
            cos_bucket_prefix: prefix.to_string(),
            output_file: None,
        }
    }

    #[tokio::test]
    async fn test_task_info() {
        set_current_dir(&*EXE_DIR).unwrap();
        #[cfg(unix)]
        let command_type = "SHELL";
        #[cfg(windows)]
        let command_type = "POWERSHELL";
        let info = TaskInfo {
            task_id: "invt-xxxx".to_string(),
            user: User::new(&get_current_username()).unwrap(),
            working_directory: EXE_DIR.to_str().unwrap().to_string(),
            command_type: command_type.to_string(),
            timeout: 60,
        };
        let script = format!("invt-xxxx.{}", info.script_extension().unwrap());
        let output_file = format!("invt-xxxx.{}", EXTENSION_LOG);
        info.create_script(b"pwd").await.unwrap();
        info.create_output_file().await.unwrap();
        #[cfg(unix)]
        {
            use crate::executor::unix::EXEC_MODE;
            let mtdt = tokio::fs::metadata("tmp").await.unwrap();
            let mode = std::os::unix::fs::PermissionsExt::mode(&mtdt.permissions());
            assert_eq!(mode & EXEC_MODE, EXEC_MODE);
        }
        set_current_dir("tmp").unwrap();
        assert!(exists(&script).unwrap());
        assert!(exists(&output_file).unwrap());
        #[cfg(unix)]
        {
            use crate::executor::unix::EXEC_MODE;
            let mtdt = tokio::fs::metadata(&script).await.unwrap();
            let mode = std::os::unix::fs::PermissionsExt::mode(&mtdt.permissions());
            assert_eq!(mode & EXEC_MODE, EXEC_MODE);
        }
        drop(info); // drop will remove all files
        assert!(!exists(script).unwrap());
        assert!(!exists(output_file).unwrap());
    }

    #[tokio::test]
    async fn test_finish() {
        let mut st = TaskStatus::default();
        let es = init_command("exit 0").await.spawn().unwrap().wait().await;
        st.finish(es.unwrap());
        assert_eq!(st.exit_code, Some(0));
        assert!(matches!(st.result, Some(TaskResult::Success)));

        let mut st = TaskStatus::default();
        let es = init_command("exit 1").await.spawn().unwrap().wait().await;
        st.finish(es.unwrap());
        assert_eq!(st.exit_code, Some(1));
        assert!(matches!(st.result, Some(TaskResult::Failed)));

        let mut st = TaskStatus::default();
        st.result = Some(TaskResult::Terminate);
        let es = init_command("exit 1").await.spawn().unwrap().wait().await;
        st.finish(es.unwrap());
        assert_eq!(st.exit_code, Some(1));
        assert!(matches!(st.result, Some(TaskResult::Terminate)));
    }

    #[test]
    fn test_set_result() {
        let mut st = TaskStatus::default();
        st.set_result(TaskResult::Success);
        assert!(matches!(st.result, Some(TaskResult::Success)));
        st.set_result(TaskResult::Failed);
        assert!(matches!(st.result, Some(TaskResult::Success)));
    }

    #[test]
    fn test_append_output() {
        let mut op = TaskOutput::default();
        op.append_output(&[0, 1, 2], "");
        assert_eq!(op.buffer, vec![0, 1, 2]);
        op.append_output(&[3, 4, 5], "");
        assert_eq!(op.buffer, vec![0, 1, 2, 3, 4, 5]);
        op.append_output(&[6, 7, 8], "");
        assert_eq!(op.buffer, vec![0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_bytes_to_report() {
        let mut op = task_output_with_buffer(vec![]);
        let btr = op.bytes_to_report();
        assert_eq!(btr, vec![Vec::<u8>::new()]);
        assert_eq!(op.buffer, Vec::<u8>::new());

        let mut op = task_output_with_buffer(vec![1, 2, 3]);
        let btr = op.bytes_to_report();
        assert_eq!(btr, vec![vec![1, 2, 3]]);
        assert_eq!(op.buffer, Vec::<u8>::new());

        let mut op = task_output_with_buffer(vec![0; MAX_SINGLE_REPORT_BYTES]);
        let btr = op.bytes_to_report();
        assert_eq!(btr, vec![vec![0; MAX_SINGLE_REPORT_BYTES]]);
        assert_eq!(op.buffer, Vec::<u8>::new());

        let mut op = task_output_with_buffer(vec![0; MAX_SINGLE_REPORT_BYTES + 1]);
        let btr = op.bytes_to_report();
        assert_eq!(btr, vec![vec![0; MAX_SINGLE_REPORT_BYTES]]);
        assert_eq!(op.buffer, vec![0]);

        let mut op = task_output_with_buffer(vec![0; MAX_SINGLE_REPORT_BYTES * 2]);
        let btr = op.bytes_to_report();
        assert_eq!(btr, vec![vec![0; MAX_SINGLE_REPORT_BYTES]; 2]);
        assert_eq!(op.buffer, Vec::<u8>::new());

        let mut op = task_output_with_buffer(vec![0; MAX_SINGLE_REPORT_BYTES * 2 + 1]);
        let btr = op.bytes_to_report();
        assert_eq!(btr, vec![vec![0; MAX_SINGLE_REPORT_BYTES]; 2]);
        assert_eq!(op.buffer, vec![0]);
    }

    #[test]
    fn test_idx() {
        let mut op = TaskOutput::default();
        assert_eq!(op.idx.unwrap_or_default(), 0); // set last index to 0 if no report
        assert_eq!(op.idx(), 0);
        assert_eq!(op.idx.unwrap_or_default(), 0);
        assert_eq!(op.idx(), 1);
        assert_eq!(op.idx.unwrap_or_default(), 1);
        assert_eq!(op.idx(), 2);
        assert_eq!(op.idx.unwrap_or_default(), 2);
    }

    #[test]
    fn test_dropped() {
        let mut op = TaskOutput::default();
        // 1/4
        op.append_output(&[0; MAX_REPORT_BYTES as usize / 4], "");
        assert_eq!(op.buffer, vec![0; MAX_REPORT_BYTES as usize / 4]);
        assert_eq!(op.dropped(), 0);
        // 1/4 + 1/2 = 3/4
        op.append_output(&[0; MAX_REPORT_BYTES as usize / 2], "");
        assert_eq!(op.buffer, vec![0; MAX_REPORT_BYTES as usize / 4 * 3]);
        assert_eq!(op.dropped(), 0);
        // 3/4 + 1/2 = 1 + 1/4
        op.append_output(&[0; MAX_REPORT_BYTES as usize / 2], "");
        assert_eq!(op.buffer, vec![0; MAX_REPORT_BYTES as usize]);
        assert_eq!(op.dropped(), MAX_REPORT_BYTES / 4);
    }

    #[test]
    fn test_object_name() {
        let uc = task_upload_conf_with_prefix("");
        let obj = uc.object_name("", "invt-xxx");
        assert_eq!(obj, format!("/invt-xxx.log"));

        let uc = task_upload_conf_with_prefix("");
        let obj = uc.object_name("ins-xxx", "invt-xxx");
        assert_eq!(obj, format!("/ins-xxx/invt-xxx.log"));

        let uc = task_upload_conf_with_prefix("aa/bb/cc");
        let obj = uc.object_name("ins-xxx", "invt-xxx");
        assert_eq!(obj, format!("/aa/bb/cc/ins-xxx/invt-xxx.log"));
    }

    #[test]
    fn test_output_url() {
        let uc = task_upload_conf_with_prefix("aa/bb/cc");
        let obj = uc.output_url("ins-xxx", "invt-xxx");
        assert_eq!(obj, format!("{FAKE_COS_URL}/aa/bb/cc/ins-xxx/invt-xxx.log"));
    }
}
