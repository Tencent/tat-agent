cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use crate::common::consts::CMD_TYPE_SHELL;
        use crate::executor::shell_command::ShellCommand;
    } else if #[cfg(windows)] {
        use crate::common::consts::CMD_TYPE_POWERSHELL;
        use crate::executor::powershell_command::PowerShellCommand;
    }
}
use crate::common::consts::{
    FINISH_RESULT_FAILED, FINISH_RESULT_START_FAILED, FINISH_RESULT_SUCCESS,
    FINISH_RESULT_TERMINATED, FINISH_RESULT_TIMEOUT, OUTPUT_BYTE_LIMIT_EACH_REPORT,
    TASK_STORE_PATH,
};
use crate::network::cos::ObjectAPI;
use crate::network::cos::COS;
use crate::network::urls::get_meta_url;
use crate::network::MetadataAPIAdapter;
use crate::ontime::timer::Timer;
use crate::start_failed_err_info;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::fmt;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::process::Child;

#[async_trait]
pub trait MyCommand {
    async fn run(&mut self) -> Result<(), String>;
    fn cancel(&self) -> Result<(), String> {
        self.get_base().cancel()
    }
    fn cur_output_len(&self) -> usize {
        self.get_base().cur_output_len()
    }

    fn next_output(&mut self) -> (Vec<u8>, u32, u64) {
        self.get_base().next_output()
    }

    fn is_finished(&self) -> bool {
        self.get_base().is_finished()
    }

    fn is_started(&self) -> bool {
        self.get_base().is_started()
    }

    fn exit_code(&self) -> i32 {
        self.get_base().exit_code()
    }

    fn pid(&self) -> u32 {
        self.get_base().pid()
    }

    fn is_timeout(&self) -> bool {
        self.get_base().is_timeout()
    }

    fn finish_result(&self) -> String {
        self.get_base().finish_result()
    }

    fn err_info(&self) -> String {
        self.get_base().err_info()
    }

    fn finish_time(&self) -> u64 {
        self.get_base().finish_time()
    }

    fn output_url(&self) -> String {
        self.get_base().output_url()
    }

    fn output_err_info(&self) -> String {
        self.get_base().output_err_info()
    }

    fn open_log_file(&self) -> Result<File, String> {
        self.get_base().open_log_file()
    }

    fn store_path_check(&self) -> Result<(), String> {
        self.get_base().store_path_check()
    }

    fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
    fn get_base(&self) -> Arc<BaseCommand>;
}

pub fn new(
    cmd_path: &str,
    username: &str,
    cmd_type: &str,
    work_dir: &str,
    timeout: u64,
    bytes_max_report: u64,
    log_file_path: &str,
    cos_bucket: &str,
    cos_prefix: &str,
    task_id: &str,
) -> Result<Box<dyn MyCommand + Send>, String> {
    match cmd_type {
        #[cfg(unix)]
        CMD_TYPE_SHELL => Ok(Box::new(ShellCommand::new(
            cmd_path,
            username,
            work_dir,
            timeout,
            bytes_max_report,
            log_file_path,
            cos_bucket,
            cos_prefix,
            task_id,
        ))),
        #[cfg(windows)]
        CMD_TYPE_POWERSHELL => Ok(Box::new(PowerShellCommand::new(
            cmd_path,
            username,
            work_dir,
            timeout,
            bytes_max_report,
            log_file_path,
            cos_bucket,
            cos_prefix,
            task_id,
        ))),
        _ => Err(format!("invalid cmd_type:{}", cmd_type)),
    }
}

impl std::fmt::Debug for std::boxed::Box<dyn MyCommand + Send> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug(f)
    }
}

pub struct BaseCommand {
    pub cmd_path: String,
    pub username: String,
    pub work_dir: String,
    // the whole process group will be killed after timeout
    pub timeout: u64,
    pub bytes_max_report: u64,

    pub bytes_reported: AtomicU64,
    pub bytes_dropped: AtomicU64,

    // it's true after finish
    pub finished: Arc<AtomicBool>,
    // Only read this value if self.finished==true
    pub exit_code: Arc<Mutex<Option<i32>>>,
    // current output which ready to report
    pub output: Arc<Mutex<Vec<u8>>>,
    // current output report index
    pub output_idx: AtomicU32,

    pub log_file_path: String,
    // bucket url where store the complete output.
    pub cos_bucket: String,
    pub cos_prefix: String,
    pub task_id: String,

    pub output_url: Mutex<String>,
    pub output_err_info: Mutex<String>,

    // it's None before start, will be Some after self.run()
    pub pid: Mutex<Option<u32>>,
    // if child has been killed by kill -9
    pub killed: Arc<AtomicBool>,
    // if child is timeout
    pub is_timeout: Arc<AtomicBool>,
    // the time command process finished
    pub finish_time: Arc<AtomicU64>,
    // err_info when command start fail
    pub err_info: Mutex<String>,
    //timer_key and timer_id
    pub timer_info: Mutex<(u128, u64)>,
}

impl BaseCommand {
    pub fn new(
        cmd_path: &str,
        username: &str,
        work_dir: &str,
        timeout: u64,
        bytes_max_report: u64,
        log_file_path: &str,
        cos_bucket: &str,
        cos_prefix: &str,
        task_id: &str,
    ) -> BaseCommand {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("sys time may before 1970")
            .as_secs();
        BaseCommand {
            cmd_path: cmd_path.to_string(),
            username: username.to_string(),
            work_dir: work_dir.to_string(),
            timeout,
            bytes_max_report,
            bytes_reported: AtomicU64::new(0),
            bytes_dropped: AtomicU64::new(0),
            finished: Arc::new(AtomicBool::new(false)),
            exit_code: Arc::new(Mutex::new(None)),
            output: Arc::new(Mutex::new(Default::default())),
            output_idx: AtomicU32::new(0),
            log_file_path: log_file_path.to_string(),
            cos_bucket: cos_bucket.to_string(),
            cos_prefix: cos_prefix.to_string(),
            task_id: task_id.to_string(),
            output_url: Mutex::new("".to_string()),
            output_err_info: Mutex::new("".to_string()),
            pid: Mutex::new(None),
            killed: Arc::new(AtomicBool::new(false)),
            is_timeout: Arc::new(AtomicBool::new(false)),
            finish_time: Arc::new(AtomicU64::new(timestamp)),
            err_info: Mutex::new("".to_string()),
            timer_info: Mutex::new((0, 0)),
        }
    }
    // length of bytes, not chars
    pub fn cur_output_len(&self) -> usize {
        let output = self.output.lock().expect("lock failed");
        output.len()
    }

    pub fn append_output(&self, data: &[u8]) {
        let mut output = self.output.lock().expect("lock failed");
        let len = data.len();

        if self.bytes_dropped.load(Ordering::SeqCst) > 0 {
            self.bytes_dropped.fetch_add(len as u64, Ordering::SeqCst);
        } else {
            let need_report_len = len;
            if self.bytes_reported.load(Ordering::SeqCst) + len as u64 > self.bytes_max_report {
                let need_report_len =
                    self.bytes_max_report - self.bytes_reported.load(Ordering::SeqCst);
                // set as the total dropped bytes
                self.bytes_dropped
                    .store(len as u64 - need_report_len, Ordering::SeqCst);
            }
            output.write(&data[..need_report_len]).unwrap();
            self.bytes_reported
                .fetch_add(need_report_len as u64, Ordering::SeqCst);
        }
    }

    pub fn next_output(&self) -> (Vec<u8>, u32, u64) {
        let mut output = self.output.lock().expect("lock failed");
        let len = output.len();

        let ret = if len == 0 {
            vec![]
        } else if len > 0 && len <= OUTPUT_BYTE_LIMIT_EACH_REPORT {
            let r = output.clone();
            output.clear();
            r
        } else {
            debug!("output origin:{:?}", output);
            // move [0..OUTPUT_BYTE_LIMIT_EACH_REPORT] out to ret
            output.rotate_left(OUTPUT_BYTE_LIMIT_EACH_REPORT);
            let r = output.split_off(len - OUTPUT_BYTE_LIMIT_EACH_REPORT);
            debug!("output to ret:{:?}", r);
            debug!("output left:{:?}", output);
            r
        };

        (
            ret,
            self.output_idx.fetch_add(1, Ordering::SeqCst),
            self.bytes_dropped.load(Ordering::SeqCst),
        )
    }

    pub fn is_started(&self) -> bool {
        return match *self.pid.lock().unwrap() {
            None => false,
            _ => true,
        };
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }

    pub fn exit_code(&self) -> i32 {
        let pid = *self.pid.lock().unwrap();
        if let None = pid {
            return 0;
        }
        let exit_code = self.exit_code.lock().expect("exit_code get lock fail");
        match *exit_code {
            Some(code) => code,
            None => -1,
        }
    }

    pub fn cmd_path(&self) -> &String {
        &self.cmd_path
    }

    pub fn pid(&self) -> u32 {
        let pid = *self.pid.lock().unwrap();
        match pid {
            Some(pid) => pid,
            None => 0,
        }
    }

    pub fn is_timeout(&self) -> bool {
        self.is_timeout.load(Ordering::SeqCst)
    }

    pub fn finish_result(&self) -> String {
        let pid = *self.pid.lock().unwrap();
        if let None = pid {
            return FINISH_RESULT_START_FAILED.to_string();
        }
        if self.is_timeout() {
            return FINISH_RESULT_TIMEOUT.to_string();
        }
        if self.killed.load(Ordering::SeqCst) {
            return FINISH_RESULT_TERMINATED.to_string();
        }
        if self.is_finished() {
            let code = self.exit_code();
            if 0 == code {
                return FINISH_RESULT_SUCCESS.to_string();
            }
        }
        FINISH_RESULT_FAILED.to_string()
    }

    pub fn err_info(&self) -> String {
        let err_info = self.err_info.lock().unwrap();
        return String::from(err_info.as_str());
    }

    pub fn finish_time(&self) -> u64 {
        self.finish_time.load(Ordering::SeqCst)
    }

    pub fn output_url(&self) -> String {
        let output_url = self.output_url.lock().unwrap();
        return String::from(output_url.as_str());
    }

    pub fn output_err_info(&self) -> String {
        let err_info = self.output_err_info.lock().unwrap();
        return String::from(err_info.as_str());
    }

    pub fn add_timeout_timer(&self) {
        let pid = self.pid.lock().unwrap().unwrap();
        let timeout = self.timeout;
        let killed = self.killed.clone();
        let is_timeout = self.is_timeout.clone();

        *self.timer_info.lock().unwrap() =
            Timer::get_instance()
                .lock()
                .unwrap()
                .add_task(timeout, move || {
                    info!("process {} timeout,timeout value is {}", pid, timeout);
                    let ret = killed.compare_exchange(false, true, SeqCst, SeqCst);
                    if ret.is_err() {
                        info!("pid:{} already killed, ignore this timer task", pid);
                    } else {
                        is_timeout.store(true, Ordering::SeqCst);
                        BaseCommand::kill_process_group(pid);
                        info!("pid:{} killed because of timeout", pid);
                    }
                });
    }

    pub fn del_timeout_timer(&self) {
        let timer_info = *self.timer_info.lock().unwrap();
        let deleted = Timer::get_instance()
            .lock()
            .unwrap()
            .del_task(timer_info.0, timer_info.1);
        if deleted {
            debug!(
                "timer task deleted, task_key:{}, task_id:{}",
                timer_info.0, timer_info.1
            );
        } else {
            debug!(
                "timer task NOT deleted, maybe task already scheduled, task_key:{}, task_id:{}",
                timer_info.0, timer_info.1
            );
        }
    }

    pub async fn process_finish(&self, child: &mut Child) {
        let pid = child.id();
        info!("=>process {} finish", pid);
        let status = child.await.expect("child process encountered an error");
        let mut exit_code = self.exit_code.lock().expect("exit_code get lock fail");
        match status.code() {
            Some(code) => {
                exit_code.replace(code);
            }
            None => {
                info!("Process terminated by signal: {}", pid);
                exit_code.replace(-1);
            }
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("sys time may before 1970")
            .as_secs();
        self.finished.store(true, Ordering::SeqCst);
        self.finish_time.store(now, Ordering::SeqCst);
    }

    pub fn cancel(&self) -> Result<(), String> {
        let pid = *self.pid.lock().unwrap();
        match pid {
            Some(pid) => {
                let ret =
                    self.killed
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
                if ret.is_err() {
                    info!("pid:{} already killed, ignore cancel request", pid);
                } else {
                    BaseCommand::kill_process_group(pid);
                    info!("pid:{} killed because of cancel", pid);
                }
                Ok(())
            }
            None => Err("Process not running, no pid to kill".to_string()),
        }
    }

    fn store_path_check(&self) -> Result<(), String> {
        if self.cmd_path.is_empty() {
            let ret = format!("start fail because script file store failed.");
            *self.err_info.lock().unwrap() =
                start_failed_err_info!(ERR_SCRIPT_FILE_STORE_FAILED, TASK_STORE_PATH);
            return Err(ret);
        }
        Ok(())
    }

    fn open_log_file(&self) -> Result<File, String> {
        let parent = Path::new(self.log_file_path.as_str()).parent();
        match parent {
            Some(parent) => {
                if let Err(e) = create_dir_all(parent) {
                    return Err(format!(
                        "fail to open task log file {}: create parent dir fail {}: {:?}",
                        self.log_file_path,
                        parent.display(),
                        e
                    ));
                }
            }
            None => {
                warn!(
                    "parent dir not found, skip: {}",
                    self.log_file_path.as_str()
                )
            }
        }

        let res = OpenOptions::new()
            .create(true)
            .write(true)
            .open(self.log_file_path.clone());
        match res {
            Ok(file) => Ok(file),
            Err(e) => Err(format!(
                "fail to open task log file {}: {:?}",
                self.log_file_path, e
            )),
        }
    }

    pub async fn upload_log_cos(&self) {
        let log_file_path = self.log_file_path.to_string();
        if !self.cos_bucket.is_empty() {
            let metadata = MetadataAPIAdapter::build(get_meta_url().as_str());
            let rsp = metadata.tmp_credential().await;
            match rsp {
                Ok(credential) => {
                    let cli = COS::new(
                        credential.secret_id,
                        credential.secret_key,
                        credential.token,
                        self.cos_bucket.to_string(),
                    );
                    let instance_id = metadata.instance_id().await;
                    let object_name =
                        self.object_name(&*self.cos_prefix, instance_id.as_str(), &*self.task_id);
                    if let Err(e) = cli
                        .put_object_from_file(log_file_path.clone(), object_name.clone(), None)
                        .await
                    {
                        error!("pub object to cos fail: {:?}", e);
                        *self.output_err_info.lock().unwrap() = format!("Upload output file to cos fail, please check if {} has permission to put file to COS:  output file: {}, bucket: {}, prefix: {}",
                                                                        instance_id.as_str(),
                                                                        self.log_file_path,
                                                                        self.cos_bucket,
                                                                        self.cos_prefix,
                        );
                    }

                    *self.output_url.lock().unwrap() = self.set_output_url(instance_id.as_str());
                }
                Err(e) => *self.output_err_info.lock().unwrap() = e.to_string(),
            }
        }

        // delete task output file.
        if let Err(e) = std::fs::remove_file(log_file_path.clone()) {
            error!("cleanup task output file fail: {}, {:?}", log_file_path, e)
        }
    }

    pub fn set_output_url(&self, instance_id: &str) -> String {
        let output_err_info = self.output_err_info.lock().expect("lock fail");
        if !output_err_info.is_empty() {
            return "".to_string();
        }

        if self.cos_bucket.is_empty() {
            return "".to_string();
        }

        let arr = vec![
            self.cos_bucket.to_string(),
            self.cos_prefix.to_string(),
            instance_id.to_string(),
            format!("{}.log", self.task_id.to_string()),
        ];
        let x: Vec<String> = arr.into_iter().filter(|x| !x.is_empty()).collect();
        x.join("/")
    }

    fn object_name(&self, cos_bucket_prefix: &str, instance_id: &str, task_id: &str) -> String {
        let mut object_name = format!("");
        if !cos_bucket_prefix.is_empty() {
            object_name.push_str(format!("/{}", cos_bucket_prefix).as_str())
        }
        if !instance_id.is_empty() {
            object_name.push_str(format!("/{}", instance_id).as_str())
        }
        object_name.push_str(format!("/{}.log", task_id).as_str());
        object_name
    }

    pub fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output_clone;
        {
            let output = self.output.lock().expect("lock failed");
            output_clone = output.clone();
        }
        let output_debug = String::from_utf8_lossy(output_clone.as_slice());
        let may_contain_binary = String::from_utf8(output_clone.clone()).is_err();

        f.debug_struct("CommandDebugInfo")
            .field("cmd_path", &self.cmd_path)
            .field("username", &self.username)
            .field("work_dir", &self.work_dir)
            .field("timeout", &self.timeout)
            .field("bytes_max_report", &self.bytes_max_report)
            .field("bytes_reported", &self.bytes_reported)
            .field("bytes_dropped", &self.bytes_dropped)
            .field("finished", &self.finished)
            .field("exit_code", &self.exit_code)
            .field("output", &self.output)
            .field("output_debug", &output_debug)
            .field("may_contain_binary", &may_contain_binary)
            .field("output_idx", &self.output_idx)
            .field("log_file_path", &self.log_file_path)
            .field("output_url", &self.output_url)
            .field("output_err_info", &self.output_err_info)
            .field("pid", &self.pid)
            .field("killed", &self.killed)
            .field("is_timeout", &self.is_timeout)
            .field("finish_time", &self.finish_time)
            .field("err_info", &self.err_info)
            .field("timer_info", &self.timer_info)
            .field("cos_bucket", &self.cos_bucket)
            .field("cos_prefix", &self.cos_prefix)
            .field("task_id", &self.task_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::time::{Duration, Instant, SystemTime};

    use log::info;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::common::consts::FINISH_RESULT_START_FAILED;
    use crate::common::utils::get_current_username;
    use crate::ontime::timer::Timer;

    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            use std::fs::read_dir;
            use std::process::Command;
        } else if #[cfg(windows)] {
            use crate::common::consts::CMD_TYPE_POWERSHELL;
        }
    }

    #[cfg(unix)]
    static CMD_TYPE: &str = CMD_TYPE_SHELL;
    #[cfg(windows)]
    static CMD_TYPE: &str = CMD_TYPE_POWERSHELL;

    #[cfg(unix)]
    static CMD_PATH: &str = "./a.sh";
    #[cfg(windows)]
    static CMD_PATH: &str = "./a.ps1";

    fn username() -> String {
        get_current_username()
    }

    #[test]
    fn test_valid_type_shell() {
        let ret = new(
            CMD_PATH,
            &username(),
            CMD_TYPE,
            "./",
            1024,
            1024,
            "",
            "",
            "",
            "",
        );
        assert!(ret.is_ok());
    }

    #[test]
    fn test_invalid_type() {
        init_log();
        let ret = new(
            CMD_PATH,
            &username(),
            "xxx",
            "./",
            1024,
            1024,
            "",
            "",
            "",
            "",
        );
        match ret {
            Ok(_) => panic!(),
            Err(e) => info!("OK, ret:{}", e),
        }
    }

    #[tokio::test]
    async fn test_run_then_sleep() {
        init_log();
        // it doesn't matter even if ./a.sh not exist
        let log_path = format!("./{}.log", gen_rand_str());
        let ret = new(
            CMD_PATH,
            &username(),
            CMD_TYPE,
            "./",
            1024,
            1024,
            log_path.as_str(),
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        assert!(ret.is_ok());
        info!("cmd running, pid:{}", cmd.pid());
        tokio::time::delay_for(Duration::from_secs(10)).await;
        // now it's NOT a defunct process, cmd will be auto-waited
        assert!(!is_process_exist(cmd.pid()).await);
        //thread::sleep(Duration::new(10, 0));
    }

    #[tokio::test]
    async fn test_run_start_fail_working_directory() {
        init_log();
        let ret = new(
            CMD_PATH,
            &username(),
            CMD_TYPE,
            "./dir_not_exist",
            1024,
            1024,
            "./fake_path",
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        info!("cmd run ret:[{}]", ret.unwrap_err());
        assert_eq!(cmd.pid(), 0);
        assert_eq!(cmd.finish_result(), FINISH_RESULT_START_FAILED);
        assert_eq!(cmd.exit_code(), 0);
        assert!(cmd.err_info().starts_with("DirectoryNotExists"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_start_fail_user_not_exists() {
        init_log();
        let ret = new(
            CMD_PATH,
            "hacker-neo",
            CMD_TYPE,
            "./",
            1024,
            1024,
            "./fake_path",
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        info!("cmd run ret:[{}]", ret.unwrap_err());
        assert_eq!(cmd.pid(), 0);
        assert_eq!(cmd.finish_result(), FINISH_RESULT_START_FAILED);
        assert_eq!(cmd.exit_code(), 0);
        assert!(cmd.err_info().starts_with("UserNotExists"));
    }

    fn gen_rand_str() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect()
    }

    #[cfg(unix)]
    fn run_shell(cmd: &str, args: &[&str]) {
        Command::new(cmd).args(args).status().unwrap();
    }

    fn create_file(content: &str, filename: &str) {
        let mut file = File::create(filename).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        #[cfg(unix)]
        run_shell("chmod", &["+x", filename]);
    }

    fn init_log() {
        use crate::common::logger;
        logger::init_test_log();
    }

    #[cfg(unix)]
    async fn is_process_exist(pid: u32) -> bool {
        // maybe need a time to clear the dir
        tokio::time::delay_for(Duration::from_millis(2000)).await;
        let path = format!("/proc/{}", pid);
        let ret = read_dir(path);
        let exist = ret.is_ok();
        info!("pid:{} is_exist:{}", pid, exist);
        exist
    }

    #[cfg(windows)]
    async fn is_process_exist(pid: u32) -> bool {
        let pid_str = format!("PID eq {}", pid);
        let output = std::process::Command::new("TASKLIST")
            .args(&["/FI", pid_str.as_str()])
            .output()
            .expect("failed find process");
        info!(
            "task find output for {} is {}",
            pid,
            String::from_utf8_lossy(&output.stdout)
        );
        String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_pid_exist() {
        let ret = is_process_exist(1).await;
        assert!(ret);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_pid_not_exist() {
        let ret = is_process_exist(0).await;
        assert!(!ret);
    }

    #[tokio::test]
    async fn test_cancel() {
        init_log();
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let filename = format!("./.{}.sh", gen_rand_str());
                create_file("sleep 15", filename.as_str());
            } else if #[cfg(windows)] {
                let filename = format!("./{}.ps1", gen_rand_str());
                create_file("Start-Sleep -s 1500", filename.as_str());
            }
        }
        let log_path = format!("./{}.log", gen_rand_str());
        let ret = new(
            filename.as_str(),
            &username(),
            CMD_TYPE,
            "./",
            1024,
            1024,
            log_path.as_str(),
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        assert!(ret.is_ok());
        info!("{} running, pid:{}", filename, cmd.pid());
        // now it's a still running
        tokio::time::delay_for(Duration::new(10, 0)).await;
        assert_eq!(cmd.is_started(), true);
        assert!(is_process_exist(cmd.pid()).await);

        let ret = cmd.cancel();
        assert!(ret.is_ok());
        tokio::time::delay_for(Duration::new(1, 0)).await;
        assert!(!is_process_exist(cmd.pid()).await);
        // cmd.cancel() called twice is OK and safe
        let ret = cmd.cancel();
        assert!(ret.is_ok());
        // Now it's killed & waited, check it's NOT a defunct.
        // Even after killed, call cmd.pid() is OK
        info!("{} killed, pid:{}", filename, cmd.pid());
        info!("cmd:{:?}", cmd);
        tokio::time::delay_for(Duration::new(5, 0)).await;
        fs::remove_file(filename.as_str()).unwrap();
    }

    #[tokio::test]
    async fn test_output() {
        init_log();
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let filename = format!("./.{}.sh", gen_rand_str());
                create_file("yes | head -10 && sleep 3 && yes | head -5", filename.as_str());
            } else if #[cfg(windows)] {
                let filename = format!("./{}.ps1", gen_rand_str());
                create_file(
                    "foreach ($i in 1..10) { Write-Host '00' -NoNewLine };\
                    Start-Sleep -s 3; \
                    foreach ($i in 1..5) { Write-Host '11' -NoNewLine };",
                    filename.as_str(),
                );
            }
        }
        let log_path = format!("./{}.log", gen_rand_str());
        let ret = new(
            filename.as_str(),
            &username(),
            CMD_TYPE,
            "./",
            1024,
            18,
            log_path.as_str(),
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        assert!(ret.is_ok());
        info!("{} running, pid:{}", filename, cmd.pid());
        let mut cur_dropped = 0 as u64;
        // usage of read output
        loop {
            tokio::time::delay_for(Duration::from_secs(1)).await;
            let len = cmd.cur_output_len();
            // is_finished() MUST be called after cur_output_len()
            let finished = cmd.is_finished();
            if 0 != len && 0 == cur_dropped {
                let (out, idx, dropped) = cmd.next_output();
                info!(
                    "ready to report output:{:?}, output_debug:{}, idx:{}, dropped:{}",
                    out,
                    String::from_utf8_lossy(&out[..]),
                    idx,
                    dropped
                );
                assert_eq!(idx, 0);
                assert_eq!(dropped, 2);

                // Do output report task here
                // do_report(out, idx, dropped);
                if dropped > 0 {
                    // max report exceeds, get dropped and idx during sleep
                    let (out, idx, dropped_new) = cmd.next_output();
                    info!("during sleep: idx: {}, drop {}, ", idx, dropped);
                    assert_eq!(idx, 1);
                    assert_eq!(dropped_new, dropped);
                    assert_eq!(0, out.len());
                    info!("dropped, not report output any more");

                    cur_dropped = dropped_new;
                }
            }

            if finished {
                let (out, idx, dropped) = cmd.next_output();
                info!("after sleep: idx: {}, drop {}", idx, dropped);
                assert_eq!(idx, 2);
                assert_eq!(dropped, 12);
                assert_eq!(0, out.len());
                // do_report(out, idx, dropped);
                info!("finished, report final dropped bytes of output.");
                break;
            }
        }
        // will see the output bytes in cmd.output
        info!("cmd:{:?}", cmd);
        tokio::time::delay_for(Duration::new(1, 0)).await;
        assert!(!is_process_exist(cmd.pid()).await);

        fs::remove_file(filename.as_str()).unwrap();
    }

    #[tokio::test]
    async fn test_long_output() {
        init_log();
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let filename = format!("./.{}.sh", gen_rand_str());
                create_file(format!("yes | head -c {}", OUTPUT_BYTE_LIMIT_EACH_REPORT + 1).as_str(), filename.as_str());
            } else if #[cfg(windows)] {
                let filename = format!("./{}.ps1", gen_rand_str());
                create_file(
                    format!("foreach ($i in 1..{}) {{ Write-Host 'y' -NoNewLine }};", OUTPUT_BYTE_LIMIT_EACH_REPORT + 1).as_str(),
                    filename.as_str(),
                );
            }
        }
        let log_path = format!("./{}.log", gen_rand_str());
        let ret = new(
            filename.as_str(),
            &username(),
            CMD_TYPE,
            "./",
            10,
            1024,
            log_path.as_str(),
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        assert!(ret.is_ok());

        while !cmd.is_finished() {
            tokio::time::delay_for(Duration::new(1, 0)).await;
        }

        let (_, idx, dropped) = cmd.next_output();
        assert_eq!(idx, 0);
        assert_eq!(dropped, (OUTPUT_BYTE_LIMIT_EACH_REPORT + 1 - 1024) as u64);
        fs::remove_file(filename.as_str()).unwrap();
    }

    #[tokio::test]
    async fn test_base64() {
        init_log();
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let filename = format!("./.{}.sh", gen_rand_str());
                create_file("echo -n 'hello world'", filename.as_str());
            } else if #[cfg(windows)] {
                let filename = format!("./{}.ps1", gen_rand_str());
                create_file(
                    "Write-Host 'hello world' -NoNewLine",
                    filename.as_str(),
                );
            }
        }
        let log_path = format!("./{}.log", gen_rand_str());
        let ret = new(
            filename.as_str(),
            &username(),
            CMD_TYPE,
            "./",
            10,
            1024,
            log_path.as_str(),
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        assert!(ret.is_ok());
        info!("{} running, pid:{}", filename, cmd.pid());

        while !cmd.is_finished() {
            tokio::time::delay_for(Duration::new(1, 0)).await;
        }

        let (out, idx, dropped) = cmd.next_output();
        let out = base64::encode(out);

        assert_eq!(dropped, 0);
        assert_eq!(0, idx);
        assert_eq!(out, "aGVsbG8gd29ybGQ=");
        info!("out:{}", out);
        info!("cmd:{:?}", cmd);
        tokio::time::delay_for(Duration::new(1, 0)).await;
        assert!(!is_process_exist(cmd.pid()).await);
        fs::remove_file(filename.as_str()).unwrap();
    }

    #[tokio::test]
    async fn test_shell_cmd_timeout() {
        init_log();
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let filename = format!("./.{}.sh", gen_rand_str());
                create_file("pwd && sleep 10240", filename.as_str());
            } else if #[cfg(windows)] {
                let filename = format!("./{}.ps1", gen_rand_str());
                create_file(
                    "Start-Sleep -s 10240",
                    filename.as_str(),
                );
            }
        }

        let start_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        info!("script {} start_time:{}", filename, start_time);
        let log_path = format!("./{}.log", gen_rand_str());
        let ret = new(
            filename.as_str(),
            &username(),
            CMD_TYPE,
            "./",
            2,
            1024,
            log_path.as_str(),
            "",
            "",
            "",
        );
        let mut cmd = ret.unwrap();
        let ret = cmd.run().await;
        assert!(ret.is_ok());
        let instant = Instant::now();
        info!("{} running, pid:{}", filename, cmd.pid());
        let mut cnt = 0;
        loop {
            {
                let timer = Timer::get_instance();
                let mut timer = timer.lock().unwrap();
                info!("timer:{:?}", timer);
                let tasks = timer.tasks_to_schedule();
                cnt += tasks.len();
                for task in tasks {
                    task.run_task();
                }
            }
            info!("total {} tasks run", cnt);
            tokio::time::delay_for(Duration::new(0, 500_000_000)).await;
            let finished = cmd.is_finished();
            if finished {
                break;
            }
        }
        info!("cmd:{:?}", cmd);
        info!("finish result:{}", cmd.finish_result());
        assert!(cmd.is_timeout());
        assert!(instant.elapsed() <= Duration::from_secs(5));
        assert!(0 < cmd.finish_time());
        assert!(cmd.finish_time() < start_time + 5);
        assert!(!is_process_exist(cmd.pid()).await);
        fs::remove_file(filename.as_str()).unwrap();
    }
}
