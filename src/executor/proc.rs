cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use crate::common::consts::CMD_TYPE_SHELL;
        use crate::executor::shell_command::ShellCommand;
    } else if #[cfg(windows)] {
        use crate::common::consts::CMD_TYPE_POWERSHELL;
        use crate::executor::powershell_command::PowerShellCommand;
    }
}
use crate::common::asserts::GracefulUnwrap;
use crate::common::consts::{
    FINISH_RESULT_FAILED, FINISH_RESULT_START_FAILED, FINISH_RESULT_SUCCESS,
    FINISH_RESULT_TERMINATED, FINISH_RESULT_TIMEOUT, OUTPUT_BYTE_LIMIT_EACH_REPORT,
};
use crate::ontime::timer::Timer;
use async_trait::async_trait;
use log::{debug, info};
use std::fmt;
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
) -> Result<Box<dyn MyCommand + Send>, String> {
    match cmd_type {
        #[cfg(unix)]
        CMD_TYPE_SHELL => Ok(Box::new(ShellCommand::new(
            cmd_path,
            username,
            work_dir,
            timeout,
            bytes_max_report,
        ))),
        #[cfg(windows)]
        CMD_TYPE_POWERSHELL => Ok(Box::new(PowerShellCommand::new(
            cmd_path,
            username,
            work_dir,
            timeout,
            bytes_max_report,
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
    ) -> BaseCommand {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_exit("sys time may before 1970")
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
        let output = self.output.lock().unwrap_or_exit("lock failed");
        output.len()
    }

    pub fn append_output(&self, data: &mut Vec<u8>) {
        let mut output = self.output.lock().unwrap_or_exit("lock failed");
        output.append(data);
    }

    pub fn next_output(&self) -> (Vec<u8>, u32, u64) {
        let mut output = self.output.lock().unwrap_or_exit("lock failed");
        let len = output.len();
        // current output is empty, return.
        if len == 0 {
            return (
                vec![],
                self.output_idx.fetch_add(1, Ordering::SeqCst),
                self.bytes_dropped.load(Ordering::SeqCst),
            );
        }

        // already exceed max report, update dropped, index then return.
        let dropped_pre = self.bytes_dropped.load(Ordering::SeqCst);
        if dropped_pre > 0 {
            self.bytes_dropped.fetch_add(len as u64, Ordering::SeqCst);
            output.clear();
            return (
                vec![],
                self.output_idx.fetch_add(1, Ordering::SeqCst),
                dropped_pre + len as u64,
            );
        }

        // not exceed max report, continue report output.
        let mut ret;
        if len <= OUTPUT_BYTE_LIMIT_EACH_REPORT {
            // copy and move out
            ret = output.clone();
            output.clear();
        } else {
            debug!("output origin:{:?}", output);
            // move [0..OUTPUT_BYTE_LIMIT_EACH_REPORT] out to ret
            output.rotate_left(OUTPUT_BYTE_LIMIT_EACH_REPORT);
            ret = output.split_off(len - OUTPUT_BYTE_LIMIT_EACH_REPORT);
            debug!("output to ret:{:?}", ret);
            debug!("output left:{:?}", output);
        }

        let ret_len = ret.len() as u64;
        let bytes_pre = self.bytes_reported.fetch_add(ret_len, Ordering::SeqCst);
        // current output exceeds max report, init bytes_dropped and clear output.
        if ret_len + bytes_pre >= self.bytes_max_report {
            let need_report_len = self.bytes_max_report - bytes_pre;
            ret.truncate(need_report_len as usize);
            self.bytes_dropped
                .store(ret_len - need_report_len, Ordering::SeqCst);
            output.clear();
        }

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
        let exit_code = self
            .exit_code
            .lock()
            .unwrap_or_exit("exit_code get lock fail");
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
        let mut exit_code = self
            .exit_code
            .lock()
            .unwrap_or_exit("exit_code get lock fail");
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
            .unwrap_or_exit("sys time may before 1970")
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

    pub fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output_clone;
        {
            let output = self.output.lock().unwrap_or_exit("lock failed");
            output_clone = output.clone();
        }
        let output_debug = String::from_utf8_lossy(output_clone.as_slice());
        let may_contain_binary = String::from_utf8(output_clone.clone()).is_err();

        f.debug_struct("ShellCommand")
            .field("cmd_path", &self.cmd_path)
            .field("work_dir", &self.work_dir)
            .field("timeout", &self.timeout)
            .field("bytes_max_report", &self.bytes_max_report)
            .field("bytes_reported", &self.bytes_reported)
            .field("finished", &self.finished)
            .field("exit_code", &self.exit_code)
            .field("output", &self.output)
            .field("output_debug", &output_debug)
            .field("may_contain_binary", &may_contain_binary)
            .field("output_idx", &self.output_idx)
            .field("pid", &self.pid)
            .field("killed", &self.killed)
            .field("is_timeout", &self.is_timeout)
            .field("finish_time", &self.finish_time)
            .finish()
    }
}
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::time::{Duration, Instant, SystemTime};
    use std::{fs, thread};

    use log::info;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::common::asserts::GracefulUnwrap;
    use crate::common::consts::FINISH_RESULT_START_FAILED;
    use crate::ontime::timer::Timer;

    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            use std::fs::read_dir;
            use std::process::Command;
            use users::get_current_username;
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

    #[cfg(unix)]
    fn username() -> String {
        String::from(get_current_username().unwrap().to_str().unwrap())
    }

    #[cfg(windows)]
    fn username() -> String {
        String::from("System")
    }

    #[test]
    fn test_valid_type_shell() {
        let ret = new(CMD_PATH, &username(), CMD_TYPE, "./", 1024, 1024);
        assert!(ret.is_ok());
    }

    #[test]
    fn test_invalid_type() {
        init_log();
        let ret = new(CMD_PATH, &username(), "xxx", "./", 1024, 1024);
        match ret {
            Ok(_) => panic!(),
            Err(e) => info!("OK, ret:{}", e),
        }
    }

    #[test]
    fn test_run_then_sleep() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            init_log();
            // it doesn't matter even if ./a.sh not exist
            let ret = new(CMD_PATH, &username(), CMD_TYPE, "./", 1024, 1024);
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            assert!(ret.is_ok());
            info!("cmd running, pid:{}", cmd.pid());
            tokio::time::delay_for(Duration::from_secs(4)).await;
            // now it's NOT a defunct process, cmd will be auto-waited
            assert!(!is_process_exist(cmd.pid()));
            //thread::sleep(Duration::new(10, 0));
        });
    }

    #[test]
    fn test_run_start_fail_working_directory() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            init_log();
            let ret = new(
                CMD_PATH,
                &username(),
                CMD_TYPE,
                "./dir_not_exist",
                1024,
                1024,
            );
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            info!("cmd run ret:[{}]", ret.unwrap_err());
            assert_eq!(cmd.pid(), 0);
            assert_eq!(cmd.finish_result(), FINISH_RESULT_START_FAILED);
            assert_eq!(cmd.exit_code(), 0);
            assert!(cmd.err_info().starts_with("DirectoryNotExists"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn test_run_start_fail_user_not_exists() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            init_log();

            let ret = new(CMD_PATH, "hacker-neo", CMD_TYPE, "./", 1024, 1024);
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            info!("cmd run ret:[{}]", ret.unwrap_err());
            assert_eq!(cmd.pid(), 0);
            assert_eq!(cmd.finish_result(), FINISH_RESULT_START_FAILED);
            assert_eq!(cmd.exit_code(), 0);
            assert!(cmd.err_info().starts_with("UserNotExists"));
        });
    }

    fn gen_rand_str() -> String {
        thread_rng().sample_iter(&Alphanumeric).take(10).collect()
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
    fn is_process_exist(pid: u32) -> bool {
        // maybe need a time to clear the dir
        thread::sleep(Duration::from_millis(2000));
        let path = format!("/proc/{}", pid);
        let ret = read_dir(path);
        let exist = ret.is_ok();
        info!("pid:{} is_exist:{}", pid, exist);
        exist
    }

    #[cfg(windows)]
    fn is_process_exist(pid: u32) -> bool {
        let pid_str = format!("PID eq {}", pid);
        let output = std::process::Command::new("TASKLIST")
            .args(&["/FI", pid_str.as_str()])
            .output()
            .expect("failed find process");
        String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
    }

    #[cfg(unix)]
    #[test]
    fn test_pid_exist() {
        let ret = is_process_exist(1);
        assert!(ret);
    }

    #[cfg(unix)]
    #[test]
    fn test_pid_not_exist() {
        let ret = is_process_exist(0);
        assert!(!ret);
    }

    #[test]
    fn test_cancel() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
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

            let ret = new(filename.as_str(), &username(), CMD_TYPE, "./", 1024, 1024);
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            assert!(ret.is_ok());
            info!("{} running, pid:{}", filename, cmd.pid());
            // now it's a still running
            thread::sleep(Duration::new(10, 0));
            assert_eq!(cmd.is_started(), true);
            assert!(is_process_exist(cmd.pid()));

            let ret = cmd.cancel();
            assert!(ret.is_ok());
            thread::sleep(Duration::new(1, 0));
            assert!(!is_process_exist(cmd.pid()));
            // cmd.cancel() called twice is OK and safe
            let ret = cmd.cancel();
            assert!(ret.is_ok());
            // Now it's killed & waited, check it's NOT a defunct.
            // Even after killed, call cmd.pid() is OK
            info!("{} killed, pid:{}", filename, cmd.pid());
            info!("cmd:{:?}", cmd);
            thread::sleep(Duration::new(5, 0));

            fs::remove_file(filename.as_str()).unwrap();
        });
    }

    #[test]
    fn test_output() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
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

            let ret = new(filename.as_str(), &username(), CMD_TYPE, "./", 1024, 18);
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
            thread::sleep(Duration::new(1, 0));
            assert!(!is_process_exist(cmd.pid()));

            fs::remove_file(filename.as_str()).unwrap();
        });
    }

    #[test]
    fn test_base64() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
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
            let ret = new(filename.as_str(), &username(), CMD_TYPE, "./", 10, 1024);
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            assert!(ret.is_ok());
            info!("{} running, pid:{}", filename, cmd.pid());

            while !cmd.is_finished() {
                thread::sleep(Duration::new(1, 0));
            }

            let (out, idx, dropped) = cmd.next_output();
            let out = base64::encode(out);

            assert_eq!(dropped, 0);
            assert_eq!(0, idx);
            assert_eq!(out, "aGVsbG8gd29ybGQ=");
            info!("out:{}", out);
            info!("cmd:{:?}", cmd);
            thread::sleep(Duration::new(1, 0));
            assert!(!is_process_exist(cmd.pid()));

            fs::remove_file(filename.as_str()).unwrap();
        });
    }

    #[test]
    // NOTICE: This testcase has use singleton of timer,
    // All testcase share the same one timer, so:
    // This testcase can NOT run together with test_timer_in_one_case
    fn test_shell_cmd_timeout() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            init_log();

            cfg_if::cfg_if! {
                if #[cfg(unix)] {
                    let filename = format!("./.{}.sh", gen_rand_str());
                    create_file("sleep 10240", filename.as_str());
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
            info!("start_time:{}", start_time);

            let ret = new(filename.as_str(), &username(), CMD_TYPE, "./", 2, 1024);
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            assert!(ret.is_ok());
            assert!(is_process_exist(cmd.pid()));
            let instant = Instant::now();
            info!("{} running, pid:{}", filename, cmd.pid());
            thread::sleep(Duration::new(1, 0));

            let mut cnt = 0;
            loop {
                {
                    let timer = Timer::get_instance();
                    let mut timer = timer.lock().unwrap_or_exit("");
                    info!("timer:{:?}", timer);
                    let tasks = timer.tasks_to_schedule();
                    cnt += tasks.len();
                    for task in tasks {
                        task.run_task();
                    }
                }
                info!("total {} tasks run", cnt);
                thread::sleep(Duration::new(0, 500_000_000));
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
            assert!(!is_process_exist(cmd.pid()));
            fs::remove_file(filename.as_str()).unwrap();
        });
    }

    #[test]
    #[cfg(unix)]
    fn test_daemon() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            init_log();
            let filename = format!("./.{}.sh", gen_rand_str());
            create_file("echo 'hello world'\nsleep 10 &\ndate", filename.as_str());

            let ret = new(filename.as_str(), &username(), CMD_TYPE, "./", 6, 1024);
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            assert!(ret.is_ok());

            loop {
                {
                    let timer = Timer::get_instance();
                    let mut timer = timer.lock().unwrap_or_exit("");
                    info!("timer:{:?}", timer);
                    let tasks = timer.tasks_to_schedule();
                    for task in tasks {
                        task.run_task();
                    }
                }
                thread::sleep(Duration::from_secs(1));
                let finished = cmd.is_finished();
                if finished {
                    break;
                }
            }
            assert_eq!(cmd.is_timeout(), false);
            fs::remove_file(filename.as_str()).unwrap();
        });
    }

    #[test]
    #[cfg(unix)]
    fn test_daemon_output() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            init_log();
            let filename = format!("./.{}.sh", gen_rand_str());
            create_file(
                "yes | head -1024 \nsleep 1200 &\n yes | head -1025",
                filename.as_str(),
            );

            let ret = new(filename.as_str(), &username(), CMD_TYPE, "./", 1200, 10240);
            let mut cmd = ret.unwrap();
            let ret = cmd.run().await;
            assert!(ret.is_ok());

            loop {
                {
                    let timer = Timer::get_instance();
                    let mut timer = timer.lock().unwrap_or_exit("");
                    //info!("timer:{:?}", timer);
                    let tasks = timer.tasks_to_schedule();
                    for task in tasks {
                        task.run_task();
                    }
                }
                thread::sleep(Duration::from_secs(1));
                let finished = cmd.is_finished();
                if finished {
                    break;
                }
            }
            assert_eq!(cmd.is_timeout(), false);
            fs::remove_file(filename.as_str()).unwrap();
        });
    }
}
