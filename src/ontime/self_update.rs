use crate::network::types::{AgentError, CheckUpdateResponse, HttpMethod};
use crate::network::{HttpRequester, InvokeAPIAdapter};
use std::fs::{create_dir_all, File};
use std::io::{self, Write};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use log::{debug, error, info, warn};
use tokio::runtime::{Builder, Runtime};
use unzip::{Unzipper, UnzipperStats};

const SELF_UPDATE_FILENAME: &str = "agent_update.zip";
const UPDATE_FILE_UNZIP_DIR: &str = "agent_update_unzip";
const AGENT_FILENAME: &str = "tat_agent";
const UPDATE_DOWNLOAD_TIMEOUT: u64 = 20 * 60;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use crate::executor::FILE_EXECUTE_PERMISSION_MODE;
        use std::os::unix::fs::PermissionsExt;
        use std::fs::{set_permissions, Permissions};
        const INSTALL_SCRIPT: &str = "install.sh";
        const SELF_UPDATE_PATH: &str = "/tmp/tat_agent/self_update/";
        const SELF_UPDATE_SCRIPT: &str = "self_update.sh";
    } else if #[cfg(windows)] {
        use crate::daemonizer::wow64_disable_exc;
        const SELF_UPDATE_PATH: &str = "C:\\Program Files\\qcloud\\tat_agent\\tmp\\self_update\\";
        const SELF_UPDATE_SCRIPT: &str = "self_update.bat";
    }
}

pub fn try_update(self_updating: Arc<AtomicBool>, need_restart: Arc<AtomicBool>) {
    let rt_res = Builder::new().basic_scheduler().enable_all().build();
    if let Err(e) = rt_res {
        warn!("runtime for try update build failed: {e:?}, will retry later");
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    let mut rt = rt_res.unwrap();

    let adapter = InvokeAPIAdapter::new();

    let check_update_rsp = check_update(&mut rt, &adapter);
    if let Err(e) = check_update_rsp {
        warn!("check update http request failed: {:?}", e);
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    let check_update_rsp = check_update_rsp.unwrap();

    if check_update_rsp.need_update() == false {
        info!("check update ret need_update:false, no newer version to update now");
        self_updating.store(false, Ordering::SeqCst);
        return;
    }

    if check_update_rsp.download_url().is_none() || check_update_rsp.md5().is_none() {
        warn!("check update rsp invalid no url or md5: {check_update_rsp:?}");
        self_updating.store(false, Ordering::SeqCst);
        return;
    }

    info!("new agent version found:{check_update_rsp:?}, going to download");
    let download_ret = download_file(
        &mut rt,
        check_update_rsp.download_url().clone().unwrap(),
        SELF_UPDATE_PATH.to_string(),
        SELF_UPDATE_FILENAME.to_string(),
    );
    if let Err(e) = download_ret {
        error!("download new agent failed: {}", e);
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    let download_content = download_ret.unwrap();

    let md5_check_pass = md5_check(&download_content, check_update_rsp.md5().clone().unwrap());
    if md5_check_pass {
        info!("download file md5 matched with remote");
    } else {
        warn!("download file md5 mismatch with remote, ignore this update");
        self_updating.store(false, Ordering::SeqCst);
        return;
    }

    let unzip_ret = unzip_file(
        SELF_UPDATE_PATH,
        SELF_UPDATE_FILENAME,
        UPDATE_FILE_UNZIP_DIR,
    );
    if let Err(e) = unzip_ret {
        warn!("self update file unzip failed: {}, ignore this update", e);
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    info!("self update file unzip success");

    let add_execute_ret = batch_set_execute_permission(
        SELF_UPDATE_PATH,
        UPDATE_FILE_UNZIP_DIR,
        SELF_UPDATE_SCRIPT,
        AGENT_FILENAME,
    );
    if let Err(e) = add_execute_ret {
        warn!("set execute permission for self update file failed: {e}, ignore this update");
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    info!("self update script set execute permission success");

    let try_run_ret = try_run_agent(SELF_UPDATE_PATH, UPDATE_FILE_UNZIP_DIR, AGENT_FILENAME);
    if let Err(e) = try_run_ret {
        warn!("try run agent failed: {}, ignore this update", e);
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    info!(
        "try run agent --version succ ret: '{}'",
        try_run_ret.unwrap()
    );

    let update_script_ret =
        run_self_update_script(SELF_UPDATE_PATH, UPDATE_FILE_UNZIP_DIR, SELF_UPDATE_SCRIPT);
    if let Err(e) = update_script_ret {
        warn!("run self update script failed: {}", e);
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    info!("agent self update script run success, will restart later gracefully");
    need_restart.store(true, Ordering::SeqCst);
}

fn check_update(
    rt: &mut Runtime,
    adapter: &InvokeAPIAdapter,
) -> Result<CheckUpdateResponse, AgentError<String>> {
    let req = adapter.check_update();
    let rsp = rt.block_on(req);
    rsp
}

fn download_file(
    rt: &mut Runtime,
    url: String,
    path: String,
    filename: String,
) -> Result<Bytes, String> {
    create_dir_all(path.clone())
        .map_err(|e| format!("path `{}` create failed because: {}", path, e))?;

    let filepath = format!("{}/{}", path, filename);
    let mut file =
        File::create(filepath).map_err(|e| format!("download file create failed: {}", e))?;

    let req = HttpRequester::new(&url);
    req.with_time_out(UPDATE_DOWNLOAD_TIMEOUT);

    let req = req.send_request::<String>(HttpMethod::GET, "", None, None);
    let rsp = rt
        .block_on(req)
        .map_err(|e| format!("self update download failed: {:?}", e))?;

    let bytes = rt
        .block_on(rsp.bytes())
        .map_err(|e| format!("self update download bytes return failed: {}", e))?;

    file.write_all(bytes.as_ref())
        .map_err(|e| format!("self update file write failed: {}", e))?;

    file.sync_all()
        .map_err(|e| format!("self update file sync disk failed: {}", e))?;

    info!("self update download success");
    Ok(bytes)
}

fn md5_check(download_content: &Bytes, md5: String) -> bool {
    let digest = md5::compute(download_content);
    let digest = format!("{:x}", digest);
    debug!("download file md5: {}, remote md5: {}", digest, md5);
    digest.eq_ignore_ascii_case(md5.as_str())
}

fn unzip_file(path: &str, zip_filename: &str, unzip_dir: &str) -> Result<UnzipperStats, io::Error> {
    let zip_file = format!("{}/{}", path, zip_filename);
    let file = File::open(zip_file)?;
    let abs_unzip_dir = format!("{}/{}", path, unzip_dir);
    let unzipper = Unzipper::new(file, abs_unzip_dir);
    unzipper.unzip()
}

#[cfg(unix)]
fn batch_set_execute_permission(
    path: &str,
    unzip_dir: &str,
    script_filename: &str,
    agent_filename: &str,
) -> io::Result<()> {
    let script = format!("{}/{}/{}", path, unzip_dir, script_filename);
    set_execute_permission(script)?;

    let agent = format!("{}/{}/{}", path, unzip_dir, agent_filename);
    set_execute_permission(agent)
}

#[cfg(windows)]
// set permission is no needed for windows.
fn batch_set_execute_permission(_: &str, _: &str, _: &str, _: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_execute_permission(abs_filename: String) -> io::Result<()> {
    set_permissions(
        abs_filename,
        Permissions::from_mode(FILE_EXECUTE_PERMISSION_MODE),
    )
}

fn try_run_agent(path: &str, unzip_dir: &str, agent_filename: &str) -> Result<String, String> {
    let agent = format!("{}{}/{}", path, unzip_dir, agent_filename);
    let out = Command::new(agent)
        .arg("--version")
        .output()
        .map_err(|e| format!("agent run ret: {:?}", e))?;

    let out = String::from_utf8(out.stdout)
        .map_err(|e| format!("version output contains non-utf8 char: {e:?}, invalid agent"))?;

    let out_v: Vec<&str> = out.split(' ').collect();
    if out_v.len() != 2 || out_v[0] != AGENT_FILENAME {
        return Err(format!("version output invalid: {}", out));
    }
    Ok(out)
}

fn run_self_update_script(
    path: &str,
    unzip_dir: &str,
    script_filename: &str,
) -> Result<(), String> {
    let script = format!("{}{}/{}", path, unzip_dir, script_filename);
    #[cfg(unix)]
    let cmd = Command::new("sh").arg("-c").arg(script).output();
    #[cfg(windows)]
    let cmd = wow64_disable_exc(move || Command::new(script.clone()).output());

    let out = cmd.map_err(|e| format!("self update run ret: {:?}", e))?;
    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    debug!("stdout of self update script:[{}]", stdout);
    debug!("stderr of self update script:[{}]", stderr);

    out.status
        .success()
        .then_some(())
        .ok_or(format!("ret code: {:?}", out.status.code()))
}

pub fn try_restart_agent() -> Result<(), String> {
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            let script = format!("{}{}/{}", SELF_UPDATE_PATH, UPDATE_FILE_UNZIP_DIR, INSTALL_SCRIPT);
            set_execute_permission(script.clone()).map_err(|e|format!("set execute permission failed: {:?}", e))?;
            let cmd = Command::new("sh")
            .args(&["-c", format!("{} restart", script).as_str()])
            .output();
        } else if #[cfg(windows)] {
           let cmd = wow64_disable_exc(move ||{
            Command::new("cmd.exe")
                .args(&["/C", "sc stop tatsvc & sc start tatsvc"])
                .output()});
        }
    }

    let out = cmd.map_err(|e| format!("run cmd failed: {:?}", e))?;
    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    debug!("stdout of try restart agent:[{}]", stdout);
    debug!("stderr of try restart agent:[{}]", stderr);

    out.status
        .success()
        .then_some(())
        .ok_or(format!("ret code: {:?}", out.status.code()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::logger::init_test_log;

    #[test]
    fn test_self_update() {
        init_test_log();
        let updating = Arc::new(AtomicBool::new(true));
        let need_restart = Arc::new(AtomicBool::new(false));
        try_update(updating.clone(), need_restart.clone());
        let updating = updating.load(Ordering::SeqCst);
        assert!(updating);
        let need_restart = need_restart.load(Ordering::SeqCst);
        assert!(need_restart);
    }
}
