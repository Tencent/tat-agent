use std::fs::{create_dir_all, File};
use std::io;
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use log::{debug, error, info, warn};
use tokio::runtime::{Builder, Runtime};
use unzip::{Unzipper, UnzipperStats};

use crate::common::consts::{
    AGENT_FILENAME, INVOKE_API, SELF_UPDATE_FILENAME, SELF_UPDATE_PATH, SELF_UPDATE_SCRIPT,
    UPDATE_DOWNLOAD_TIMEOUT, UPDATE_FILE_UNZIP_DIR,
};
use crate::http::{HttpRequester, InvokeAPIAdapter, Requester};
use crate::types::{AgentError, CheckUpdateResponse, HttpMethod};

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        use std::fs::{set_permissions,Permissions};

        use crate::common::consts::{INSTALL_SCRIPT, FILE_EXECUTE_PERMISSION_MODE};
    } else if #[cfg(windows)] {
        use crate::daemonizer::wow64_disable_exc;
    }
}

pub fn try_update(self_updating: Arc<AtomicBool>, need_restart: Arc<AtomicBool>) {
    let rt_res = Builder::new().basic_scheduler().enable_all().build();
    if let Err(e) = rt_res {
        warn!(
            "runtime for try update build fail:{:?}, will retry later",
            e
        );
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    let mut rt = rt_res.unwrap();

    let adapter = InvokeAPIAdapter::build(INVOKE_API);

    let check_update_rsp = check_update(&mut rt, &adapter);
    if let Err(e) = check_update_rsp {
        warn!("check update http request fail:{:?}", e);
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
        warn!(
            "check update rsp invalid no url or md5:{:?}",
            check_update_rsp
        );
        self_updating.store(false, Ordering::SeqCst);
        return;
    }

    info!(
        "new agent version found:{:?}, going to download",
        check_update_rsp
    );

    let download_ret = download_file(
        &mut rt,
        check_update_rsp.download_url().clone().unwrap(),
        SELF_UPDATE_PATH.to_string(),
        SELF_UPDATE_FILENAME.to_string(),
    );
    if let Err(e) = download_ret {
        error!("download new agent fail:{}", e);
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
        SELF_UPDATE_PATH.to_string(),
        SELF_UPDATE_FILENAME.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
    );
    if let Err(e) = unzip_ret {
        warn!("self update file unzip fail:{}, ignore this update", e);
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    info!("self update file unzip success");

    let add_execute_ret = batch_set_execute_permission(
        SELF_UPDATE_PATH.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
        SELF_UPDATE_SCRIPT.to_string(),
        AGENT_FILENAME.to_string(),
    );
    if let Err(e) = add_execute_ret {
        warn!(
            "set execute permission for self update file fail:{}, ignore this update",
            e
        );
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    info!("self update script set execute permission success");

    let try_run_ret = try_run_agent(
        SELF_UPDATE_PATH.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
        AGENT_FILENAME.to_string(),
    );
    if let Err(e) = try_run_ret {
        warn!("try run agent fail:{}, ignore this update", e);
        self_updating.store(false, Ordering::SeqCst);
        return;
    }
    info!(
        "try run agent --version succ ret:'{}'",
        try_run_ret.unwrap()
    );

    let update_script_ret = run_self_update_script(
        SELF_UPDATE_PATH.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
        SELF_UPDATE_SCRIPT.to_string(),
    );
    if let Err(e) = update_script_ret {
        warn!("run self update script fail:{}", e);
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
    if let Err(e) = create_dir_all(path.clone()) {
        let s = format!("path:{} create fail because:{}", path, e);
        return Err(s);
    }
    let filepath = format!("{}/{}", path, filename);
    let file = File::create(filepath);
    if let Err(e) = file {
        let s = format!("download file create fail:{}", e);
        return Err(s);
    }
    let mut file = file.unwrap();

    let mut req = HttpRequester::new();
    req.with_time_out(UPDATE_DOWNLOAD_TIMEOUT);
    let init_ret = req.initialize(url.as_str());
    if let None = init_ret {
        let s = "http init fail, maybe url invalid".to_string();
        return Err(s);
    }

    let req = req.send_request::<String>(HttpMethod::GET, "", None);
    let rsp = rt.block_on(req);
    if let Err(e) = rsp {
        let s = format!("self update download fail:{:?}", e);
        return Err(s);
    }
    let rsp = rsp.unwrap();

    let bytes = rt.block_on(rsp.bytes());
    if let Err(e) = bytes {
        let s = format!("self update download bytes ret fail:{}", e);
        return Err(s);
    }
    let bytes = bytes.unwrap();

    let write_ret = file.write_all(bytes.as_ref());
    if let Err(e) = write_ret {
        let s = format!("self update file write fail:{}", e);
        return Err(s);
    }

    let sync_ret = file.sync_all();
    if let Err(e) = sync_ret {
        let s = format!("self update file sync disk fail:{}", e);
        return Err(s);
    }

    info!("self update download success");
    Ok(bytes)
}

fn md5_check(download_content: &Bytes, md5: String) -> bool {
    let digest = md5::compute(download_content);
    let digest = format!("{:x}", digest);
    debug!("download file md5:{}, remote md5:{}", digest, md5);
    digest.eq_ignore_ascii_case(md5.as_str())
}

fn unzip_file(
    path: String,
    zip_filename: String,
    unzip_dir: String,
) -> Result<UnzipperStats, io::Error> {
    let zip_file = format!("{}/{}", path, zip_filename);
    let file = File::open(zip_file)?;
    let abs_unzip_dir = format!("{}/{}", path, unzip_dir);
    let unzipper = Unzipper::new(file, abs_unzip_dir);
    unzipper.unzip()
}

#[cfg(unix)]
fn batch_set_execute_permission(
    path: String,
    unzip_dir: String,
    script_filename: String,
    agent_filename: String,
) -> io::Result<()> {
    let script = format!("{}/{}/{}", path, unzip_dir, script_filename);
    set_execute_permission(script)?;

    let agent = format!("{}/{}/{}", path, unzip_dir, agent_filename);
    set_execute_permission(agent)
}

#[cfg(windows)]
// set permission is no needed for windows.
fn batch_set_execute_permission(
    _path: String,
    _unzip_dir: String,
    _script_filename: String,
    _agent_filename: String,
) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_execute_permission(abs_filename: String) -> io::Result<()> {
    set_permissions(
        abs_filename,
        Permissions::from_mode(FILE_EXECUTE_PERMISSION_MODE),
    )
}

fn try_run_agent(
    path: String,
    unzip_dir: String,
    agent_filename: String,
) -> Result<String, String> {
    let agent = format!("{}{}/{}", path, unzip_dir, agent_filename);
    let cmd = Command::new(agent).arg("--version").output();
    if let Err(e) = cmd {
        return Err(format!("agent run ret: {:?}", e));
    }
    let out = cmd.unwrap();

    let out = String::from_utf8(out.stdout);

    if let Err(e) = out {
        return Err(format!(
            "version output contains non-utf8 char:{:?}, invalid agent",
            e
        ));
    }
    let out = out.unwrap();

    let out_v: Vec<&str> = out.split(' ').collect();
    if out_v.len() != 2 || out_v[0] != AGENT_FILENAME {
        return Err(format!("version output invalid:{}", out));
    }
    Ok(out)
}

fn run_self_update_script(
    path: String,
    unzip_dir: String,
    script_filename: String,
) -> Result<(), String> {
    let script = format!("{}{}/{}", path, unzip_dir, script_filename);
    #[cfg(unix)]
    let cmd = Command::new("sh").arg("-c").arg(script).output();
    #[cfg(windows)]
    let cmd = wow64_disable_exc(move || Command::new(script.clone()).output());

    if let Err(e) = cmd {
        return Err(format!("self update run ret: {:?}", e));
    }
    let out = cmd.unwrap();
    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    debug!("stdout of self update script:[{}]", stdout);
    debug!("stderr of self update script:[{}]", stderr);

    if out.status.success() {
        Ok(())
    } else {
        Err(format!("ret code:{:?}", out.status.code()))
    }
}

pub fn try_restart_agent() -> Result<(), String> {
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            let script = format!("{}{}/{}",
                             SELF_UPDATE_PATH.to_string(),
                             UPDATE_FILE_UNZIP_DIR.to_string(),
                             INSTALL_SCRIPT.to_string(),
            );
            if let Err(e) = set_execute_permission(script.clone()) {
                return Err(format!("set execute permission fail: {:?}", e))
            }
            let cmd = Command::new("sh")
            .args(&[
                "-c",
                &script,
                "restart"
            ])
            .output();
        } else if #[cfg(windows)] {
           let cmd = wow64_disable_exc(move ||{
            Command::new("cmd.exe")
                .args(&["/C","sc stop tatsvc & sc start tatsvc"])
                .output()});
        }
    }

    if let Err(e) = cmd {
        return Err(format!("run cmd fail: {:?}", e));
    }
    let out = cmd.unwrap();
    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    debug!("stdout of try restart agent:[{}]", stdout);
    debug!("stderr of try restart agent:[{}]", stderr);

    if out.status.success() {
        Ok(())
    } else {
        Err(format!("ret code:{:?}", out.status.code()))
    }
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
