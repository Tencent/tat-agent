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
    AGENT_FILENAME, SELF_UPDATE_FILENAME, SELF_UPDATE_PATH, SELF_UPDATE_SCRIPT,
    UPDATE_DOWNLOAD_TIMEOUT, UPDATE_FILE_UNZIP_DIR,
};
use crate::common::envs;
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
    let mut rt = match Builder::new().basic_scheduler().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            warn!(
                "runtime for try update build fail:{:?}, will retry later",
                e
            );
            self_updating.store(false, Ordering::SeqCst);
            return;
        }
    };

    let adapter = InvokeAPIAdapter::build(envs::get_invoke_url().as_str());

    let check_update_rsp = match check_update(&mut rt, &adapter) {
        Ok(rsp) => rsp,
        Err(e) => {
            warn!("check update http request fail:{:?}", e);
            self_updating.store(false, Ordering::SeqCst);
            return;
        }
    };

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

    let download_content = match download_file(
        &mut rt,
        check_update_rsp.download_url().clone().unwrap(),
        SELF_UPDATE_PATH.to_string(),
        SELF_UPDATE_FILENAME.to_string(),
    ) {
        Ok(dc) => dc,
        Err(e) => {
            error!("download new agent fail:{}", e);
            self_updating.store(false, Ordering::SeqCst);
            return;
        }
    };

    let md5_check_pass = md5_check(&download_content, check_update_rsp.md5().clone().unwrap());
    if md5_check_pass {
        info!("download file md5 matched with remote");
    } else {
        warn!("download file md5 mismatch with remote, ignore this update");
        self_updating.store(false, Ordering::SeqCst);
        return;
    }

    match unzip_file(
        SELF_UPDATE_PATH.to_string(),
        SELF_UPDATE_FILENAME.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
    ) {
        Ok(_) => info!("self update file unzip success"),
        Err(e) => {
            warn!("self update file unzip fail:{}, ignore this update", e);
            self_updating.store(false, Ordering::SeqCst);
            return;
        }
    };

    match batch_set_execute_permission(
        SELF_UPDATE_PATH.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
        SELF_UPDATE_SCRIPT.to_string(),
        AGENT_FILENAME.to_string(),
    ) {
        Ok(_) => info!("self update script set execute permission success"),
        Err(e) => {
            warn!(
                "set execute permission for self update file fail:{}, ignore this update",
                e
            );
            self_updating.store(false, Ordering::SeqCst);
            return;
        }
    };

    match try_run_agent(
        SELF_UPDATE_PATH.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
        AGENT_FILENAME.to_string(),
    ) {
        Ok(s) => info!("try run agent --version succ ret:'{}'", s),
        Err(e) => {
            warn!("try run agent fail:{}, ignore this update", e);
            self_updating.store(false, Ordering::SeqCst);
            return;
        }
    };

    match run_self_update_script(
        SELF_UPDATE_PATH.to_string(),
        UPDATE_FILE_UNZIP_DIR.to_string(),
        SELF_UPDATE_SCRIPT.to_string(),
    ) {
        Ok(_) => {
            info!("agent self update script run success, will restart later gracefully");
            need_restart.store(true, Ordering::SeqCst);
        }
        Err(e) => {
            warn!("run self update script fail:{}", e);
            self_updating.store(false, Ordering::SeqCst);
            return;
        }
    };
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
    create_dir_all(path.clone()).map_err(|e| format!("path:{} create fail because:{}", path, e))?;
    let filepath = format!("{}/{}", path, filename);
    let mut file =
        File::create(filepath).map_err(|e| format!("download file create fail:{}", e))?;

    let mut req = HttpRequester::new();
    req.with_time_out(UPDATE_DOWNLOAD_TIMEOUT);
    req.initialize(url.as_str())
        .ok_or("http init fail, maybe url invalid".to_string())?;

    let req = req.send_request::<String>(HttpMethod::GET, "", None);

    let rsp = rt
        .block_on(req)
        .map_err(|e| format!("self update download fail:{:?}", e))?;

    let bytes = rt
        .block_on(rsp.bytes())
        .map_err(|e| format!("self update download bytes ret fail:{}", e))?;

    file.write_all(bytes.as_ref())
        .map_err(|e| format!("self update file write fail:{}", e))?;

    file.sync_all()
        .map_err(|e| format!("self update file sync disk fail:{}", e))?;

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
    let out = Command::new(agent)
        .arg("--version")
        .output()
        .map_err(|e| format!("agent run ret: {:?}", e))?;

    let out = String::from_utf8(out.stdout).map_err(|e| {
        format!(
            "version output contains non-utf8 char:{:?}, invalid agent",
            e
        )
    })?;

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

    let out = cmd.map_err(|e| format!("self update run ret: {:?}", e))?;

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
                             SELF_UPDATE_PATH,
                             UPDATE_FILE_UNZIP_DIR,
                             INSTALL_SCRIPT,
            );
            set_execute_permission(script.clone()).map_err(|e|format!("set execute permission fail: {:?}", e))?;
            let cmd = Command::new("sh")
            .args(&[
                "-c",
                format!("{} restart", script).as_str()
            ])
            .output();
        } else if #[cfg(windows)] {
           let cmd = wow64_disable_exc(move ||{
            Command::new("cmd.exe")
                .args(&["/C","sc stop tatsvc & sc start tatsvc"])
                .output()});
        }
    }

    let out = cmd.map_err(|e| format!("run cmd fail: {:?}", e))?;
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
