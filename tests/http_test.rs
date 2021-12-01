extern crate tat_agent;

mod support;

use std::sync::Once;
use std::thread;
use support::server;

use tat_agent::common::consts;

static INIT: Once = Once::new();

pub fn initialize() {
    INIT.call_once(|| {
        println!("mock server started...");
        tat_agent::common::logger::init_test_log();
        thread::spawn(move || {
            server::start(8080);
        });
    })
}

#[cfg(test)]
#[tokio::test(basic_scheduler)]
async fn test_describe_tasks() {
    initialize();
    let adapter = tat_agent::http::InvokeAPIAdapter::build(consts::MOCK_INVOKE_API);
    let resp = adapter.describe_tasks();
    assert_eq!(1, resp.await.unwrap().invocation_normal_task_set.len())
}

#[cfg(test)]
#[tokio::test(basic_scheduler)]
async fn test_report_task_start() {
    use std::time::SystemTime;
    use tat_agent::common::asserts::GracefulUnwrap;
    initialize();
    let adapter = tat_agent::http::InvokeAPIAdapter::build(consts::MOCK_INVOKE_API);
    let start_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_exit("sys time may before 1970")
        .as_secs();
    let resp = adapter
        .report_task_start("invt-12345678", start_timestamp)
        .await;
    assert_eq!(true, resp.is_ok());
}

#[cfg(test)]
#[tokio::test(basic_scheduler)]
async fn test_upload_task_log() {
    initialize();
    let adapter = tat_agent::http::InvokeAPIAdapter::build(consts::MOCK_INVOKE_API);
    let resp = adapter
        .upload_task_log(
            "invk-12345678",
            1,
            "some output info".as_bytes().to_vec(),
            0,
        )
        .await;
    assert_eq!(true, resp.is_ok());
}

#[cfg(test)]
#[tokio::test(basic_scheduler)]
async fn test_report_task_finish() {
    initialize();
    let adapter = tat_agent::http::InvokeAPIAdapter::build(consts::MOCK_INVOKE_API);
    let resp = adapter
        .report_task_finish("invk-12345678", "some output info", "", 0, 1, 0, "", "")
        .await;
    assert_eq!(true, resp.is_ok());
}

#[cfg(test)]
#[tokio::test(basic_scheduler)]
async fn test_check_update() {
    let adapter = tat_agent::http::InvokeAPIAdapter::build(consts::MOCK_INVOKE_API);
    let resp = adapter.check_update();
    let resp = resp.await.unwrap();
    assert_eq!(true, resp.need_update());
    assert_eq!("http://example.com", resp.download_url().clone().unwrap());
    assert_eq!(
        "eeb0248363b2e9b66f975abd4f092db8",
        resp.md5().clone().unwrap()
    );
}

#[tokio::test(basic_scheduler)]
async fn test_process_msg() {
    use std::sync::{atomic::AtomicU64, Arc};
    use tat_agent::http::thread::HttpWorker;
    use tat_agent::types::inner_msg::KickMsg;
    initialize();
    let adapter = tat_agent::http::InvokeAPIAdapter::build(consts::MOCK_INVOKE_API);
    let worker = HttpWorker::new(adapter, Arc::new(AtomicU64::new(0)));
    let msg = KickMsg {
        kick_source: String::from("Test"),
    };
    worker.process(msg).await;
}
