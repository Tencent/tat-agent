extern crate tat_agent;
use futures01::{future, Future, Stream};
use hyper::server::Server;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use response::AgentRequest;
use response::Empty;
use serde_json::from_str;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;

use crate::support::response;

type ResponseFuture = Box<dyn Future<Item = Response<Body>, Error = hyper::error::Error> + Send>;

pub fn start(port: u16) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let new_service = move || {
        service_fn(move |req: Request<Body>| {
            println!("request: {:?}", req);
            req.into_body().concat2().and_then(|whole_body| {
                let body_bytes = whole_body.into_bytes().to_vec();
                let s = match str::from_utf8(&body_bytes) {
                    Ok(v) => v,
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
                let rr = from_str::<AgentRequest<Empty>>(&s).unwrap();
                let action_str = &rr.general_params.action;
                println!("action: {}", action_str);
                match action_str as &str {
                    "DescribeTasks" => {
                        describe_tasks(Request::new(Body::from(format!("{:?}", &body_bytes))))
                    }
                    "ReportTaskStart" => {
                        report_task_start(Request::new(Body::from(format!("{:?}", &body_bytes))))
                    }
                    "UploadTaskLog" => {
                        upload_task_log(Request::new(Body::from(format!("{:?}", &body_bytes))))
                    }
                    "ReportTaskFinish" => {
                        report_task_finish(Request::new(Body::from(format!("{:?}", &body_bytes))))
                    }
                    "CheckUpdate" => {
                        check_update(Request::new(Body::from(format!("{:?}", &body_bytes))))
                    }
                    _ =>   Box::new(future::ok(Response::new(Body::from("hello"))))
                }
            })
        })
    };
    let server = Server::bind(&addr)
        .serve(new_service)
        .map_err(|e| eprintln!("Server error: {}", e));
    hyper::rt::run(server);
}

fn describe_tasks(req: Request<Body>) -> ResponseFuture {
    assert_eq!(req.uri(), "/");
    println!("describe tasks");
    let body = req.into_body();
    Box::new(
        body.concat2()
            .from_err()
            .and_then(|_whole_body| Box::new(future::ok(response::tasks_response()))),
    )
}

fn report_task_start(req: Request<Body>) -> ResponseFuture {
    assert_eq!(req.uri(), "/");
    println!("report task start");
    let body = req.into_body();
    Box::new(
        body.concat2()
            .from_err()
            .and_then(|_whole_body| Box::new(future::ok(response::start_response()))),
    )
}

fn report_task_finish(req: Request<Body>) -> ResponseFuture {
    assert_eq!(req.uri(), "/");
    println!("report task finish");
    let body = req.into_body();
    Box::new(
        body.concat2()
            .from_err()
            .and_then(|_whole_body| Box::new(future::ok(response::start_response()))),
    )
}

fn upload_task_log(req: Request<Body>) -> ResponseFuture {
    assert_eq!(req.uri(), "/");
    println!("upload task log");
    let body = req.into_body();
    Box::new(
        body.concat2()
            .from_err()
            .and_then(|whole_body| {
                let str_body = String::from_utf8(whole_body.to_vec()).unwrap();
                let _words: Vec<&str> = str_body.split('=').collect();
                Box::new(future::ok(response::upload_response()))
            }),
    )
}

fn check_update(req: Request<Body>) -> ResponseFuture {
    assert_eq!(req.uri(), "/");
    println!("check update");
    let body = req.into_body();
    Box::new(
        body.concat2()
            .from_err()
            .and_then(|_whole_body| Box::new(future::ok(response::check_update_response()))),
    )
}