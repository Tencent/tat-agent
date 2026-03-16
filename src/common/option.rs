use crate::executor::execute_arg_command;
use crate::network::{InvocationNormalTask, Tag, register, unregister};

use std::{process::exit, sync::LazyLock};

use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Opts {
    /// Work as pty server (for debug)
    #[clap(short, long)]
    pub server_mode: bool,

    /// Use console as log appender
    #[clap(short, long)]
    pub console_log: bool,

    /// Do not daemonize
    #[cfg(unix)]
    #[clap(short, long)]
    pub no_daemon: bool,

    /// Do not wait image state complete
    #[cfg(windows)]
    #[clap(short, long)]
    pub ignore_image_state: bool,

    #[command(subcommand)]
    command: Option<EnumCommands>,
}

#[derive(Subcommand, Debug)]
enum EnumCommands {
    /// Register machine to TAT server
    Register(RegisterArgs),

    /// Unregister machine
    Unregister,

    /// Execute single command dispatch flow for testing
    Execute(ExecuteArgs),
}

#[derive(Args, Debug)]
struct RegisterArgs {
    /// The region to register
    region: String,

    /// `register_code_id` from `CreateRegisterCode()` API
    id: String,

    /// `register_code_value` from `CreateRegisterCode()` API
    value: String,

    /// Tag in key:value format to attach to this instance (can be specified multiple times)
    #[arg(short, long)]
    tag: Vec<String>,
}

#[derive(Args, Debug)]
struct ExecuteArgs {
    /// Test command content
    command: String,

    /// Command execution timeout (in seconds)
    #[arg(short, long, default_value_t = 60)]
    timeout: u64,

    //=============== UNIX =================
    /// Command type (e.g. SHELL)
    #[cfg(unix)]
    #[arg(short, long, default_value = "SHELL")]
    command_type: String,

    /// Username to execute the command
    #[cfg(unix)]
    #[arg(short, long, default_value = "root")]
    user: String,

    /// Working directory for command execution
    #[cfg(unix)]
    #[arg(short, long, default_value = "/root")]
    work_dir: String,

    //=============== WINDOWS =================
    /// Command type (e.g. POWERSHELL, BAT)
    #[cfg(windows)]
    #[arg(short, long, default_value = "POWERSHELL")]
    command_type: String,

    /// Username to execute the command
    #[cfg(windows)]
    #[arg(short, long, default_value = "System")]
    user: String,

    /// Working directory for command execution
    #[cfg(windows)]
    #[arg(
        short,
        long,
        default_value = r"C:\Program Files\QCloud\tat_agent\workdir"
    )]
    work_dir: String,
}

impl Opts {
    pub fn get_opts() -> &'static Opts {
        static INS: LazyLock<Opts> = LazyLock::new(Opts::parse);
        &INS
    }
}

pub fn check_register_args() {
    let Some(EnumCommands::Register(args)) = Opts::get_opts().command.as_ref() else {
        return;
    };
    if args.tag.len() > 10 {
        eprintln!("Error: too many tags (max 10, got {})", args.tag.len());
        exit(-1)
    }
    let mut tags: Vec<Tag> = Vec::with_capacity(args.tag.len());
    for raw in &args.tag {
        let Some((key, value)) = raw.split_once(':').map(|(k, v)| (k.trim(), v.trim())) else {
            eprintln!("Error: invalid tag format `{raw}`, expected key:value");
            exit(-1)
        };
        if key.is_empty() || value.is_empty() {
            eprintln!("Error: invalid tag `{raw}`, key and value must not be empty");
            exit(-1)
        }
        tags.push(Tag {
            key: key.to_string(),
            value: value.to_string(),
        })
    }

    if let Err(err) = register(&args.region, &args.id, &args.value, tags) {
        eprintln!("register failed: {:#}", err);
        exit(-1)
    }
    println!("register success");
    exit(0)
}

pub fn check_unregister_args() {
    let Some(EnumCommands::Unregister) = Opts::get_opts().command.as_ref() else {
        return;
    };
    if let Err(err) = unregister() {
        eprintln!("unregister failed: {:#}", err);
        exit(-1)
    }
    println!("unregister success");
    exit(0)
}

pub fn check_execute_args() {
    let Some(EnumCommands::Execute(args)) = Opts::get_opts().command.as_ref() else {
        return;
    };
    let command = STANDARD.encode(&args.command);
    let task = InvocationNormalTask {
        command,
        time_out: args.timeout,
        command_type: args.command_type.clone(),
        username: args.user.clone(),
        working_directory: args.work_dir.clone(),
        invocation_task_id: String::from("invt-testargcmd"),
        cos_bucket_url: String::new(),
        cos_bucket_prefix: String::new(),
    };
    execute_arg_command(task);
}
