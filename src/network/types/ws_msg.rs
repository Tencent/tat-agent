use crate::common::get_current_username;
use crate::tssh::{WS_BIN_MSG, WS_TXT_MSG};

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::{io::Cursor, marker::PhantomData};

use anyhow::{Context, Result};
use bson::Document;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const EVENT_KICK: &str = "kick";
pub const EVENT_CHECK_UPDATE: &str = "CheckUpdate";
pub const EVENT_FORCE_RESTART: &str = "ForceRestart";

/// Generic message envelope sent over the WebSocket transport.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct MsgBase<T> {
    pub r#type: String,
    pub seq: u64,
    pub data: T,
}

/// A message with a format-tagged session/channel identifier.
pub type Msg<F, T> = MsgBase<MsgId<F, T>>;

/// Session and channel routing identifier paired with a format-specific payload.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct MsgId<F: MsgFormat, T> {
    pub session_id: String,

    // Compatible with legacy front-end code
    // If no channel_id is provided, use empty string as channel_id.
    #[serde(default)]
    pub channel_id: String,

    #[serde(flatten)]
    pub inner: F::Wrapper<T>,
}

impl<F: MsgFormat, T> Display for MsgId<F, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.session_id, self.channel_id)
    }
}

/// Build a response `MsgId<F, T>` from a new payload and a reference request ID.
/// Session/channel routing is cloned from the request, and the format-specific
/// wrapper is constructed via [`MsgFormat::rewrap`].
impl<T, U, F: MsgFormat> From<(T, &MsgId<F, U>)> for MsgId<F, T> {
    fn from(value: (T, &MsgId<F, U>)) -> Self {
        MsgId {
            session_id: value.1.session_id.clone(),
            channel_id: value.1.channel_id.clone(),
            inner: F::rewrap(value.0, &value.1.inner),
        }
    }
}

impl<F: MsgFormat, T> MsgId<F, T> {
    /// Create an `Empty`-payload copy of this identifier, reusing the same
    /// session/channel routing for a response or forwarded message.
    pub fn empty(&self) -> MsgId<F, Empty> {
        (Empty, self).into()
    }
}

/// Serialization format abstraction for WebSocket messages.
pub trait MsgFormat: Sized {
    /// The wrapper type that holds a payload `T` plus any format-specific metadata needed.
    type Wrapper<T>;

    /// The error type used when a handler needs to report a failure for a
    /// message carrying payload `T`.
    type Err<T>;

    /// The event-bus event name used for this format's raw frame delivery.
    fn msg_event() -> &'static str;

    /// Build a new wrapper from `payload`, inheriting any format-specific
    /// fields from `prev`.
    fn rewrap<T, U>(payload: T, prev: &Self::Wrapper<U>) -> Self::Wrapper<T>;

    /// Deserialize a complete `Msg<Self, T>` from raw bytes received over the
    /// WebSocket transport.
    fn parse<T: DeserializeOwned>(data: Vec<u8>) -> Result<Msg<Self, T>>;

    /// Serialize a complete `Msg<Self, T>` to bytes for transmission over the
    /// WebSocket transport.
    fn to_bytes<T: Serialize>(msg: &Msg<Self, T>) -> Vec<u8>;

    /// Construct the format-specific error payload from a human-readable message.
    fn err<T, E: ToString>(e: E) -> Self::Err<T>;
}

/// Marker type for JSON-formatted messages.
pub struct Json;

/// Transparent wrapper for JSON-encoded message payloads.
#[derive(Serialize, Deserialize, Debug)]
pub struct JsonData<T>(pub T);

impl MsgFormat for Json {
    type Wrapper<T> = JsonData<T>;
    type Err<T> = PtyError;

    fn msg_event() -> &'static str {
        WS_TXT_MSG
    }

    fn rewrap<T, U>(payload: T, _prev: &Self::Wrapper<U>) -> Self::Wrapper<T> {
        JsonData(payload)
    }

    fn parse<T: DeserializeOwned>(data: Vec<u8>) -> Result<Msg<Self, T>> {
        serde_json::from_slice::<Msg<Self, T>>(&data).with_context(|| {
            let origin_msg = unsafe { std::str::from_utf8_unchecked(&data) };
            format!("parse JSON from_slice failed, origin msg: {origin_msg}")
        })
    }

    fn to_bytes<T: Serialize>(msg: &Msg<Self, T>) -> Vec<u8> {
        serde_json::to_string(msg)
            .expect("JSON serialize failed")
            .into_bytes()
    }

    fn err<T, E: ToString>(e: E) -> Self::Err<T> {
        PtyError::new(e)
    }
}

/// Marker type for BSON-formatted messages.
pub struct Bson;

/// BSON message payload wrapper that preserves `custom_data` across request/response cycles.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BsonData<T> {
    pub custom_data: String,
    pub data: T,
}

impl MsgFormat for Bson {
    type Wrapper<T> = BsonData<T>;
    type Err<T> = ErrMsg<T>;

    fn msg_event() -> &'static str {
        WS_BIN_MSG
    }

    fn rewrap<T, U>(payload: T, prev: &Self::Wrapper<U>) -> Self::Wrapper<T> {
        BsonData {
            custom_data: prev.custom_data.clone(),
            data: payload,
        }
    }

    fn parse<T: DeserializeOwned>(data: Vec<u8>) -> Result<Msg<Self, T>> {
        let doc = Document::from_reader(&mut Cursor::new(data))
            .context("parse BSON from_reader failed")?;
        bson::from_document::<Msg<Self, T>>(doc).context("parse BSON from_document failed")
    }

    fn to_bytes<T: Serialize>(msg: &Msg<Self, T>) -> Vec<u8> {
        let mut data = Vec::new();
        let _ = bson::to_bson(msg)
            .expect("BSON serialize to_bson failed")
            .as_document()
            .expect("BSON serialize as_document failed")
            .to_writer(&mut data);
        data
    }

    fn err<T, E: ToString>(e: E) -> Self::Err<T> {
        ErrMsg::<T>::new(e)
    }
}

/// Empty payload for messages that carry no data.
#[derive(Serialize, Deserialize, Debug)]
pub struct Empty;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyStart {
    #[serde(default = "get_current_username")]
    pub user_name: String,
    #[serde(flatten)]
    pub prog: Option<Program>,
    pub cols: u16,
    pub rows: u16,
    #[serde(default)]
    pub init_block: bool,
    #[serde(default)]
    pub no_shell: bool,
    #[serde(default)]
    pub envs: HashMap<String, String>,
    pub cwd: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Program {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyInput {
    pub input: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyResize {
    pub cols: u16,
    pub rows: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PtyStop;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyOutput {
    pub output: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PtyReady;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyMaxRate {
    pub rate: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PtyPing;

#[derive(Serialize, Deserialize, Debug)]
pub struct PtyPong;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PtyError {
    pub reason: String,
}

impl PtyError {
    pub fn new(reason: impl ToString) -> Self {
        let reason = reason.to_string();
        Self { reason }
    }
}

/// Generic error message with a type tag for format-specific routing.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ErrMsg<T> {
    pub error: String,
    #[serde(skip)]
    pub type_tag: PhantomData<T>,
}

impl<T> ErrMsg<T> {
    pub fn new(error: impl ToString) -> Self {
        Self {
            error: error.to_string(),
            type_tag: Default::default(),
        }
    }
}

//file msg
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFileReq {
    pub path: String,
    pub mode: u32,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub is_dir: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFileResp {
    pub created: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteFileReq {
    pub path: String,
    #[serde(default)]
    pub is_dir: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteFileResp {
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ReadFileReq {
    pub path: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_read_size")]
    pub size: usize,
}

fn default_read_size() -> usize {
    usize::MAX
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ReadFileResp {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub offset: usize,
    pub length: usize,
    pub is_last: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WriteFileReq {
    pub path: String,
    pub offset: Option<usize>,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct WriteFileResp {
    pub length: usize,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct FileExistReq {
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct FileExistResp {
    pub exists: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct FileInfoReq {
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FileInfoResp {
    pub r#type: String,
    pub name: String,
    pub size: u64,
    pub modify_time: u64,
    pub access_time: u64,
    #[cfg(unix)]
    pub owner: u32,
    #[cfg(unix)]
    pub group: u32,
    #[cfg(unix)]
    pub rights: String,
    #[cfg(unix)]
    pub longname: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ListPathReq {
    pub path: String,
    #[serde(default = "default_list_filter")]
    pub filter: String,
    #[serde(default = "default_show_hidden")]
    pub show_hidden: bool,
}

fn default_list_filter() -> String {
    "*".to_string()
}

fn default_show_hidden() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ListPathResp {
    pub index: usize,
    pub is_last: bool,
    pub files: Vec<FileInfoResp>,
}

//exec msg
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdReq {
    pub cmd: String,
}

#[cfg(unix)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdResp {
    pub output: String,
}

//exec msg
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdStreamReq {
    pub cmd: String,
    pub timeout: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCmdStreamResp {
    pub index: u32,
    pub is_last: bool,
    // #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

//proxy msg
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyNew {
    pub proxy_id: String,
    pub port: String,
    #[serde(default = "default_ip")]
    pub ip: String,
}

fn default_ip() -> String {
    "127.0.0.1".to_string()
}

//proxy msg
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyReady {
    pub proxy_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyData {
    pub proxy_id: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ProxyClose {
    pub proxy_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectForwardData {
    pub session_id: String,
}

/// Metadata for a message type: its event name, whether it requires a channel,
/// and whether it must be dispatched synchronously (in order) rather than concurrently.
pub trait MsgSpec {
    const MSG_TYPE: &'static str;
    const NEED_CHANNEL: bool = true;
    const NEED_SYNC_DISPATCH: bool = false;
}

macro_rules! batch_impl_msg_spec {
    // Top-level: dispatch comma-separated entries
    // Each entry is: types : spec
    ($($ty:ident $(| $rest:ident)* : $spec:tt),* $(,)?) => {
        $(
            batch_impl_msg_spec!(@entry $ty, $spec);
            $(
                batch_impl_msg_spec!(@entry $rest, $spec);
            )*
        )*
    };
    // Simple string only: defaults for both
    (@entry $ty:ident, ($val:expr)) => {
        impl MsgSpec for $ty {
            const MSG_TYPE: &'static str = $val;
        }
    };
    // With NoNeedChannel
    (@entry $ty:ident, ($val:expr, NoNeedChannel)) => {
        impl MsgSpec for $ty {
            const MSG_TYPE: &'static str = $val;
            const NEED_CHANNEL: bool = false;
        }
    };
    // With SyncDispatch
    (@entry $ty:ident, ($val:expr, SyncDispatch)) => {
        impl MsgSpec for $ty {
            const MSG_TYPE: &'static str = $val;
            const NEED_SYNC_DISPATCH: bool = true;
        }
    };
    // With both NoNeedChannel and SyncDispatch
    (@entry $ty:ident, ($val:expr, NoNeedChannel, SyncDispatch)) => {
        impl MsgSpec for $ty {
            const MSG_TYPE: &'static str = $val;
            const NEED_CHANNEL: bool = false;
            const NEED_SYNC_DISPATCH: bool = true;
        }
    };
    // With both (reverse order)
    (@entry $ty:ident, ($val:expr, SyncDispatch, NoNeedChannel)) => {
        impl MsgSpec for $ty {
            const MSG_TYPE: &'static str = $val;
            const NEED_CHANNEL: bool = false;
            const NEED_SYNC_DISPATCH: bool = true;
        }
    };
}

batch_impl_msg_spec! {
    PtyStart: ("PtyStart", NoNeedChannel),
    PtyStop: ("PtyStop", NoNeedChannel),
    PtyResize: ("PtyResize"),
    PtyInput: ("PtyInput", SyncDispatch),
    PtyReady: ("PtyReady"),
    PtyOutput: ("PtyOutput"),
    PtyError: ("PtyError"),

    PtyMaxRate: ("PtyMaxRate", NoNeedChannel),
    PtyPing: ("PtyPing"),
    PtyPong: ("PtyPong"),

    ExecCmdReq: ("PtyExecCmd"),
    ExecCmdStreamReq | ExecCmdStreamResp: ("PtyExecCmdStream"),

    ProxyNew: ("PtyProxyNew", NoNeedChannel),
    ProxyReady: ("PtyProxyReady"),
    ProxyData: ("PtyProxyData", SyncDispatch),
    ProxyClose: ("PtyProxyClose", NoNeedChannel),

    CreateFileReq | CreateFileResp: ("PtyCreateFile"),
    DeleteFileReq | DeleteFileResp: ("PtyDeleteFile"),
    ListPathReq | ListPathResp: ("PtyListPath"),
    FileExistReq | FileExistResp: ("PtyFileExist"),
    FileInfoReq | FileInfoResp: ("PtyFileInfo"),
    WriteFileReq | WriteFileResp: ("PtyWriteFile"),
    ReadFileReq | ReadFileResp: ("PtyReadFile"),

    Empty: (""),
}

#[cfg(unix)]
batch_impl_msg_spec! {
    ExecCmdResp: ("PtyExecCmd"),
}

/// Delegates `MsgSpec` implementation to a `Source` type,
/// so wrapper types inherit the spec of their inner type.
pub trait MsgSpecInherit {
    type Source: MsgSpec;
}

impl<T: MsgSpecInherit> MsgSpec for T {
    const MSG_TYPE: &'static str = T::Source::MSG_TYPE;
    const NEED_CHANNEL: bool = T::Source::NEED_CHANNEL;
    const NEED_SYNC_DISPATCH: bool = T::Source::NEED_SYNC_DISPATCH;
}

impl<T: MsgSpec> MsgSpecInherit for ErrMsg<T> {
    type Source = T;
}

impl<T: MsgSpec> MsgSpecInherit for JsonData<T> {
    type Source = T;
}

impl<T: MsgSpec> MsgSpecInherit for BsonData<T> {
    type Source = T;
}
