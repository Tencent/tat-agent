use super::{Tssh, session::Channel};
use crate::common::evbus;
use crate::network::types::ws_msg::{MsgFormat, MsgId};
use crate::network::types::ws_msg::{MsgSpec, MsgSpecInherit};

use std::{future::Future, sync::Arc};

use anyhow::{Context, Result};
use log::error;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A request handler that processes a parsed message and sends a reply.
pub trait HandleMsg {
    fn process(&mut self) -> impl Future<Output = ()> + Send;
}

/// A message type that can be dispatched from raw bytes via the event bus.
/// Provides automatic registration with the correct dispatch strategy
pub trait DispatchMsg: MsgSpec + 'static {
    fn dispatch(data: Vec<u8>) -> impl Future<Output = ()> + Send + 'static;

    async fn register() {
        if Self::NEED_SYNC_DISPATCH {
            return evbus::subscribe_future(Self::MSG_TYPE, Self::dispatch).await;
        }
        let handler = |msg| tokio::spawn(async move { Self::dispatch(msg).await });
        evbus::subscribe(Self::MSG_TYPE, handler).await;
    }
}

/// Unified handler for both JSON and BSON WebSocket messages.
/// The format is parameterized by `F`, and the payload type by `T`.
pub struct Handler<F: MsgFormat, T> {
    pub channel: Option<Arc<Channel>>,
    pub request: MsgId<F, T>,
}

impl<F: MsgFormat, T: MsgSpec> MsgSpecInherit for Handler<F, T> {
    type Source = T;
}

impl<F: MsgFormat, T: DeserializeOwned> Handler<F, T> {
    async fn new(data: Vec<u8>) -> Result<Self> {
        let msg = F::parse(data).context("parse msg")?;
        let mut handler = Self {
            channel: None,
            request: msg.data,
        };

        let session_id = &handler.request.session_id;
        let channel_id = &handler.request.channel_id;
        if let Some(session) = Tssh::get_session(session_id).await
            && let Some(channel) = session.get_channel(channel_id).await
        {
            handler.channel = Some(channel);
        }

        Ok(handler)
    }

    pub async fn reply<R: MsgSpec + Serialize>(&self, resp: R) {
        let id = &self.request;
        let inner = (resp, id).into();
        Tssh::reply(inner).await;
    }

    pub async fn reply_err(&self, err: impl ToString)
    where
        F::Err<T>: MsgSpec + Serialize,
    {
        self.reply(F::err(err)).await;
    }
}

impl<F, T> DispatchMsg for Handler<F, T>
where
    F: MsgFormat,
    T: MsgSpec + DeserializeOwned,
    F::Wrapper<T>: Send + Sync,
    F::Wrapper<F::Err<T>>: Send,
    F::Err<T>: MsgSpec + Serialize + Send,
    Self: HandleMsg + 'static,
{
    async fn dispatch(data: Vec<u8>) {
        let mut handler = match Self::new(data).await {
            Ok(h) => h,
            Err(e) => return error!("new handler: {e:#}"),
        };
        let id = &handler.request.to_string();

        if T::NEED_CHANNEL && handler.channel.is_none() {
            error!("dispatch: channel `{id}` not found");
            return handler.reply_err("channel not found").await;
        }

        if T::NEED_SYNC_DISPATCH {
            let ch = handler.channel.as_ref().unwrap().clone();
            if let Err(e) = ch.plugin.component.sync_dispatch(handler) {
                error!("channel `{id}` sync_dispatch failed: {e:#}");
            }
            return;
        }

        handler.process().await
    }
}
