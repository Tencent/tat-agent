use super::gather::Gather;
use super::proxy::Proxy;
use super::pty::Pty;
use crate::common::utils::{Stopper, Timer};
use crate::network::types::ws_msg::{PtyBinBase, PtyJsonBase};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use log::{error, info};

const SESSION_REMOVE_INTERVAL: u64 = 60 * 5;

pub struct Session {
    pub session_id: String,
    pub channels: RwLock<HashMap<String, Arc<Channel>>>,
    timer: Timer,
    stopper: Stopper,
}

impl Session {
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_owned(),
            channels: Default::default(),
            timer: Timer::new(SESSION_REMOVE_INTERVAL),
            stopper: Stopper::new(),
        }
    }

    pub fn stop(&self) {
        self.stopper.stop();
    }

    pub fn add_channel(&self, channel_id: &str, channel: Arc<Channel>) -> Result<(), String> {
        let id = format!("{}:{}", self.session_id, channel_id);
        let mut chs = self.channels.write().expect("lock failed");
        if chs.contains_key(channel_id) {
            error!("duplicate add_channel `{id}`");
            Err(format!("channel `{id}` already start"))?
        }
        chs.insert(channel_id.to_owned(), channel.clone());
        info!("add_channel `{id}`");
        Gather::runtime().spawn(async move { channel.process_output().await });
        self.timer.freeze();
        Ok(())
    }

    pub fn remove_channel(&self, channel_id: &str) {
        let _ = self
            .channels
            .write()
            .expect("lock failed")
            .remove(channel_id)
            .map(|ch| {
                ch.stop();
                self.timer.unfreeze();
                info!("remove_channel `{}:{}`", self.session_id, channel_id)
            });
    }

    pub fn get_channel(&self, channel_id: &str) -> Option<Arc<Channel>> {
        self.channels
            .read()
            .expect("lock failed")
            .get(channel_id)
            .map(|ch| {
                ch.update_last_time();
                ch.clone()
            })
    }

    pub async fn process_output(&self) {
        info!("=>Session::process_output: {}", self.session_id);
        let stopper_rx = self.stopper.get_receiver().expect("get_receiver failed");
        tokio::select! {
            _ = stopper_rx => info!("session `{}` stopped", self.session_id),
            _ = self.timer.timeout() => info!("session `{}` timeout", self.session_id),
        };
        Gather::remove_session(&self.session_id);
        info!("session `{}` process_output finished", self.session_id);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for ch in self.channels.read().expect("lock failed").values() {
            ch.stop();
        }
    }
}

pub struct Channel {
    pub session_id: String,
    pub channel_id: String,
    pub plugin: Plugin,
}

impl Channel {
    pub fn new(session_id: &str, channel_id: &str, plugin: Plugin) -> Self {
        Self {
            session_id: session_id.to_owned(),
            channel_id: channel_id.to_owned(),
            plugin,
        }
    }

    pub fn stop(&self) {
        self.plugin.controller.stopper.stop();
    }

    pub fn update_last_time(&self) {
        self.plugin.controller.timer.refresh();
    }

    pub async fn process_output(&self) {
        let id = format!("{}:{}", self.session_id, self.channel_id);
        info!("=>Channel::process_output: {}", id);
        self.plugin.process().await;
        info!("channel `{}` process_output finished", id);
        let Some(session) = Gather::get_session(&self.session_id) else {
            return;
        };
        session.remove_channel(&self.channel_id);
    }
}

pub struct Plugin {
    pub component: PluginComp,
    pub data: PluginData,
    pub controller: PluginCtrl,
}

pub enum PluginComp {
    Pty(Pty),
    Proxy(Proxy),
    None { username: String },
}

impl Plugin {
    pub fn id(&self) -> String {
        match &self.component {
            PluginComp::Pty(_) => format!("{}:{}", self.data.session_id, self.data.channel_id),
            PluginComp::Proxy(proxy) => proxy.proxy_id.clone(),
            PluginComp::None { .. } => format!("{}:{}", self.data.session_id, self.data.channel_id),
        }
    }

    pub async fn process(&self) {
        let id = self.id();
        match &self.component {
            PluginComp::Pty(pty) => pty.process(&id, &self.data, &self.controller).await,
            PluginComp::Proxy(proxy) => proxy.process(&id, &self.data, &self.controller).await,
            PluginComp::None { .. } => tokio::select! {
                _ = self.controller.stopper.get_receiver().expect("get_receiver failed") => (),
                _ = self.controller.timer.timeout() => info!("Channel `{id}` timeout"),
            },
        }
    }

    pub fn try_get_pty(&self) -> Option<&Pty> {
        let PluginComp::Pty(pty) = &self.component else {
            return None;
        };
        Some(pty)
    }

    pub fn try_get_proxy(&self) -> Option<&Proxy> {
        let PluginComp::Proxy(proxy) = &self.component else {
            return None;
        };
        Some(proxy)
    }
}

#[derive(Clone)]
pub struct PluginData {
    pub session_id: String,
    pub channel_id: String,
}

impl<'a, T> From<&'a PtyJsonBase<T>> for PluginData {
    fn from(value: &'a PtyJsonBase<T>) -> Self {
        Self {
            session_id: value.session_id.clone(),
            channel_id: value.channel_id.clone(),
        }
    }
}

impl<'a, T> From<&'a PtyBinBase<T>> for PluginData {
    fn from(value: &'a PtyBinBase<T>) -> Self {
        Self {
            session_id: value.session_id.clone(),
            channel_id: value.channel_id.clone(),
        }
    }
}

pub struct PluginCtrl {
    pub stopper: Stopper,
    pub timer: Timer,
}

impl PluginCtrl {
    pub fn new(interval: u64) -> Self {
        Self {
            timer: Timer::new(interval),
            stopper: Stopper::new(),
        }
    }
}
