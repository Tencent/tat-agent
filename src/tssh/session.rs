use super::{Tssh, proxy::Proxy, pty::Pty};
use crate::common::guard::{PreventRestartGuard, prevent_restart};
use crate::common::{Stopper, Timer};
use crate::network::types::ws_msg::*;
use crate::tssh::handler::HandleMsg;
use crate::{executor::User, tssh::handler::Handler};

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail};
use log::{error, info};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

const SESSION_TTL: Duration = Duration::from_secs(60 * 5); // 5 min

type ChannelMap = RwLock<HashMap<String, Arc<Channel>>>;

pub struct Session {
    pub session_id: String,
    pub channels: ChannelMap,
    timer: Timer,
    stopper: Stopper,
    _guard: PreventRestartGuard, // Hold the restart lock for the entire duration of session
}

impl Session {
    pub async fn new(session_id: &str) -> Self {
        Self {
            _guard: prevent_restart().await,
            session_id: session_id.to_owned(),
            channels: Default::default(),
            timer: Timer::new(SESSION_TTL),
            stopper: Stopper::new(),
        }
    }

    pub async fn stop(&self) {
        self.stopper.stop().await;
    }

    pub async fn add_channel(&self, channel_id: &str, channel: Arc<Channel>) -> Result<()> {
        let id = format!("{}:{}", self.session_id, channel_id);
        let mut chs = self.channels.write().await;
        if chs.contains_key(channel_id) {
            error!("duplicate add_channel `{id}`");
            bail!("channel `{id}` already start");
        }
        chs.insert(channel_id.to_owned(), channel.clone());
        info!("add_channel `{id}`");
        tokio::spawn(async move { channel.process_output().await });
        self.timer.freeze();
        Ok(())
    }

    pub async fn remove_channel(&self, channel_id: &str) {
        if let Some(ch) = self.channels.write().await.remove(channel_id) {
            ch.stop().await;
            self.timer.unfreeze();
            info!("remove_channel `{}:{}`", self.session_id, channel_id)
        }
    }

    pub async fn get_channel(&self, channel_id: &str) -> Option<Arc<Channel>> {
        self.channels.read().await.get(channel_id).map(|ch| {
            ch.plugin.controller.timer.refresh();
            ch.clone()
        })
    }

    pub async fn process_output(&self) {
        info!("=>Session::process_output: {}", self.session_id);
        let stopper_rx = self
            .stopper
            .get_receiver()
            .await
            .expect("get_receiver failed");
        tokio::select! {
            _ = stopper_rx => info!("session `{}` stopped", self.session_id),
            _ = self.timer.timeout() => info!("session `{}` timeout", self.session_id),
        };
        Tssh::remove_session(&self.session_id).await;
        info!("session `{}` process_output finished", self.session_id);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut channels = std::mem::take(&mut self.channels);
        tokio::spawn(async move {
            for ch in channels.get_mut().values() {
                ch.stop().await;
            }
        });
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

    pub async fn stop(&self) {
        self.plugin.controller.stopper.stop().await;
        self.plugin.component.stop_sync_dispatch().await;
    }

    pub async fn process_output(&self) {
        let id = format!("{}:{}", self.session_id, self.channel_id);
        info!("=>Channel::process_output: {}", id);
        self.plugin.process().await;
        info!("channel `{}` process_output finished", id);
        let Some(session) = Tssh::get_session(&self.session_id).await else {
            return;
        };
        session.remove_channel(&self.channel_id).await;
    }
}

pub struct Plugin {
    pub component: PluginComp,
    pub controller: PluginCtrl,
}

impl Plugin {
    pub async fn process(&self) {
        match &self.component {
            PluginComp::Pty(pty, id, ..) => pty.process(id, &self.controller).await,
            PluginComp::Proxy(proxy, id, ..) => proxy.process(id, &self.controller).await,
            PluginComp::Nil { id, .. } => tokio::select! {
                _ = self.controller.stopper.get_receiver().await.expect("get_receiver failed") => (),
                _ = self.controller.timer.timeout() => info!("Channel `{id}` timeout"),
            },
        }
    }

    pub fn try_get_pty(&self) -> Option<&Pty> {
        let PluginComp::Pty(pty, ..) = &self.component else {
            return None;
        };
        Some(pty)
    }

    pub fn try_get_proxy(&self) -> Option<&Proxy> {
        let PluginComp::Proxy(proxy, ..) = &self.component else {
            return None;
        };
        Some(proxy)
    }
}

pub struct SyncDispatcher {
    tx: UnboundedSender<Box<dyn Any + Send + 'static>>,
    stopper: Stopper,
}

async fn handle_sync_dispatch<T: HandleMsg + 'static>() -> SyncDispatcher {
    let (tx, mut rx) = unbounded_channel::<Box<dyn Any + Send + 'static>>();
    let stopper = Stopper::new();
    let stopper_rx = stopper.get_receiver().await.unwrap();
    tokio::spawn(async move {
        let handler = async {
            while let Some(Some(h)) = rx.recv().await.as_mut().map(|any| any.downcast_mut::<T>()) {
                h.process().await;
            }
        };
        tokio::select! {
            _ = handler => (),
            _ = stopper_rx => (),
        }
    });
    SyncDispatcher { tx, stopper }
}

pub enum PluginComp {
    Pty(Pty, MsgId<Json, Empty>, SyncDispatcher),
    Proxy(Proxy, MsgId<Bson, Empty>, SyncDispatcher),
    Nil {
        username: String,
        id: MsgId<Json, Empty>,
    },
}

impl PluginComp {
    pub async fn pty(pty: Pty, req: &MsgId<Json, PtyStart>) -> Self {
        let id = req.empty();
        let tx = handle_sync_dispatch::<Handler<Json, PtyInput>>().await;
        Self::Pty(pty, id, tx)
    }

    pub async fn proxy(proxy: Proxy, req: &MsgId<Bson, ProxyNew>) -> Self {
        let id = req.empty();
        let tx = handle_sync_dispatch::<Handler<Bson, ProxyData>>().await;
        Self::Proxy(proxy, id, tx)
    }

    pub fn get_user(&self) -> Result<Arc<User>> {
        match self {
            Self::Pty(pty, ..) => Ok(pty.user.clone()),
            Self::Nil { username, .. } => User::new(username).map(Arc::new),
            _ => bail!("unsupported channel plugin"),
        }
    }

    pub fn get_sync_dispatcher(&self) -> Result<&SyncDispatcher> {
        match self {
            Self::Pty(.., sd) => Ok(sd),
            Self::Proxy(.., sd) => Ok(sd),
            _ => bail!("unsupported channel plugin"),
        }
    }

    pub fn sync_dispatch<T: Send + 'static>(&self, handler: T) -> Result<()> {
        self.get_sync_dispatcher()?
            .tx
            .send(Box::new(handler))
            .map_err(|e| anyhow!("sync dispatch send failed: {e:#}"))
    }

    pub async fn stop_sync_dispatch(&self) {
        if let Ok(sd) = self.get_sync_dispatcher() {
            sd.stopper.stop().await
        }
    }
}

pub struct PluginCtrl {
    pub stopper: Stopper,
    pub timer: Timer,
}

impl PluginCtrl {
    pub fn new(interval: Duration) -> Self {
        Self {
            timer: Timer::new(interval),
            stopper: Stopper::new(),
        }
    }
}
