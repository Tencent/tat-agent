use crate::common::consts::EVENT_SLOT_DEFAULT;
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex, RwLock};
type SenderHolder = Arc<Mutex<mpsc::Sender<EventValue>>>;
type Handler = Arc<dyn Fn(String) + Sync + Send + 'static>;

#[derive(Clone)]
pub struct EventBus {
    event_slots: Arc<RwLock<HashMap<String, String>>>,
    event_handlers: Arc<RwLock<HashMap<String, Handler>>>,
    senders: Arc<RwLock<HashMap<String, SenderHolder>>>,
}

struct EventValue {
    event: String,
    value: String,
}

impl EventBus {
    pub fn new() -> Self {
        EventBus {
            event_slots: Arc::new(RwLock::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(HashMap::new())),
            senders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn slot_register<F>(&self, slot: &str, event: &str, handler: F) -> &Self
    where
        F: Fn(String) + 'static + Sync + Send,
    {
        self.event_slots
            .write()
            .unwrap()
            .insert(event.to_string(), slot.to_string());

        self.event_handlers
            .write()
            .unwrap()
            .insert(event.to_string(), Arc::new(handler));

        //Each slot has its own thread
        let mut writer = self.senders.write().unwrap();
        if writer.get(slot).is_none() {
            let (msg_sender, msg_receiver) = std::sync::mpsc::channel::<EventValue>();
            writer.insert(slot.to_string(), Arc::new(Mutex::new(msg_sender)));
            let self_0 = self.clone();
            std::thread::spawn(move || {
                for ev in msg_receiver.iter() {
                    if let Some(handler) =
                        self_0.event_handlers.read().unwrap().get(ev.event.as_str())
                    {
                        handler(ev.value);
                    }
                }
            });
        };
        self
    }

    pub fn register<F>(&self, event: &str, handler: F) -> &Self
    where
        F: Fn(String) + 'static + Sync + Send,
    {
        self.slot_register(EVENT_SLOT_DEFAULT, event, handler)
    }

    pub fn dispatch(&self, event: &str, value: String) {
        //find slot from event
        if let Some(slot) = self.event_slots.read().unwrap().get(event) {
            //find  sender from slot
            if let Some(sender_holder) = self.senders.read().unwrap().get(slot) {
                let _ = sender_holder.lock().unwrap().send(EventValue {
                    event: event.to_string(),
                    value,
                });
            }
        }
    }
}
