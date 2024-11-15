use std::collections::{HashMap, LinkedList};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Condvar, Mutex, RwLock};

use log::debug;

const SLOT_DEFAULT: &str = "event_slot_default";
type Handler = Box<dyn Fn(Vec<u8>) + Sync + Send + 'static>;

pub struct EventBus {
    event_slots: RwLock<HashMap<String, String>>,
    slot_queues: RwLock<HashMap<String, Arc<EventQueue>>>,
    event_handlers: RwLock<HashMap<String, Handler>>,
    dispatch_count: AtomicU64,
    receive_count: AtomicU64,
}

struct Event {
    name: String,
    msg: Vec<u8>,
}

struct EventQueue {
    queue: Mutex<LinkedList<Event>>,
    signal: Condvar,
}

impl EventQueue {
    fn new() -> Self {
        EventQueue {
            queue: Mutex::new(LinkedList::new()),
            signal: Condvar::new(),
        }
    }

    fn queue_event(&self, event: Event) {
        self.queue
            .lock()
            .expect("queue event failed")
            .push_back(event);
        self.signal.notify_one();
    }

    fn pull_event(&self) -> Event {
        let mut guard = self.queue.lock().expect("pull event failed");
        if let Some(event) = guard.pop_front() {
            return event;
        }

        loop {
            guard = self.signal.wait(guard).expect("wait signal failed");
            if let Some(event) = guard.pop_front() {
                return event;
            }
        }
    }
}

impl EventBus {
    pub fn new() -> Self {
        EventBus {
            event_slots: RwLock::new(HashMap::new()),
            event_handlers: RwLock::new(HashMap::new()),
            slot_queues: RwLock::new(HashMap::new()),
            dispatch_count: AtomicU64::new(0),
            receive_count: AtomicU64::new(0),
        }
    }

    pub fn slot_register<F>(self: &Arc<Self>, slot: &str, event: &str, func: F) -> &Arc<Self>
    where
        F: Fn(Vec<u8>) + 'static + Sync + Send,
    {
        self.event_slots
            .write()
            .unwrap()
            .insert(event.to_string(), slot.to_string());

        self.event_handlers
            .write()
            .unwrap()
            .insert(event.to_string(), Box::new(func));

        let mut slot_queues = self.slot_queues.write().expect("slot_queues lock failed");
        if slot_queues.get(slot).is_some() {
            return self;
        };

        //create queue for slot
        let queue = Arc::new(EventQueue::new());
        slot_queues.insert(slot.to_string(), queue.clone());

        //create thread for queue
        let _ = std::thread::Builder::new().name(slot.to_string()).spawn({
            let eb = self.clone();
            move || loop {
                let event = queue.pull_event();
                if let Some(handler) = eb
                    .event_handlers
                    .read()
                    .expect("event_handlers lock failed")
                    .get(&event.name)
                {
                    let count = eb.receive_count.fetch_add(1, SeqCst);
                    debug!("receive_count: {}", count);
                    handler(event.msg);
                }
            }
        });
        self
    }

    pub fn register<F>(self: &Arc<Self>, event: &str, func: F) -> &Arc<Self>
    where
        F: Fn(Vec<u8>) + 'static + Sync + Send,
    {
        self.slot_register(SLOT_DEFAULT, event, func)
    }

    pub fn dispatch(&self, event: &str, msg: Vec<u8>) {
        let count = self.dispatch_count.fetch_add(1, SeqCst);
        debug!("dispatch_count: {}", count);
        if let Some(slot) = self.event_slots.read().expect("lock failed").get(event) {
            //find queues from slot
            if let Some(slot_queues) = self.slot_queues.read().expect("lock failed").get(slot) {
                let name = event.to_string();
                slot_queues.queue_event(Event { name, msg });
            }
        }
    }
}
