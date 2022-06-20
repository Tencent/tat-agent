use std::collections::BTreeMap;
use std::fmt::{self, Debug};
use std::ops::Fn;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

pub struct TimerTask {
    task_id: u64,
    task_fn: Box<dyn Fn() -> ()>,
}

impl TimerTask {
    fn new<F>(task_id: u64, task_fn: F) -> Box<TimerTask>
    where
        F: 'static + Fn() -> (),
    {
        Box::new(TimerTask {
            task_id,
            task_fn: Box::new(task_fn),
        })
    }

    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    pub fn run_task(&self) {
        (self.task_fn)()
    }
}

pub struct Timer {
    cur_id: u64,
    instant: Instant,
    // Key is the elapsed nano seconds from program start.
    // Value is the timer task to run.
    task_map: BTreeMap<u128, Box<TimerTask>>,
}

impl Timer {
    fn new() -> Timer {
        Timer {
            cur_id: 0,
            instant: Instant::now(),
            task_map: BTreeMap::new(),
        }
    }

    fn inc_fetch_cur_id(&mut self) -> u64 {
        self.cur_id = {
            if self.cur_id == std::u64::MAX {
                0
            } else {
                self.cur_id + 1
            }
        };
        self.cur_id
    }

    // Insert the task to the map.
    // Param relative_time is the key wanted, if key conflict, will find next near key to insert,
    // because the key is nano second, so add 1 or some doesn't matter.
    // The probability of nano second key conflict is very small.
    // Return the actual inserted key
    fn insert_task_map(&mut self, relative_time: u128, task: Box<TimerTask>) -> u128 {
        let mut actual_key = relative_time;
        while self.task_map.contains_key(&actual_key) {
            actual_key += 1;
        }
        self.task_map.insert(actual_key, task);
        actual_key
    }

    // Run task_fn() at sec_after seconds later.
    // Return the actual inserted key and task_id.
    pub fn add_task<F>(&mut self, sec_after: u64, task_fn: F) -> (u128, u64)
    where
        F: 'static + Fn() -> (),
    {
        let cur_id = self.inc_fetch_cur_id();
        let task = TimerTask::new(cur_id, task_fn);
        let cur_relative_time = self.instant.elapsed().as_nanos();
        let sec_after = sec_after as u128;
        let actual_key = self.insert_task_map(cur_relative_time + sec_after * 1_000_000_000, task);
        (actual_key, cur_id)
    }

    // Delete a pre-added task, if no need to run it.
    // Return whether the task existed && removed
    pub fn del_task(&mut self, key: u128, task_id: u64) -> bool {
        let item = self.task_map.get(&key);
        if let Some(task) = item {
            if task_id == task.task_id() {
                self.task_map.remove(&key);
                return true;
            }
        }
        false
    }

    // Move the arrived timer task out to run at somewhere else.
    // Because all method of Timer is in the MutexGuard of Timer singleton,
    // And run task may occupy some time, so move out to release the lock.
    pub fn tasks_to_schedule(&mut self) -> Vec<Box<TimerTask>> {
        let now = self.instant.elapsed().as_nanos();
        let mut keys = vec![];
        for (key, _value) in self.task_map.iter() {
            if *key <= now {
                keys.push(*key);
            } else {
                break;
            }
        }
        let mut tasks = vec![];
        for key in &keys {
            let task = self.task_map.remove(key).unwrap();
            tasks.push(task);
        }
        tasks
    }

    // get the singleton, thread safe by mutex wrapped
    pub fn get_instance() -> Arc<Mutex<Timer>> {
        static mut INS: Option<Arc<Mutex<Timer>>> = None;
        let &mut ins;
        unsafe {
            ins = INS.get_or_insert_with(|| Arc::new(Mutex::new(Timer::new())));
        }
        ins.clone()
    }
}

impl Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut task_map_debug = "{".to_string();
        for (key, value) in self.task_map.iter() {
            task_map_debug +=
                format!("(key:{}, value.task_id:{}), ", key, value.task_id()).as_str();
        }
        task_map_debug += "}";

        f.debug_struct("Timer")
            .field("cur_id", &self.cur_id)
            .field("instant", &self.instant)
            .field("task_map_len", &self.task_map.len())
            .field("task_map_debug", &task_map_debug)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    use log::info;

    use crate::common::asserts::GracefulUnwrap;
    use crate::common::logger::init_test_log;

    #[test]
    // because singleton timer has only one instance,
    // we have to put all timer testcase in one.
    // NOTICE: can NOT run together with test_shell_cmd_timeout,
    // because that testcase also use the singleton
    fn test_timer_in_one_case() {
        init_test_log();
        test_timer_task_add_del_schedule();
        test_timer_singleton_inc_cur_id();
        test_several_task();
    }

    // usage of schedule timer tasks
    fn test_several_task() {
        {
            let timer = Timer::get_instance();
            let mut timer = timer.lock().unwrap_or_exit("");
            timer.add_task(3, || {
                info!("running task of after 3");
            });
            timer.add_task(2, || {
                info!("running task of after 2");
            });
            timer.add_task(5, || {
                info!("running task of after 5");
            });
            timer.add_task(2, || {
                info!("running task of after 2 (another)");
            });
        }
        {
            let timer = Timer::get_instance();
            let mut timer = timer.lock().unwrap_or_exit("");
            info!("timer:{:?}", timer);
            let mut cnt = 0;
            while cnt < 4 {
                let tasks = timer.tasks_to_schedule();
                cnt += tasks.len();
                for task in tasks {
                    task.run_task();
                }
                info!("total {} tasks run", cnt);
                thread::sleep(Duration::new(0, 500_000_000));
            }
            info!("timer:{:?}", timer);
        }
    }

    fn test_timer_singleton_inc_cur_id() {
        {
            let timer = Timer::get_instance();
            let mut timer = timer.lock().unwrap_or_exit("");
            let cur = timer.inc_fetch_cur_id();
            assert_eq!(3, cur);
            info!("timer:{:?}", timer);
        }
        {
            let timer = Timer::get_instance();
            let mut timer = timer.lock().unwrap_or_exit("");
            let cur = timer.inc_fetch_cur_id();
            assert_eq!(4, cur);
            info!("timer:{:?}", timer);
        }
    }

    fn test_timer_task_add_del_schedule() {
        {
            let timer = Timer::get_instance();
            let mut timer = timer.lock().unwrap_or_exit("");

            timer.add_task(3, || {
                info!("task after 3");
            });
            info!("timer:{:?}", timer);
            assert_eq!(timer.task_map.len(), 1);
            assert_eq!(timer.cur_id, 1);

            let (key, id) = timer.add_task(1, || {
                info!("task after 1");
            });
            info!("timer:{:?}", timer);
            assert_eq!(timer.task_map.len(), 2);
            assert_eq!(timer.cur_id, 2);
            assert_eq!(id, 2);

            let f = timer.del_task(key, id);
            info!("timer:{:?}", timer);
            assert_eq!(f, true);
            assert_eq!(timer.task_map.len(), 1);
            assert_eq!(timer.cur_id, 2);
        }
        {
            let timer = Timer::get_instance();
            let mut timer = timer.lock().unwrap_or_exit("");

            let tasks = timer.tasks_to_schedule();
            assert_eq!(0, tasks.len());
        }
        thread::sleep(Duration::new(3, 0));
        {
            let timer = Timer::get_instance();
            let mut timer = timer.lock().unwrap_or_exit("");

            let tasks = timer.tasks_to_schedule();
            assert_eq!(1, tasks.len());
            assert_eq!(timer.task_map.len(), 0);

            for task in tasks {
                task.run_task();
            }
        }
    }
}
