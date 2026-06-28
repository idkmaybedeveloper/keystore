use std::sync::{Arc, Mutex};
use std::time::Duration;

type TaskList = Arc<Mutex<Vec<Box<dyn Fn() + Send + 'static>>>>;

pub struct AsyncTask {
    tasks: TaskList,
}

impl AsyncTask {
    pub fn new() -> Self {
        Self { tasks: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn add_idle<F>(&self, task: F)
    where
        F: Fn() + Send + 'static,
    {
        let mut tasks = self.tasks.lock().unwrap();
        tasks.push(Box::new(task));
    }

    pub fn run_pending(&self) {
        let mut tasks = self.tasks.lock().unwrap();
        while let Some(task) = tasks.pop() {
            task();
        }
    }

    pub fn schedule_periodic<F>(&self, _interval: Duration, _task: F)
    where
        F: Fn() + Send + 'static,
    {
    }
}

impl Default for AsyncTask {
    fn default() -> Self {
        Self::new()
    }
}
