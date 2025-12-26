use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub timestamp: SystemTime,
}

pub struct Metrics {
    metrics: Arc<Mutex<HashMap<String, Vec<Metric>>>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self { metrics: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn record(&self, name: &str, value: f64) {
        let mut metrics = self.metrics.lock().unwrap();
        let entry = metrics.entry(name.to_string()).or_insert_with(Vec::new);
        entry.push(Metric { name: name.to_string(), value, timestamp: SystemTime::now() });

        if entry.len() > 1000 {
            entry.remove(0);
        }
    }

    pub fn get_metrics(&self, name: &str) -> Vec<Metric> {
        let metrics = self.metrics.lock().unwrap();
        metrics.get(name).cloned().unwrap_or_default()
    }

    pub fn get_all_metrics(&self) -> HashMap<String, Vec<Metric>> {
        let metrics = self.metrics.lock().unwrap();
        metrics.clone()
    }

    pub fn clear_old_metrics(&self, max_age: Duration) {
        let mut metrics = self.metrics.lock().unwrap();
        let now = SystemTime::now();

        for values in metrics.values_mut() {
            values.retain(|m| {
                now.duration_since(m.timestamp).map(|age| age < max_age).unwrap_or(false)
            });
        }

        metrics.retain(|_, v| !v.is_empty());
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
