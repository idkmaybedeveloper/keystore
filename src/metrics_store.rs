use crate::metrics::Metrics;
use std::sync::Arc;

pub struct MetricsStore {
    metrics: Arc<Metrics>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self { metrics: Arc::new(Metrics::new()) }
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub fn record_key_operation(&self, operation: &str, duration_ms: f64) {
        self.metrics.record(&format!("key_operation_{}", operation), duration_ms);
    }

    pub fn record_key_generation(&self, duration_ms: f64) {
        self.metrics.record("key_generation_time", duration_ms);
    }

    pub fn record_key_retrieval(&self, duration_ms: f64) {
        self.metrics.record("key_retrieval_time", duration_ms);
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new()
    }
}
