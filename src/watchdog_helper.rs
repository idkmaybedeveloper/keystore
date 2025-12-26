pub mod watchdog {
    pub struct WatchPoint;

    pub const DEFAULT_TIMEOUT_MS: u64 = 500;

    pub fn watch_millis(_id: &'static str, _millis: u64) -> Option<WatchPoint> {
        None
    }

    pub fn watch(_id: &'static str) -> Option<WatchPoint> {
        None
    }

    pub fn watch_millis_with(
        _id: &'static str,
        _millis: u64,
        _context: impl std::fmt::Debug + Send + 'static,
    ) -> Option<WatchPoint> {
        None
    }
}
