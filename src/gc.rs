use crate::database::KeystoreDB;
use anyhow::Result;
use log::info;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub struct Gc {
    db: Arc<Mutex<KeystoreDB>>,
    last_run: Mutex<Option<SystemTime>>,
    interval: Duration,
}

impl Gc {
    pub fn new(db: Arc<Mutex<KeystoreDB>>) -> Self {
        Self { db, last_run: Mutex::new(None), interval: Duration::from_secs(3600) }
    }

    pub fn with_interval(db: Arc<Mutex<KeystoreDB>>, interval: Duration) -> Self {
        Self { db, last_run: Mutex::new(None), interval }
    }

    pub fn should_run(&self) -> bool {
        let last_run = self.last_run.lock().unwrap();
        match *last_run {
            None => true,
            Some(time) => {
                SystemTime::now().duration_since(time).map(|d| d >= self.interval).unwrap_or(true)
            }
        }
    }

    pub fn run(&self) -> Result<()> {
        if !self.should_run() {
            return Ok(());
        }

        info!("Running garbage collection");

        let mut last_run = self.last_run.lock().unwrap();
        *last_run = Some(SystemTime::now());
        drop(last_run);

        let mut db = self.db.lock().unwrap();

        let deleted = db.cleanup_orphaned_entries()?;
        if deleted > 0 {
            info!("GC: Deleted {} orphaned entries", deleted);
        }

        Ok(())
    }
}
