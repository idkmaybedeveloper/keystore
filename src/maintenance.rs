use crate::database::KeystoreDB;
use anyhow::Result;
use log::info;
use std::sync::{Arc, Mutex};

pub struct Maintenance {
    db: Arc<Mutex<KeystoreDB>>,
}

impl Maintenance {
    pub fn new(db: Arc<Mutex<KeystoreDB>>) -> Self {
        Self { db }
    }

    pub fn run_maintenance(&self) -> Result<()> {
        info!("Running maintenance tasks");

        let mut db = self.db.lock().unwrap();

        let deleted = db.cleanup_orphaned_entries()?;
        if deleted > 0 {
            info!("Maintenance: Cleaned up {} orphaned entries", deleted);
        }

        Ok(())
    }

    pub fn vacuum_database(&self) -> Result<()> {
        let mut db = self.db.lock().unwrap();
        db.vacuum()?;
        info!("Database vacuum completed");
        Ok(())
    }
}
