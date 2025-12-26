use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::{Arc, RwLock};

pub struct PerbootDB {
    grants: RwLock<HashMap<String, i64>>,
}

impl PerbootDB {
    pub fn new() -> Self {
        Self { grants: RwLock::new(HashMap::new()) }
    }

    pub fn add_grant(&self, grant_name: String, key_id: i64) {
        let mut grants = self.grants.write().unwrap();
        grants.insert(grant_name, key_id);
    }

    pub fn get_grant(&self, grant_name: &str) -> Option<i64> {
        let grants = self.grants.read().unwrap();
        grants.get(grant_name).copied()
    }

    pub fn remove_grant(&self, grant_name: &str) -> bool {
        let mut grants = self.grants.write().unwrap();
        grants.remove(grant_name).is_some()
    }

    pub fn list_grants(&self) -> Vec<String> {
        let grants = self.grants.read().unwrap();
        grants.keys().cloned().collect()
    }

    pub fn clear(&self) {
        let mut grants = self.grants.write().unwrap();
        grants.clear();
    }
}

impl Default for PerbootDB {
    fn default() -> Self {
        Self::new()
    }
}

pub static PERBOOT_DB: LazyLock<Arc<PerbootDB>> = LazyLock::new(|| Arc::new(PerbootDB::new()));
