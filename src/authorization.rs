use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct HardwareAuthToken {
    pub user_id: i64,
    pub authenticator_id: i64,
    pub authenticator_type: u32,
    pub timestamp: i64,
    pub mac: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuthTokenEntry {
    pub auth_token: HardwareAuthToken,
    pub time_received: SystemTime,
}

pub struct AuthorizationManager {
    tokens: Arc<Mutex<HashMap<i64, AuthTokenEntry>>>,
}

impl AuthorizationManager {
    pub fn new() -> Self {
        Self { tokens: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn add_auth_token(&self, user_id: i64, token: HardwareAuthToken) {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.insert(
            user_id,
            AuthTokenEntry { auth_token: token, time_received: SystemTime::now() },
        );
    }

    pub fn get_auth_token(&self, user_id: i64) -> Option<AuthTokenEntry> {
        let tokens = self.tokens.lock().unwrap();
        tokens.get(&user_id).cloned()
    }

    pub fn find_auth_token<F>(&self, predicate: F) -> Option<AuthTokenEntry>
    where
        F: Fn(&AuthTokenEntry) -> bool,
    {
        let tokens = self.tokens.lock().unwrap();
        let mut matches: Vec<_> = tokens.values().filter(|e| predicate(e)).collect();
        matches.sort_by_key(|e| e.time_received);
        matches.last().map(|e| (*e).clone())
    }

    pub fn clear_expired(&self, max_age: Duration) {
        let mut tokens = self.tokens.lock().unwrap();
        let now = SystemTime::now();
        tokens.retain(|_, entry| {
            now.duration_since(entry.time_received).map(|age| age < max_age).unwrap_or(false)
        });
    }

    pub fn clear(&self) {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.clear();
    }
}

impl Default for AuthorizationManager {
    fn default() -> Self {
        Self::new()
    }
}
