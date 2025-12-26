use crate::crypto::{ZVec, generate_aes256_key};
use crate::security_level::SecurityLevel;
use anyhow::Result;
use log::warn;

pub struct BootLevelKeyCache {
    keys: std::collections::HashMap<i32, ZVec>,
}

impl BootLevelKeyCache {
    pub fn new() -> Self {
        Self { keys: std::collections::HashMap::new() }
    }

    pub fn get_or_create_key(&mut self, boot_level: i32) -> Result<ZVec> {
        if let Some(key) = self.keys.get(&boot_level) {
            return Ok(key.clone());
        }

        let key = generate_aes256_key()?;
        self.keys.insert(boot_level, key.clone());
        Ok(key)
    }

    pub fn clear(&mut self) {
        self.keys.clear();
    }
}

impl Default for BootLevelKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_level_zero_key(_security_level: SecurityLevel) -> Result<ZVec> {
    warn!("Boot level keys not fully implemented, using software key");
    generate_aes256_key()
}
