use crate::database::KeystoreDB;
use crate::error::{Error, ResponseCode};
use crate::key_parameter::KeyParameter;
use anyhow::Result;
use log::info;

pub struct LegacyImporter {
    db: std::sync::Arc<std::sync::Mutex<KeystoreDB>>,
}

impl LegacyImporter {
    pub fn new(db: std::sync::Arc<std::sync::Mutex<KeystoreDB>>) -> Self {
        Self { db }
    }

    pub fn import_legacy_key(
        &self,
        _alias: &str,
        _namespace: i64,
        _key_blob: &[u8],
        _params: &[KeyParameter],
    ) -> Result<i64> {
        info!("Legacy key import requested (not implemented)");
        Err(Error::Rc(ResponseCode::Unimplemented).into())
    }

    pub fn can_import(&self) -> bool {
        false
    }
}
