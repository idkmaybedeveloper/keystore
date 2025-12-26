use crate::database::KeystoreDB;
use crate::super_key::SuperKeyManager;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, RwLock};

pub static DB_PATH: LazyLock<RwLock<PathBuf>> =
    LazyLock::new(|| RwLock::new(PathBuf::from("/tmp/keystore")));

pub static SUPER_KEY: LazyLock<Arc<RwLock<SuperKeyManager>>> =
    LazyLock::new(|| Arc::new(RwLock::new(SuperKeyManager::new())));

pub fn create_thread_local_db() -> KeystoreDB {
    let db_path = DB_PATH.read().expect("Could not get the database directory");
    KeystoreDB::new(&db_path).expect("Failed to open database")
}

pub fn get_keymint_device(
    _security_level: &crate::security_level::SecurityLevel,
) -> anyhow::Result<(Arc<Mutex<()>>, crate::database::Uuid)> {
    Err(anyhow::anyhow!("KeyMint not available in standalone mode"))
}

pub fn get_remotely_provisioned_component_name(
    _security_level: &crate::security_level::SecurityLevel,
) -> anyhow::Result<Option<String>> {
    Ok(None)
}
