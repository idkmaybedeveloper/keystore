pub mod perboot;
pub mod utils;

use crate::key_parameter::KeyParameter;
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub use utils::{BlobMetaData, BlobMetaEntry, KeyMetaData, KeyMetaEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Client = 0,
    Super = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Self([0; 16])
    }
}

pub static KEYSTORE_UUID: Uuid = Uuid([
    0x41, 0xe3, 0xb9, 0xce, 0x27, 0x58, 0x4e, 0x91, 0xbc, 0xfd, 0xa5, 0x5d, 0x91, 0x85, 0xab, 0x11,
]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime(i64);

impl DateTime {
    pub fn now() -> Result<Self> {
        let duration =
            SystemTime::now().duration_since(UNIX_EPOCH).context("Time went backwards")?;
        Ok(Self(duration.as_millis() as i64))
    }

    pub fn to_millis_epoch(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedBy {
    Password,
    KeyId(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubComponentType {
    KeyBlob = 0,
    Cert = 1,
    CertChain = 2,
}

#[derive(Debug)]
pub struct KeyIdGuard(i64);

impl KeyIdGuard {
    pub fn id(&self) -> i64 {
        self.0
    }
}

struct KeyIdLockDb {
    locked_keys: Mutex<std::collections::HashSet<i64>>,
    cond_var: Condvar,
}

static KEY_ID_LOCK: std::sync::LazyLock<KeyIdLockDb> = std::sync::LazyLock::new(|| KeyIdLockDb {
    locked_keys: Mutex::new(std::collections::HashSet::new()),
    cond_var: Condvar::new(),
});

impl KeyIdLockDb {
    fn get(&self, key_id: i64) -> KeyIdGuard {
        let mut locked_keys = self.locked_keys.lock().unwrap();
        while locked_keys.contains(&key_id) {
            locked_keys = self.cond_var.wait(locked_keys).unwrap();
        }
        locked_keys.insert(key_id);
        KeyIdGuard(key_id)
    }
}

impl Drop for KeyIdGuard {
    fn drop(&mut self) {
        let mut locked_keys = KEY_ID_LOCK.locked_keys.lock().unwrap();
        locked_keys.remove(&self.0);
        drop(locked_keys);
        KEY_ID_LOCK.cond_var.notify_all();
    }
}

#[derive(Debug, Default)]
pub struct KeyEntry {
    id: i64,
    key_blob: Option<Vec<u8>>,
    cert: Option<Vec<u8>>,
    cert_chain: Option<Vec<u8>>,
    km_uuid: Uuid,
    parameters: Vec<KeyParameter>,
    metadata: KeyMetaData,
}

impl KeyEntry {
    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn take_key_blob(&mut self) -> Option<Vec<u8>> {
        self.key_blob.take()
    }

    pub fn take_cert(&mut self) -> Option<Vec<u8>> {
        self.cert.take()
    }

    pub fn take_cert_chain(&mut self) -> Option<Vec<u8>> {
        self.cert_chain.take()
    }

    pub fn km_uuid(&self) -> &Uuid {
        &self.km_uuid
    }

    pub fn into_key_parameters(self) -> Vec<KeyParameter> {
        self.parameters
    }

    pub fn metadata(&self) -> &KeyMetaData {
        &self.metadata
    }
}

#[derive(Debug)]
pub struct KeyDescriptor {
    pub domain: Domain,
    pub namespace: i64,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    App = 0,
    Selinux = 1,
    KeyId = 2,
}

pub struct KeystoreDB {
    pub(crate) conn: Connection,
}

impl KeystoreDB {
    const PERSISTENT_DB_FILENAME: &'static str = "persistent.sqlite";

    pub fn new(db_root: &Path) -> Result<Self> {
        let persistent_path = db_root.join(Self::PERSISTENT_DB_FILENAME);
        let conn = Connection::open(&persistent_path).context("Failed to open database")?;

        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS keyentry (
                id INTEGER PRIMARY KEY,
                key_type INTEGER,
                domain INTEGER,
                namespace INTEGER,
                alias TEXT,
                km_uuid BLOB
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS blobentry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subcomponent_type INTEGER,
                keyentryid INTEGER,
                blob BLOB
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS blobmetadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                blobentryid INTEGER,
                tag INTEGER,
                data BLOB
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS keyparameter (
                keyentryid INTEGER,
                tag INTEGER,
                data BLOB
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS keymetadata (
                keyentryid INTEGER,
                tag INTEGER,
                data BLOB
            )",
            [],
        )?;

        Ok(())
    }

    pub fn store_new_key(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        params: &[KeyParameter],
        blob: &[u8],
        blob_metadata: &BlobMetaData,
        key_metadata: &KeyMetaData,
        km_uuid: &Uuid,
    ) -> Result<KeyIdGuard> {
        let tx = self.conn.transaction()?;

        let key_id = {
            let mut stmt = tx.prepare(
                "INSERT INTO keyentry (key_type, domain, namespace, alias, km_uuid)
                 VALUES (?, ?, ?, ?, ?)",
            )?;
            stmt.execute(params![
                key_type as i32,
                key.domain as i32,
                key.namespace,
                key.alias,
                km_uuid.0.as_slice()
            ])?;
            tx.last_insert_rowid()
        };

        let key_id_guard = KEY_ID_LOCK.get(key_id);

        {
            let mut stmt = tx.prepare(
                "INSERT INTO blobentry (subcomponent_type, keyentryid, blob)
                 VALUES (?, ?, ?)",
            )?;
            stmt.execute(params![SubComponentType::KeyBlob as i32, key_id, blob])?;
            let blob_id = tx.last_insert_rowid();

            for (tag, entry) in blob_metadata.iter() {
                let mut stmt = tx.prepare(
                    "INSERT INTO blobmetadata (blobentryid, tag, data)
                     VALUES (?, ?, ?)",
                )?;
                let data = serde_cbor::to_vec(entry)?;
                stmt.execute(params![blob_id, tag, data])?;
            }
        }

        for param in params {
            let mut stmt = tx.prepare(
                "INSERT INTO keyparameter (keyentryid, tag, data)
                 VALUES (?, ?, ?)",
            )?;
            let data = serde_cbor::to_vec(param)?;
            stmt.execute(params![key_id, param.tag as i32, data])?;
        }

        for (tag, entry) in key_metadata.iter() {
            let mut stmt = tx.prepare(
                "INSERT INTO keymetadata (keyentryid, tag, data)
                 VALUES (?, ?, ?)",
            )?;
            let data = serde_cbor::to_vec(entry)?;
            stmt.execute(params![key_id, tag, data])?;
        }

        tx.commit()?;
        Ok(key_id_guard)
    }

    pub fn load_key_entry(
        &self,
        key: &KeyDescriptor,
        key_id: Option<i64>,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        let key_id = if let Some(id) = key_id {
            id
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id FROM keyentry
                 WHERE domain = ? AND namespace = ? AND alias = ?",
            )?;
            stmt.query_row(params![key.domain as i32, key.namespace, key.alias], |row| {
                row.get::<_, i64>(0)
            })?
        };

        let key_id_guard = KEY_ID_LOCK.get(key_id);

        let mut entry = KeyEntry { id: key_id, ..Default::default() };

        {
            let mut stmt = self.conn.prepare(
                "SELECT blob FROM blobentry
                 WHERE keyentryid = ? AND subcomponent_type = ?
                 ORDER BY id DESC LIMIT 1",
            )?;
            entry.key_blob = stmt
                .query_row(params![key_id, SubComponentType::KeyBlob as i32], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .ok();
        }

        {
            let mut stmt = self.conn.prepare(
                "SELECT blob FROM blobentry
                 WHERE keyentryid = ? AND subcomponent_type = ?
                 ORDER BY id DESC LIMIT 1",
            )?;
            entry.cert = stmt
                .query_row(params![key_id, SubComponentType::Cert as i32], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .ok();
        }

        {
            let mut stmt = self.conn.prepare(
                "SELECT blob FROM blobentry
                 WHERE keyentryid = ? AND subcomponent_type = ?
                 ORDER BY id DESC LIMIT 1",
            )?;
            entry.cert_chain = stmt
                .query_row(params![key_id, SubComponentType::CertChain as i32], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .ok();
        }

        {
            let mut stmt =
                self.conn.prepare("SELECT tag, data FROM keyparameter WHERE keyentryid = ?")?;
            let mut rows = stmt.query(params![key_id])?;
            while let Some(row) = rows.next()? {
                let data: Vec<u8> = row.get(1)?;
                if let Ok(param) = serde_cbor::from_slice::<KeyParameter>(&data) {
                    entry.parameters.push(param);
                }
            }
        }

        {
            let mut stmt =
                self.conn.prepare("SELECT tag, data FROM keymetadata WHERE keyentryid = ?")?;
            let mut rows = stmt.query(params![key_id])?;
            while let Some(row) = rows.next()? {
                let data: Vec<u8> = row.get(1)?;
                match serde_cbor::from_slice::<crate::database::utils::KeyMetaEntry>(&data) {
                    Ok(meta_entry) => {
                        entry.metadata.add(meta_entry);
                    }
                    Err(e) => {
                        log::warn!("Failed to deserialize KeyMetaEntry: {}", e);
                    }
                }
            }
        }

        Ok((key_id_guard, entry))
    }

    pub fn delete_key(&mut self, key_id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM keyentry WHERE id = ?", params![key_id])?;
        tx.execute("DELETE FROM blobentry WHERE keyentryid = ?", params![key_id])?;
        tx.execute("DELETE FROM keyparameter WHERE keyentryid = ?", params![key_id])?;
        tx.execute("DELETE FROM keymetadata WHERE keyentryid = ?", params![key_id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn load_blob_metadata_for_key(&self, key_id: i64) -> Result<BlobMetaData> {
        let mut stmt = self.conn.prepare(
            "SELECT be.id, bm.tag, bm.data FROM blobentry be
             JOIN blobmetadata bm ON be.id = bm.blobentryid
             WHERE be.keyentryid = ? AND be.subcomponent_type = ?
             ORDER BY be.id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![key_id, SubComponentType::KeyBlob as i32])?;
        let mut metadata = BlobMetaData::new();
        while let Some(row) = rows.next()? {
            let _blob_id: i64 = row.get(0)?;
            let _tag: i64 = row.get(1)?;
            let data: Vec<u8> = row.get(2)?;
            match serde_cbor::from_slice::<crate::database::utils::BlobMetaEntry>(&data) {
                Ok(entry) => {
                    metadata.add(entry);
                }
                Err(e) => {
                    log::warn!("Failed to deserialize BlobMetaEntry: {}", e);
                }
            }
        }
        Ok(metadata)
    }

    pub fn cleanup_orphaned_entries(&mut self) -> Result<usize> {
        let tx = self.conn.transaction()?;

        let deleted = tx.execute(
            "DELETE FROM blobentry WHERE keyentryid NOT IN (SELECT id FROM keyentry)",
            [],
        )?;

        let deleted_params = tx.execute(
            "DELETE FROM keyparameter WHERE keyentryid NOT IN (SELECT id FROM keyentry)",
            [],
        )?;

        let deleted_metadata = tx.execute(
            "DELETE FROM keymetadata WHERE keyentryid NOT IN (SELECT id FROM keyentry)",
            [],
        )?;

        let deleted_blob_metadata = tx.execute(
            "DELETE FROM blobmetadata WHERE blobentryid NOT IN (SELECT id FROM blobentry)",
            [],
        )?;

        tx.commit()?;

        Ok(deleted + deleted_params + deleted_metadata + deleted_blob_metadata)
    }

    pub fn vacuum(&mut self) -> Result<()> {
        self.conn.execute("VACUUM", [])?;
        Ok(())
    }
}
