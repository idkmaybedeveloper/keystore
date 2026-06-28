use crate::crypto::{Password, ZVec};
use crate::database::utils::EncryptedBy;
use crate::database::{
    BlobMetaData, BlobMetaEntry, KEYSTORE_UUID, KeyDescriptor, KeyMetaData, KeyMetaEntry, KeyType,
    KeystoreDB,
};
use crate::error::{Error, ResponseCode};
use crate::key_parameter::KeyParameter;
use crate::operation::{Operation, OperationDb};
use crate::super_key::{SuperKey, SuperKeyManager, USER_SUPER_KEY};
use anyhow::Result;
use log::error;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct Keystore {
    db: Arc<Mutex<KeystoreDB>>,
    super_key_manager: Arc<Mutex<SuperKeyManager>>,
    operation_db: Arc<OperationDb>,
    password: ZVec,
}

#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: i64,
    pub parameters: Vec<KeyParameter>,
}

impl Keystore {
    pub fn new<P: AsRef<Path>>(db_path: P, password: &[u8]) -> Result<Self> {
        let db = KeystoreDB::new(db_path.as_ref())?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            super_key_manager: Arc::new(Mutex::new(SuperKeyManager::new())),
            operation_db: Arc::new(OperationDb::new()),
            password: ZVec::from_slice(password),
        })
    }

    pub fn create_operation(&self, key_id: i64) -> Arc<Operation> {
        let operation = Arc::new(Operation::new(key_id));
        self.operation_db.add_operation(&operation);
        operation
    }

    pub fn operation_db(&self) -> &Arc<OperationDb> {
        &self.operation_db
    }

    pub fn generate_key(
        &self,
        alias: &str,
        namespace: i64,
        params: Vec<KeyParameter>,
        key_blob: Vec<u8>,
    ) -> Result<KeyMetadata> {
        let key = KeyDescriptor {
            domain: crate::database::Domain::App,
            namespace,
            alias: Some(alias.to_string()),
        };

        let mut db = self.db.lock().unwrap();
        let super_key = self.get_super_key(&mut db, 0)?;

        let (encrypted_blob, iv, tag) = super_key.encrypt(&key_blob)?;

        let mut blob_metadata = BlobMetaData::new();
        blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(match super_key.id {
            crate::super_key::SuperKeyIdentifier::DatabaseId(id) => id,
        })));
        blob_metadata.add(BlobMetaEntry::Iv(iv));
        blob_metadata.add(BlobMetaEntry::AeadTag(tag));

        let mut key_metadata = KeyMetaData::new();
        key_metadata
            .add(KeyMetaEntry::CreationDate(crate::database::DateTime::now()?.to_millis_epoch()));

        let key_id_guard = db.store_new_key(
            &key,
            KeyType::Client,
            &params,
            &encrypted_blob,
            &blob_metadata,
            &key_metadata,
            &KEYSTORE_UUID,
        )?;

        Ok(KeyMetadata { key_id: key_id_guard.id(), parameters: params })
    }

    pub fn get_key(&self, alias: &str, namespace: i64) -> Result<Vec<u8>> {
        let key = KeyDescriptor {
            domain: crate::database::Domain::App,
            namespace,
            alias: Some(alias.to_string()),
        };

        let mut db = self.db.lock().unwrap();
        let (_guard, mut entry) = db.load_key_entry(&key, None)?;

        let key_id = entry.id();
        let encrypted_blob = entry.take_key_blob().ok_or(Error::Rc(ResponseCode::KeyNotFound))?;

        let super_key = self.get_super_key(&mut db, 0)?;

        let blob_meta = db.load_blob_metadata_for_key(key_id)?;
        let iv = blob_meta.iv().ok_or_else(|| {
            error!("IV not found in blob metadata");
            Error::Rc(ResponseCode::ValueCorrupted)
        })?;
        let tag = blob_meta.aead_tag().ok_or_else(|| {
            error!("AEAD tag not found in blob metadata");
            Error::Rc(ResponseCode::ValueCorrupted)
        })?;

        let decrypted = super_key.decrypt(&encrypted_blob, iv, tag)?;
        Ok(decrypted.as_ref().to_vec())
    }

    pub fn delete_key(&self, alias: &str, namespace: i64) -> Result<()> {
        let key = KeyDescriptor {
            domain: crate::database::Domain::App,
            namespace,
            alias: Some(alias.to_string()),
        };

        let mut db = self.db.lock().unwrap();
        let (_guard, entry) = db.load_key_entry(&key, None)?;
        db.delete_key(entry.id())?;
        Ok(())
    }

    fn get_super_key(&self, db: &mut KeystoreDB, user_id: u32) -> Result<Arc<SuperKey>> {
        let password = Password::Ref(self.password.as_ref());
        let mut manager = self.super_key_manager.lock().unwrap();
        manager.get_or_create_super_key(db, user_id, &USER_SUPER_KEY, password)
    }
}
