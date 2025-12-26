use crate::crypto::{Password, ZVec, aes_gcm_decrypt, aes_gcm_encrypt, generate_aes256_key};
use crate::database::utils::EncryptedBy;
use crate::database::{
    BlobMetaData, BlobMetaEntry, KEYSTORE_UUID, KeyDescriptor, KeyMetaData, KeyMetaEntry, KeyType,
    KeystoreDB,
};
use anyhow::{Context, Result};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperEncryptionAlgorithm {
    Aes256Gcm,
}

pub struct SuperKeyType<'a> {
    pub alias: &'a str,
    pub algorithm: SuperEncryptionAlgorithm,
    pub name: &'a str,
}

pub const USER_SUPER_KEY: SuperKeyType = SuperKeyType {
    alias: "USER_SUPER_KEY",
    algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
    name: "User super key",
};

#[derive(Debug, Clone, Copy)]
pub enum SuperEncryptionType {
    None,
    AfterFirstUnlock,
}

#[derive(Debug, Clone, Copy)]
pub enum SuperKeyIdentifier {
    DatabaseId(i64),
}

pub struct SuperKey {
    algorithm: SuperEncryptionAlgorithm,
    key: ZVec,
    pub id: SuperKeyIdentifier,
}

impl SuperKey {
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        match self.algorithm {
            SuperEncryptionAlgorithm::Aes256Gcm => {
                aes_gcm_encrypt(plaintext, &self.key).context("Encryption failed")
            }
        }
    }

    pub fn decrypt(&self, data: &[u8], iv: &[u8], tag: &[u8]) -> Result<ZVec> {
        match self.algorithm {
            SuperEncryptionAlgorithm::Aes256Gcm => {
                aes_gcm_decrypt(data, iv, tag, &self.key).context("Decryption failed")
            }
        }
    }
}

pub struct SuperKeyManager {
    keys: std::collections::HashMap<(u32, String), Arc<SuperKey>>,
}

impl SuperKeyManager {
    pub fn new() -> Self {
        Self { keys: std::collections::HashMap::new() }
    }

    pub fn get_or_create_super_key(
        &mut self,
        db: &mut KeystoreDB,
        user_id: u32,
        key_type: &SuperKeyType,
        password: Password,
    ) -> Result<Arc<SuperKey>> {
        let cache_key = (user_id, key_type.alias.to_string());
        if let Some(cached) = self.keys.get(&cache_key) {
            return Ok(cached.clone());
        }

        let key = KeyDescriptor {
            domain: crate::database::Domain::App,
            namespace: user_id as i64,
            alias: Some(key_type.alias.to_string()),
        };

        if let Ok((_guard, mut entry)) = db.load_key_entry(&key, None) {
            if let Some(blob) = entry.take_key_blob() {
                let metadata = entry.metadata();
                let salt = metadata
                    .iter()
                    .find(|(_, e)| matches!(e, KeyMetaEntry::Sec1PublicKey(_)))
                    .map(|(_, e)| {
                        if let KeyMetaEntry::Sec1PublicKey(salt) = e {
                            salt.clone()
                        } else {
                            vec![]
                        }
                    })
                    .unwrap_or_default();

                let blob_metadata = db.load_blob_metadata_for_key(entry.id())?;
                let iv = blob_metadata.iv().cloned();
                let tag = blob_metadata.aead_tag().cloned();

                if let (Some(iv), Some(tag)) = (iv, tag) {
                    let derived_key = password.derive_key_hkdf(&salt, 32)?;
                    let decrypted = aes_gcm_decrypt(&blob, &iv, &tag, &derived_key.as_ref())?;
                    let super_key = Arc::new(SuperKey {
                        algorithm: key_type.algorithm,
                        key: decrypted,
                        id: SuperKeyIdentifier::DatabaseId(entry.id()),
                    });
                    self.keys.insert(cache_key, super_key.clone());
                    return Ok(super_key);
                }
            }
        }

        let super_key = Self::create_super_key(db, user_id, key_type, password)?;
        self.keys.insert(cache_key, super_key.clone());
        Ok(super_key)
    }

    fn create_super_key(
        db: &mut KeystoreDB,
        user_id: u32,
        key_type: &SuperKeyType,
        password: Password,
    ) -> Result<Arc<SuperKey>> {
        let super_key = generate_aes256_key().context("Failed to generate AES-256 key")?;

        let salt = crate::crypto::generate_salt()?;
        let derived_key = password.derive_key_hkdf(&salt, 32)?;

        let (encrypted_super_key, iv, tag) =
            aes_gcm_encrypt(&super_key.as_ref(), &derived_key).context("Failed to encrypt")?;

        let salt_clone = salt.clone();
        let mut blob_metadata = BlobMetaData::new();
        blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
        blob_metadata.add(BlobMetaEntry::Salt(salt));
        blob_metadata.add(BlobMetaEntry::Iv(iv));
        blob_metadata.add(BlobMetaEntry::AeadTag(tag));

        let mut key_metadata = KeyMetaData::new();
        key_metadata.add(KeyMetaEntry::Sec1PublicKey(salt_clone));

        let key = KeyDescriptor {
            domain: crate::database::Domain::App,
            namespace: user_id as i64,
            alias: Some(key_type.alias.to_string()),
        };

        let key_id_guard = db.store_new_key(
            &key,
            KeyType::Super,
            &[],
            &encrypted_super_key,
            &blob_metadata,
            &key_metadata,
            &KEYSTORE_UUID,
        )?;

        Ok(Arc::new(SuperKey {
            algorithm: key_type.algorithm,
            key: super_key,
            id: SuperKeyIdentifier::DatabaseId(key_id_guard.id()),
        }))
    }
}
