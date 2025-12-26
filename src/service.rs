use crate::database::{Domain, KeyDescriptor, KeystoreDB};
use crate::error::{Error, ResponseCode};
use crate::key_parameter::KeyParameter;
use crate::security_level::SecurityLevel;
use anyhow::{Context, Result};
use rusqlite::params;
use std::sync::{Arc, Mutex};

pub struct KeystoreService {
    db: Arc<Mutex<KeystoreDB>>,
}

impl KeystoreService {
    pub fn new(db: Arc<Mutex<KeystoreDB>>) -> Result<Self> {
        Ok(Self { db })
    }

    pub fn get_key_entry(&self, key: &KeyDescriptor, caller_uid: u32) -> Result<KeyEntryResponse> {
        let db = self.db.lock().unwrap();
        let (_guard, mut entry) =
            db.load_key_entry(key, None).context("Failed to load key entry")?;

        if let Domain::App = key.domain {
            if caller_uid as i64 != key.namespace {
                return Err(Error::Rc(ResponseCode::PermissionDenied))
                    .context("Caller does not own this key");
            }
        }

        let key_id = entry.id();
        let alias = key.alias.clone();
        let key_descriptor =
            KeyDescriptor { domain: Domain::KeyId, namespace: key_id, alias: alias.clone() };

        let modification_time = entry.metadata().get_creation_date().unwrap_or(0);
        let cert = entry.take_cert();
        let cert_chain = entry.take_cert_chain();
        let authorizations = entry.into_key_parameters();

        Ok(KeyEntryResponse {
            key: KeyDescriptor { domain: Domain::KeyId, namespace: key_id, alias },
            metadata: KeyMetadata {
                key: key_descriptor,
                key_security_level: SecurityLevel::Software,
                certificate: cert,
                certificate_chain: cert_chain,
                modification_time_ms: modification_time,
                authorizations,
            },
        })
    }

    pub fn list_entries(
        &self,
        domain: i32,
        namespace: i64,
        caller_uid: u32,
    ) -> Result<Vec<KeyEntryResponse>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .conn
            .prepare("SELECT id, alias FROM keyentry WHERE domain = ? AND namespace = ?")
            .context("Failed to prepare statement")?;

        let domain_enum = match domain {
            0 => Domain::App,
            1 => Domain::Selinux,
            2 => Domain::KeyId,
            _ => return Err(Error::Rc(ResponseCode::InvalidArgument).into()),
        };

        if let Domain::App = domain_enum {
            if caller_uid as i64 != namespace {
                return Err(anyhow::anyhow!("Caller cannot list keys in this namespace")
                    .context(Error::Rc(ResponseCode::PermissionDenied)));
            }
        }

        let mut results = Vec::new();
        let rows = stmt.query_map(params![domain, namespace], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })?;

        for row in rows {
            let (key_id, alias) = row?;
            let key_desc = KeyDescriptor { domain: Domain::KeyId, namespace: key_id, alias };
            match self.get_key_entry(&key_desc, caller_uid) {
                Ok(entry) => results.push(entry),
                Err(_) => continue,
            }
        }

        Ok(results)
    }
}

pub struct KeyEntryResponse {
    pub key: KeyDescriptor,
    pub metadata: KeyMetadata,
}

pub struct KeyMetadata {
    pub key: KeyDescriptor,
    pub key_security_level: SecurityLevel,
    pub certificate: Option<Vec<u8>>,
    pub certificate_chain: Option<Vec<u8>>,
    pub modification_time_ms: i64,
    pub authorizations: Vec<KeyParameter>,
}
