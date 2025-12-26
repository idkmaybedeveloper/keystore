use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyMetaData {
    data: HashMap<i64, KeyMetaEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyMetaEntry {
    CreationDate(i64),
    Sec1PublicKey(Vec<u8>),
    Iv(Vec<u8>),
    AeadTag(Vec<u8>),
}

impl KeyMetaData {
    pub fn new() -> Self {
        Self { data: HashMap::new() }
    }

    pub fn add(&mut self, entry: KeyMetaEntry) {
        let tag = match &entry {
            KeyMetaEntry::CreationDate(_) => 0,
            KeyMetaEntry::Sec1PublicKey(_) => 1,
            KeyMetaEntry::Iv(_) => 2,
            KeyMetaEntry::AeadTag(_) => 3,
        };
        self.data.insert(tag, entry);
    }

    pub fn get_iv(&self) -> Option<&Vec<u8>> {
        self.data.get(&2).and_then(|e| if let KeyMetaEntry::Iv(iv) = e { Some(iv) } else { None })
    }

    pub fn get_aead_tag(&self) -> Option<&Vec<u8>> {
        self.data
            .get(&3)
            .and_then(|e| if let KeyMetaEntry::AeadTag(tag) = e { Some(tag) } else { None })
    }

    pub fn get_creation_date(&self) -> Option<i64> {
        self.data
            .get(&0)
            .and_then(|e| if let KeyMetaEntry::CreationDate(date) = e { Some(*date) } else { None })
    }

    pub fn iter(&self) -> impl Iterator<Item = (i64, &KeyMetaEntry)> {
        self.data.iter().map(|(k, v)| (*k, v))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlobMetaData {
    data: HashMap<i64, BlobMetaEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobMetaEntry {
    EncryptedBy(EncryptedBy),
    Salt(Vec<u8>),
    Iv(Vec<u8>),
    AeadTag(Vec<u8>),
    KmUuid([u8; 16]),
    PublicKey(Vec<u8>),
    MaxBootLevel(i32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptedBy {
    Password,
    KeyId(i64),
}

impl BlobMetaData {
    pub fn new() -> Self {
        Self { data: HashMap::new() }
    }

    pub fn add(&mut self, entry: BlobMetaEntry) {
        let tag = match &entry {
            BlobMetaEntry::EncryptedBy(_) => 0,
            BlobMetaEntry::Salt(_) => 1,
            BlobMetaEntry::Iv(_) => 2,
            BlobMetaEntry::AeadTag(_) => 3,
            BlobMetaEntry::KmUuid(_) => 4,
            BlobMetaEntry::PublicKey(_) => 5,
            BlobMetaEntry::MaxBootLevel(_) => 6,
        };
        self.data.insert(tag, entry);
    }

    pub fn iter(&self) -> impl Iterator<Item = (i64, &BlobMetaEntry)> {
        self.data.iter().map(|(k, v)| (*k, v))
    }

    pub fn encrypted_by(&self) -> Option<&EncryptedBy> {
        self.data
            .get(&0)
            .and_then(|e| if let BlobMetaEntry::EncryptedBy(eb) = e { Some(eb) } else { None })
    }

    pub fn iv(&self) -> Option<&Vec<u8>> {
        self.data.get(&2).and_then(|e| if let BlobMetaEntry::Iv(iv) = e { Some(iv) } else { None })
    }

    pub fn aead_tag(&self) -> Option<&Vec<u8>> {
        self.data
            .get(&3)
            .and_then(|e| if let BlobMetaEntry::AeadTag(tag) = e { Some(tag) } else { None })
    }
}
