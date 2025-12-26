use crate::crypto::{Password, aes_gcm_decrypt};
use crate::error::{Error, ResponseCode};
use anyhow::{Context, Result};

pub struct LegacyBlob {
    data: Vec<u8>,
    iv: Vec<u8>,
    tag: Vec<u8>,
}

impl LegacyBlob {
    pub fn from_encrypted(data: Vec<u8>, iv: Vec<u8>, tag: Vec<u8>) -> Self {
        Self { data, iv, tag }
    }

    pub fn decrypt(&self, password: Password) -> Result<Vec<u8>> {
        let salt = vec![0u8; 16];
        let key =
            password.derive_key_hkdf(&salt, 32).context("Failed to derive key from password")?;

        aes_gcm_decrypt(&self.data, &self.iv, &self.tag, &key)
            .map(|zvec| zvec.as_ref().to_vec())
            .context("Failed to decrypt legacy blob")
    }

    pub fn is_encrypted(&self) -> bool {
        !self.data.is_empty()
    }
}

pub struct LegacyBlobLoader;

impl LegacyBlobLoader {
    pub fn new() -> Self {
        Self
    }

    pub fn load_blob(&self, _path: &std::path::Path) -> Result<LegacyBlob> {
        Err(Error::Rc(ResponseCode::Unimplemented).into())
    }
}

impl Default for LegacyBlobLoader {
    fn default() -> Self {
        Self::new()
    }
}
