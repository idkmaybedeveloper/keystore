mod zvec;

pub use zvec::ZVec;

use anyhow::Result;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};

pub const GCM_IV_LENGTH: usize = 12;
pub const TAG_LENGTH: usize = 16;
pub const AES_256_KEY_LENGTH: usize = 32;
pub const AES_128_KEY_LENGTH: usize = 16;
pub const SALT_LENGTH: usize = 16;
pub const HMAC_SHA256_LEN: usize = 32;

/// Old keystore versions produced 16-byte IVs with 4 ignored trailing zero bytes.
pub const LEGACY_IV_LENGTH: usize = 16;

pub fn generate_aes256_key() -> Result<ZVec> {
    let mut key = ZVec::new(AES_256_KEY_LENGTH)?;
    rand_bytes(key.as_mut())?;
    Ok(key)
}

pub fn generate_aes128_key() -> Result<ZVec> {
    let mut key = ZVec::new(AES_128_KEY_LENGTH)?;
    rand_bytes(key.as_mut())?;
    Ok(key)
}

pub fn generate_salt() -> Result<Vec<u8>> {
    generate_random_data(SALT_LENGTH)
}

pub fn generate_random_data(size: usize) -> Result<Vec<u8>> {
    let mut data = vec![0; size];
    rand_bytes(&mut data)?;
    Ok(data)
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(msg)?;
    Ok(signer.sign_to_vec()?)
}

pub fn aes_gcm_decrypt(data: &[u8], iv: &[u8], tag: &[u8], key: &[u8]) -> Result<ZVec> {
    let iv = match iv.len() {
        GCM_IV_LENGTH => iv,
        LEGACY_IV_LENGTH => &iv[..GCM_IV_LENGTH],
        _ => anyhow::bail!("invalid IV length: {}", iv.len()),
    };
    if tag.len() != TAG_LENGTH {
        anyhow::bail!("invalid AEAD tag length: {}", tag.len());
    }
    let cipher = match key.len() {
        AES_128_KEY_LENGTH => Cipher::aes_128_gcm(),
        AES_256_KEY_LENGTH => Cipher::aes_256_gcm(),
        _ => anyhow::bail!("invalid key length: {}", key.len()),
    };
    let plaintext = decrypt_aead(cipher, key, Some(iv), &[], data, tag)?;
    Ok(ZVec::from_vec(plaintext))
}

pub fn aes_gcm_encrypt(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut iv = vec![0; GCM_IV_LENGTH];
    rand_bytes(&mut iv)?;
    let cipher = match key.len() {
        AES_128_KEY_LENGTH => Cipher::aes_128_gcm(),
        AES_256_KEY_LENGTH => Cipher::aes_256_gcm(),
        _ => anyhow::bail!("invalid key length: {}", key.len()),
    };
    let mut tag = vec![0; TAG_LENGTH];
    let ciphertext = encrypt_aead(cipher, key, Some(&iv), &[], plaintext, &mut tag)?;
    Ok((ciphertext, iv, tag))
}

pub enum Password<'a> {
    Ref(&'a [u8]),
    Owned(ZVec),
}

impl<'a> From<&'a [u8]> for Password<'a> {
    fn from(pw: &'a [u8]) -> Self {
        Self::Ref(pw)
    }
}

impl<'a> Password<'a> {
    pub fn as_bytes(&'a self) -> &'a [u8] {
        match self {
            Self::Ref(b) => b,
            Self::Owned(z) => z.as_ref(),
        }
    }

    fn get_key(&'a self) -> &'a [u8] {
        self.as_bytes()
    }

    /// Key derivation via PBKDF2-SHA256 (8192 iterations).
    /// Kept for backwards compatibility with old databases.
    pub fn derive_key_pbkdf2(&self, salt: &[u8], out_len: usize) -> Result<ZVec> {
        if salt.len() != SALT_LENGTH {
            anyhow::bail!("invalid salt length: {}", salt.len());
        }
        match out_len {
            AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
            _ => anyhow::bail!("invalid output length: {}", out_len),
        }

        let pw = self.get_key();
        let mut result = ZVec::new(out_len)?;
        openssl::pkcs5::pbkdf2_hmac(pw, salt, 8192, MessageDigest::sha256(), result.as_mut())?;
        Ok(result)
    }

    /// Key derivation via HKDF-SHA256 (RFC 5869).
    /// Preferred for high-entropy synthetic passwords.
    pub fn derive_key_hkdf(&self, salt: &[u8], out_len: usize) -> Result<ZVec> {
        let prk = hkdf_extract(self.get_key(), salt)?;
        hkdf_expand(out_len, &prk, &[])
    }
}

/// HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM) → PRK.
pub fn hkdf_extract(secret: &[u8], salt: &[u8]) -> Result<ZVec> {
    let pkey = PKey::hmac(salt)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(secret)?;
    Ok(ZVec::from_vec(signer.sign_to_vec()?))
}

/// HKDF-Expand(PRK, info, L) using HMAC-SHA256.
pub fn hkdf_expand(out_len: usize, prk: &[u8], info: &[u8]) -> Result<ZVec> {
    const HASH_LEN: usize = 32; // SHA-256
    let n = out_len.div_ceil(HASH_LEN);

    let pkey = PKey::hmac(prk)?;
    let mut out = ZVec::new(out_len)?;
    let mut prev: Vec<u8> = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        if !prev.is_empty() {
            signer.update(&prev)?;
        }
        signer.update(info)?;
        signer.update(&[i as u8])?;
        let t = signer.sign_to_vec()?;

        let copy_len = std::cmp::min(HASH_LEN, out_len - offset);
        out.as_mut()[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
        offset += copy_len;
        prev = t;
    }

    Ok(out)
}
