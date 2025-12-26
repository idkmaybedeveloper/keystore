mod zvec;

pub use zvec::ZVec;

use anyhow::Result;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};

pub const GCM_IV_LENGTH: usize = 12;
pub const TAG_LENGTH: usize = 16;
pub const AES_256_KEY_LENGTH: usize = 32;
pub const AES_128_KEY_LENGTH: usize = 16;
pub const SALT_LENGTH: usize = 16;
pub const HMAC_SHA256_LEN: usize = 32;

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
    let mut salt = vec![0; SALT_LENGTH];
    rand_bytes(&mut salt)?;
    Ok(salt)
}

pub fn generate_random_data(size: usize) -> Result<Vec<u8>> {
    let mut data = vec![0; size];
    rand_bytes(&mut data)?;
    Ok(data)
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(msg)?;
    Ok(signer.sign_to_vec()?)
}

pub fn aes_gcm_decrypt(data: &[u8], iv: &[u8], tag: &[u8], key: &[u8]) -> Result<ZVec> {
    if iv.len() != GCM_IV_LENGTH {
        anyhow::bail!("Invalid IV length");
    }
    if tag.len() != TAG_LENGTH {
        anyhow::bail!("Invalid tag length");
    }

    let cipher = match key.len() {
        AES_128_KEY_LENGTH => Cipher::aes_128_gcm(),
        AES_256_KEY_LENGTH => Cipher::aes_256_gcm(),
        _ => anyhow::bail!("Invalid key length"),
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
        _ => anyhow::bail!("Invalid key length"),
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
    fn get_key(&'a self) -> &'a [u8] {
        match self {
            Self::Ref(b) => b,
            Self::Owned(z) => z.as_ref(),
        }
    }

    pub fn derive_key_pbkdf2(&self, salt: &[u8], out_len: usize) -> Result<ZVec> {
        if salt.len() != SALT_LENGTH {
            anyhow::bail!("Invalid salt length");
        }
        match out_len {
            AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
            _ => anyhow::bail!("Invalid key length"),
        }

        use openssl::pkcs5::pbkdf2_hmac;
        let pw = self.get_key();
        let mut result = ZVec::new(out_len)?;
        pbkdf2_hmac(pw, salt, 8192, openssl::hash::MessageDigest::sha256(), result.as_mut())?;
        Ok(result)
    }

    pub fn derive_key_hkdf(&self, salt: &[u8], out_len: usize) -> Result<ZVec> {
        use openssl::pkcs5::pbkdf2_hmac;
        let mut prk = vec![0; 32];
        pbkdf2_hmac(self.get_key(), salt, 1, openssl::hash::MessageDigest::sha256(), &mut prk)?;

        let mut out = vec![0; out_len];
        let info = [];
        hkdf_expand_internal(out_len, &prk, &info, &mut out)?;
        Ok(ZVec::from_vec(out))
    }
}

fn hkdf_expand_internal(out_len: usize, _prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    use openssl::hash::{MessageDigest, hash};

    let hash_len = MessageDigest::sha256().size();
    let n = (out_len + hash_len - 1) / hash_len;

    let mut offset = 0;
    for i in 1..=n {
        let mut input = Vec::new();
        if i > 1 {
            input.extend_from_slice(&out[offset - hash_len..offset]);
        }
        input.extend_from_slice(info);
        input.push(i as u8);

        let t = hash(MessageDigest::sha256(), &input)?;
        let copy_len = std::cmp::min(hash_len, out_len - offset);
        out[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
        offset += copy_len;
    }

    Ok(())
}

pub fn hkdf_extract(secret: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    let pkey = PKey::hmac(salt)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(secret)?;
    Ok(signer.sign_to_vec()?)
}

pub fn hkdf_expand(out_len: usize, _prk: &[u8], info: &[u8]) -> Result<ZVec> {
    use openssl::hash::{MessageDigest, hash};

    let hash_len = MessageDigest::sha256().size();
    let n = (out_len + hash_len - 1) / hash_len;

    let mut out = ZVec::new(out_len)?;
    let mut offset = 0;

    for i in 1..=n {
        let mut input = Vec::new();
        if i > 1 {
            input.extend_from_slice(&out.as_ref()[offset - hash_len..offset]);
        }
        input.extend_from_slice(info);
        input.push(i as u8);

        let t = hash(MessageDigest::sha256(), &input)?;
        let copy_len = std::cmp::min(hash_len, out_len - offset);
        out.as_mut()[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
        offset += copy_len;
    }

    Ok(out)
}
