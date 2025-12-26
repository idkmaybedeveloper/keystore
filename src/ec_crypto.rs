use crate::crypto::{
    AES_256_KEY_LENGTH, ZVec, aes_gcm_decrypt, aes_gcm_encrypt, generate_salt, hkdf_expand,
    hkdf_extract,
};
use anyhow::{Context, Result};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};

pub struct ECDHPrivateKey {
    key: EcKey<Private>,
}

impl ECDHPrivateKey {
    pub fn generate() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let key = EcKey::generate(&group)?;
        Ok(Self { key })
    }

    pub fn from_private_key(buf: &[u8]) -> Result<Self> {
        let key = EcKey::private_key_from_der(buf)?;
        Ok(Self { key })
    }

    pub fn private_key(&self) -> Result<ZVec> {
        let der = self.key.private_key_to_der()?;
        Ok(ZVec::from_vec(der))
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        let point = self.key.public_key();
        let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let bytes =
            point.to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        Ok(bytes)
    }

    fn agree_key(
        &self,
        salt: &[u8],
        other_public_key: &[u8],
        sender_public_key: &[u8],
        recipient_public_key: &[u8],
    ) -> Result<ZVec> {
        let hkdf = hkdf_extract(sender_public_key, salt)
            .context("hkdf_extract on sender_public_key failed")?;
        let hkdf = hkdf_extract(recipient_public_key, &hkdf)
            .context("hkdf_extract on recipient_public_key failed")?;

        let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let other_point = EcPoint::from_bytes(&group, other_public_key, &mut ctx)?;
        let other_key = EcKey::from_public_key(&group, &other_point)?;

        let pkey_self = PKey::from_ec_key(self.key.clone())?;
        let pkey_other = PKey::from_ec_key(other_key)?;

        let mut deriver = openssl::derive::Deriver::new(&pkey_self)?;
        deriver.set_peer(&pkey_other)?;
        let mut secret = vec![0; 66];
        let secret_len = deriver.derive(&mut secret)?;
        secret.truncate(secret_len);

        let prk = hkdf_extract(&secret, &hkdf).context("hkdf_extract on secret failed")?;

        let aes_key = hkdf_expand(AES_256_KEY_LENGTH, &prk, b"AES-256-GCM key")
            .context("hkdf_expand failed")?;
        Ok(aes_key)
    }

    pub fn encrypt_message(
        recipient_public_key: &[u8],
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let sender_key = Self::generate().context("generate failed")?;
        let sender_public_key = sender_key.public_key().context("public_key failed")?;
        let salt = generate_salt().context("generate_salt failed")?;
        let aes_key = sender_key
            .agree_key(&salt, recipient_public_key, &sender_public_key, recipient_public_key)
            .context("agree_key failed")?;
        let (ciphertext, iv, tag) =
            aes_gcm_encrypt(message, &aes_key).context("aes_gcm_encrypt failed")?;
        Ok((sender_public_key, salt, iv, ciphertext, tag))
    }

    pub fn decrypt_message(
        &self,
        sender_public_key: &[u8],
        salt: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<ZVec> {
        let recipient_public_key = self.public_key()?;
        let aes_key = self
            .agree_key(salt, sender_public_key, sender_public_key, &recipient_public_key)
            .context("agree_key failed")?;
        aes_gcm_decrypt(ciphertext, iv, tag, &aes_key).context("aes_gcm_decrypt failed")
    }
}
