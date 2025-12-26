use crate::crypto::{generate_aes128_key, generate_aes256_key};
use crate::database::Uuid;
use crate::ec_crypto::ECDHPrivateKey;
use crate::error::{Error, ResponseCode};
use crate::key_parameter::{KeyParameter, KeyParameterValue, Tag};
use crate::security_level::SecurityLevel;
use anyhow::{Context, Result};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

pub struct KeyMintDevice {
    security_level: SecurityLevel,
    uuid: Uuid,
    version: i32,
}

impl KeyMintDevice {
    pub const KEY_MASTER_V4_0: i32 = 40;
    pub const KEY_MASTER_V4_1: i32 = 41;
    pub const KEY_MINT_V1: i32 = 100;
    pub const KEY_MINT_V2: i32 = 200;
    pub const KEY_MINT_V3: i32 = 300;

    pub fn get(security_level: SecurityLevel) -> Result<KeyMintDevice> {
        Ok(KeyMintDevice { security_level, uuid: Uuid::default(), version: Self::KEY_MINT_V1 })
    }

    pub fn get_or_none(security_level: SecurityLevel) -> Result<Option<KeyMintDevice>> {
        Ok(Some(Self::get(security_level)?))
    }

    pub fn version(&self) -> i32 {
        self.version
    }

    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn generate_key(&self, params: &[KeyParameter]) -> Result<(Vec<u8>, Vec<KeyParameter>)> {
        let algorithm = params
            .iter()
            .find(|p| p.tag == Tag::Algorithm)
            .and_then(|p| match &p.value {
                KeyParameterValue::Algorithm(a) => Some(*a),
                _ => None,
            })
            .ok_or_else(|| Error::Rc(ResponseCode::InvalidArgument))
            .context("Algorithm parameter required")?;

        let key_size = params
            .iter()
            .find(|p| p.tag == Tag::KeySize)
            .and_then(|p| match &p.value {
                KeyParameterValue::KeySize(s) => Some(*s),
                _ => None,
            })
            .unwrap_or(256);

        let key_material = match algorithm {
            1 => {
                if key_size == 128 {
                    generate_aes128_key()?.as_ref().to_vec()
                } else if key_size == 256 {
                    generate_aes256_key()?.as_ref().to_vec()
                } else {
                    anyhow::bail!("Unsupported AES key size: {}", key_size);
                }
            }
            2 => {
                let rsa = Rsa::generate(key_size as u32).context("Failed to generate RSA key")?;
                let pkey = PKey::from_rsa(rsa)?;
                pkey.private_key_to_der().context("Failed to serialize RSA key")?
            }
            3 => {
                let ec_key = ECDHPrivateKey::generate().context("Failed to generate EC key")?;
                ec_key.private_key()?.as_ref().to_vec()
            }
            _ => {
                anyhow::bail!("Unsupported algorithm: {}", algorithm);
            }
        };

        let mut characteristics = params.to_vec();
        characteristics
            .push(KeyParameter { tag: Tag::KeySize, value: KeyParameterValue::KeySize(key_size) });

        Ok((key_material, characteristics))
    }
}
