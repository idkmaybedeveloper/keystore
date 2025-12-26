use crate::error::{Error, ResponseCode};
use crate::key_parameter::KeyParameter;
use anyhow::Result;

pub struct SoftwareKeyBlob {
    key_material: Vec<u8>,
    characteristics: Vec<KeyParameter>,
}

impl SoftwareKeyBlob {
    pub fn new(key_material: Vec<u8>, characteristics: Vec<KeyParameter>) -> Self {
        Self { key_material, characteristics }
    }

    pub fn key_material(&self) -> &[u8] {
        &self.key_material
    }

    pub fn characteristics(&self) -> &[KeyParameter] {
        &self.characteristics
    }
}

pub fn export_key(
    _data: &[u8],
    _params: &[KeyParameter],
) -> Result<(u32, Vec<u8>, Vec<KeyParameter>)> {
    Err(Error::Rc(ResponseCode::Unimplemented).into())
}
