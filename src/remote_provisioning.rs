use crate::database::KeyDescriptor;
use crate::security_level::SecurityLevel;
use anyhow::Result;

#[derive(Default)]
pub struct RemProvState {}

impl RemProvState {
    pub fn new(_security_level: SecurityLevel) -> Self {
        Self {}
    }

    pub fn get_rkpd_attestation_key_and_certs(
        &self,
        _key: &KeyDescriptor,
        _caller_uid: u32,
        _params: &[crate::key_parameter::KeyParameter],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(None)
    }
}
