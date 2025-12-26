use crate::database::{BlobMetaData, KeyDescriptor, KeystoreDB};
use anyhow::Result;

pub enum AttestationKeyInfo {
    RkpdProvisioned {
        attestation_key: Vec<u8>,
        attestation_certs: Vec<u8>,
    },
    UserGenerated {
        key_id: u64,
        blob: Vec<u8>,
        blob_metadata: BlobMetaData,
        issuer_subject: Vec<u8>,
    },
}

pub fn get_attest_key_info(
    _key: &KeyDescriptor,
    _caller_uid: u32,
    _attest_key_descriptor: Option<&KeyDescriptor>,
    _params: &[crate::key_parameter::KeyParameter],
    _rem_prov_state: &crate::remote_provisioning::RemProvState,
    _db: &mut KeystoreDB,
) -> Result<Option<AttestationKeyInfo>> {
    Ok(None)
}
