use crate::error::Error;
use anyhow::Result;

pub fn perform_shared_secret_negotiation() {
    log::info!("Shared secret negotiation not implemented in standalone mode");
}

pub struct SharedSecretNegotiation;

impl SharedSecretNegotiation {
    pub fn new() -> Self {
        Self
    }

    pub fn negotiate(&self) -> Result<Vec<u8>> {
        Err(Error::Rc(crate::error::ResponseCode::Unimplemented).into())
    }
}
