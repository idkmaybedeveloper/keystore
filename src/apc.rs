use crate::error::Error;
use anyhow::Result;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApcError {
    #[error("ApcError::Rc({0:?})")]
    Rc(i32),
    #[error("ApcError::System")]
    System,
}

pub struct ApcService;

impl ApcService {
    pub fn new() -> Self {
        Self
    }

    pub fn present_confirmation_prompt(
        &self,
        _prompt_text: &str,
        _extra_data: &[u8],
    ) -> Result<()> {
        Err(Error::Rc(crate::error::ResponseCode::Unimplemented).into())
    }
}
