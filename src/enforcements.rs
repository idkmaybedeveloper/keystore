use crate::authorization::AuthTokenEntry;
use crate::error::{Error, ResponseCode};
use crate::key_parameter::KeyParameter;
use anyhow::Result;
use std::collections::HashSet;
use std::time::{Duration, SystemTime};

pub struct Enforcements {
    max_auth_token_age: Duration,
}

impl Enforcements {
    pub fn new() -> Self {
        Self { max_auth_token_age: Duration::from_secs(300) }
    }

    pub fn with_max_auth_token_age(max_age: Duration) -> Self {
        Self { max_auth_token_age: max_age }
    }

    pub fn check_auth_token_age(&self, entry: &AuthTokenEntry) -> Result<()> {
        let age = SystemTime::now()
            .duration_since(entry.time_received)
            .map_err(|_| Error::Rc(ResponseCode::SystemError))?;

        if age > self.max_auth_token_age {
            return Err(Error::Rc(ResponseCode::Locked).into());
        }

        Ok(())
    }

    pub fn check_key_parameters(
        &self,
        params: &[KeyParameter],
        required_tags: &HashSet<u32>,
    ) -> Result<()> {
        let present_tags: HashSet<u32> = params.iter().map(|p| p.tag as u32).collect();

        for required in required_tags {
            if !present_tags.contains(required) {
                return Err(Error::Rc(ResponseCode::InvalidArgument).into());
            }
        }

        Ok(())
    }

    pub fn max_auth_token_age(&self) -> Duration {
        self.max_auth_token_age
    }
}

impl Default for Enforcements {
    fn default() -> Self {
        Self::new()
    }
}
