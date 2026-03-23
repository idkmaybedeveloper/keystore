use crate::database::KeystoreDB;
use crate::error::Error;
use anyhow::Result;
use log::info;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdRotationState {
    NotStarted,
    InProgress,
    Completed,
}

pub struct IdRotation {
    state: Mutex<IdRotationState>,
}

impl IdRotation {
    pub fn new(_db: Arc<Mutex<KeystoreDB>>) -> Self {
        Self { state: Mutex::new(IdRotationState::NotStarted) }
    }

    pub fn state(&self) -> IdRotationState {
        *self.state.lock().unwrap()
    }

    pub fn start_rotation(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if *state != IdRotationState::NotStarted {
            return Err(Error::sys().into());
        }
        *state = IdRotationState::InProgress;
        info!("ID rotation started");
        Ok(())
    }

    pub fn complete_rotation(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if *state != IdRotationState::InProgress {
            return Err(Error::sys().into());
        }
        *state = IdRotationState::Completed;
        info!("ID rotation completed");
        Ok(())
    }

    pub fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        *state = IdRotationState::NotStarted;
    }
}
