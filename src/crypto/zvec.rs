use anyhow::Result;
use std::ops::{Deref, DerefMut};

pub struct ZVec {
    data: Vec<u8>,
}

impl ZVec {
    pub fn new(capacity: usize) -> Result<Self> {
        Ok(Self { data: vec![0; capacity] })
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self { data: data.to_vec() }
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn reduce_len(&mut self, new_len: usize) {
        if new_len < self.data.len() {
            self.data.truncate(new_len);
        }
    }
}

impl AsMut<[u8]> for ZVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for ZVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for ZVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl AsRef<[u8]> for ZVec {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for ZVec {
    fn drop(&mut self) {
        self.data.fill(0);
    }
}

impl PartialEq for ZVec {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Clone for ZVec {
    fn clone(&self) -> Self {
        Self { data: self.data.clone() }
    }
}
