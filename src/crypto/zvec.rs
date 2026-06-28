#![allow(unsafe_code)]

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr::{NonNull, write_volatile};

/// Zeroing vector - mlocked during lifetime, zeroed with write_volatile on drop.
/// Stores a separate `len` field so `reduce_len` can shrink the view without
/// touching the allocation (needed for HKDF where the PRK may be shorter than
/// EVP_MAX_MD_SIZE).
#[derive(Default, Eq, PartialEq)]
pub struct ZVec {
    elems: Box<[u8]>,
    len: usize,
}

impl ZVec {
    pub fn new(size: usize) -> anyhow::Result<Self> {
        let v: Vec<u8> = vec![0; size];
        let b = v.into_boxed_slice();
        if !b.is_empty() {
            try_mlock(&b);
        }
        Ok(Self { elems: b, len: size })
    }

    pub fn reduce_len(&mut self, len: usize) {
        if len <= self.elems.len() {
            self.len = len;
        }
    }

    pub fn try_clone(&self) -> anyhow::Result<Self> {
        let mut result = Self::new(self.len)?;
        result.copy_from_slice(&self[..]);
        Ok(result)
    }

    /// Wraps an existing Vec. Pads to capacity first so into_boxed_slice
    /// can't reallocate and move potentially-sensitive data.
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len();
        let mut v = data;
        v.resize(v.capacity(), 0);
        let b = v.into_boxed_slice();
        if !b.is_empty() {
            try_mlock(&b);
        }
        Self { elems: b, len }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let b = data.to_vec().into_boxed_slice();
        let len = b.len();
        if !b.is_empty() {
            try_mlock(&b);
        }
        Self { elems: b, len }
    }
}

fn try_mlock(b: &[u8]) {
    #[cfg(unix)]
    {
        use std::ffi::c_void;
        let ptr = NonNull::new(b.as_ptr() as *mut c_void)
            .expect("non-null slice pointer");
        if let Err(e) = unsafe { nix::sys::mman::mlock(ptr, b.len()) } {
            log::warn!("mlock failed - key material may be swapped to disk: {e}");
        }
    }
}

impl Drop for ZVec {
    fn drop(&mut self) {
        for i in 0..self.elems.len() {
            unsafe { write_volatile(&mut self.elems[i], 0) };
        }
        if !self.elems.is_empty() {
            #[cfg(unix)]
            {
                use std::ffi::c_void;
                let ptr = NonNull::new(self.elems.as_ptr() as *mut c_void)
                    .expect("non-null slice pointer");
                if let Err(e) = unsafe { nix::sys::mman::munlock(ptr, self.elems.len()) } {
                    log::error!("munlock failed: {e:?}");
                }
            }
        }
    }
}

impl Deref for ZVec {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.elems[0..self.len]
    }
}

impl DerefMut for ZVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.elems[0..self.len]
    }
}

impl AsRef<[u8]> for ZVec {
    fn as_ref(&self) -> &[u8] {
        &self.elems[0..self.len]
    }
}

impl AsMut<[u8]> for ZVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.elems[0..self.len]
    }
}

impl Clone for ZVec {
    fn clone(&self) -> Self {
        Self::from_slice(&self.elems[0..self.len])
    }
}

impl fmt::Debug for ZVec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ZVec(len={}, [redacted])", self.len)
    }
}
