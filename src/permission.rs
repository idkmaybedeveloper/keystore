use crate::database::{Domain, KeyDescriptor};
use crate::error::{Error, ResponseCode};
use anyhow::Context;
use std::ffi::CStr;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPerm {
    ConvertStorageKeyToEphemeral = 1,
    Delete = 2,
    GenUniqueId = 4,
    GetInfo = 8,
    Grant = 16,
    ManageBlob = 32,
    Rebind = 64,
    ReqForcedOp = 128,
    Update = 256,
    Use = 512,
    UseDevId = 1024,
}

impl From<i32> for KeyPerm {
    fn from(value: i32) -> Self {
        match value {
            1 => KeyPerm::ConvertStorageKeyToEphemeral,
            2 => KeyPerm::Delete,
            4 => KeyPerm::GenUniqueId,
            8 => KeyPerm::GetInfo,
            16 => KeyPerm::Grant,
            32 => KeyPerm::ManageBlob,
            64 => KeyPerm::Rebind,
            128 => KeyPerm::ReqForcedOp,
            256 => KeyPerm::Update,
            512 => KeyPerm::Use,
            1024 => KeyPerm::UseDevId,
            _ => KeyPerm::Use,
        }
    }
}

impl KeyPerm {
    pub fn name(&self) -> &'static str {
        match self {
            KeyPerm::ConvertStorageKeyToEphemeral => "convert_storage_key_to_ephemeral",
            KeyPerm::Delete => "delete",
            KeyPerm::GenUniqueId => "gen_unique_id",
            KeyPerm::GetInfo => "get_info",
            KeyPerm::Grant => "grant",
            KeyPerm::ManageBlob => "manage_blob",
            KeyPerm::Rebind => "rebind",
            KeyPerm::ReqForcedOp => "req_forced_op",
            KeyPerm::Update => "update",
            KeyPerm::Use => "use",
            KeyPerm::UseDevId => "use_dev_id",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystorePerm {
    AddAuth,
    ClearNs,
    List,
    Lock,
    Reset,
    Unlock,
    ChangeUser,
    ChangePassword,
    ClearUID,
    GetAuthToken,
    EarlyBootEnded,
    PullMetrics,
    DeleteAllKeys,
    GetAttestationKey,
    GetLastAuthTime,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyPermSet(pub i32);

impl From<KeyPerm> for KeyPermSet {
    fn from(p: KeyPerm) -> Self {
        Self(p as i32)
    }
}

impl From<i32> for KeyPermSet {
    fn from(p: i32) -> Self {
        Self(p)
    }
}

impl From<KeyPermSet> for i32 {
    fn from(p: KeyPermSet) -> i32 {
        p.0
    }
}

impl KeyPermSet {
    pub fn includes<T: Into<KeyPermSet>>(&self, other: T) -> bool {
        let o: KeyPermSet = other.into();
        (self.0 & o.0) == o.0
    }

    pub fn iter(self) -> KeyPermIterator {
        KeyPermIterator { set: self, pos: 0 }
    }
}

pub struct KeyPermIterator {
    set: KeyPermSet,
    pos: u8,
}

impl Iterator for KeyPermIterator {
    type Item = KeyPerm;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < 32 {
            let bit = 1 << self.pos;
            self.pos += 1;
            if (self.set.0 & bit) != 0 {
                return Some(KeyPerm::from(bit));
            }
        }
        None
    }
}

pub fn check_keystore_permission(_caller_ctx: &CStr, _perm: KeystorePerm) -> anyhow::Result<()> {
    Ok(())
}

pub fn check_key_permission(
    caller_uid: u32,
    _caller_ctx: &CStr,
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    if let Some(access_vector) = access_vector {
        if access_vector.includes(perm) {
            return Ok(());
        }
    }

    match key.domain {
        Domain::App => {
            if caller_uid as i64 != key.namespace {
                return Err(Error::Rc(ResponseCode::PermissionDenied))
                    .context("Trying to access key without ownership");
            }
            Ok(())
        }
        Domain::Selinux => {
            if caller_uid as i64 != key.namespace {
                return Err(Error::Rc(ResponseCode::PermissionDenied))
                    .context("Trying to access SELinux key without proper namespace");
            }
            Ok(())
        }
        Domain::KeyId => Err(Error::Rc(ResponseCode::InvalidArgument))
            .context("Cannot check permission for Domain::KeyId"),
    }
}

pub fn check_grant_permission(
    caller_uid: u32,
    _caller_ctx: &CStr,
    access_vec: KeyPermSet,
    key: &KeyDescriptor,
) -> anyhow::Result<()> {
    match key.domain {
        Domain::App => {
            if caller_uid as i64 != key.namespace {
                return Err(Error::Rc(ResponseCode::PermissionDenied))
                    .context("Trying to grant key without ownership");
            }
        }
        Domain::Selinux => {
            if caller_uid as i64 != key.namespace {
                return Err(Error::Rc(ResponseCode::PermissionDenied))
                    .context("Trying to grant SELinux key without proper namespace");
            }
        }
        _ => {
            return Err(Error::Rc(ResponseCode::InvalidArgument))
                .context(format!("Cannot grant {:?}", key.domain));
        }
    }

    if access_vec.includes(KeyPerm::Grant) {
        return Err(Error::Rc(ResponseCode::PermissionDenied))
            .context("Grant permission cannot be granted");
    }

    Ok(())
}
