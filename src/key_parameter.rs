use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    Invalid = 0,
    Algorithm = 1,
    KeySize = 2,
    Digest = 3,
    Padding = 4,
    BlockMode = 5,
    Purpose = 6,
    AttestationChallenge = 200,
    AttestationApplicationId = 201,
    AttestationIdBrand = 301,
    AttestationIdDevice = 302,
    AttestationIdProduct = 303,
    AttestationIdSerial = 304,
    AttestationIdImei = 305,
    AttestationIdMeid = 306,
    AttestationIdManufacturer = 307,
    AttestationIdModel = 308,
    AttestationIdVendorPatchLevel = 309,
    AttestationIdBootPatchLevel = 310,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyParameterValue {
    Invalid,
    Algorithm(i32),
    KeySize(i32),
    Digest(i32),
    Padding(i32),
    BlockMode(i32),
    Purpose(i32),
    AttestationChallenge(Vec<u8>),
    AttestationApplicationId(Vec<u8>),
    Integer(i32),
    LongInteger(i64),
    Bytes(Vec<u8>),
    Bool(bool),
    Date(i64),
}

impl KeyParameterValue {
    pub fn get_tag(&self) -> Tag {
        match self {
            KeyParameterValue::Invalid => Tag::Invalid,
            KeyParameterValue::Algorithm(_) => Tag::Algorithm,
            KeyParameterValue::KeySize(_) => Tag::KeySize,
            KeyParameterValue::Digest(_) => Tag::Digest,
            KeyParameterValue::Padding(_) => Tag::Padding,
            KeyParameterValue::BlockMode(_) => Tag::BlockMode,
            KeyParameterValue::Purpose(_) => Tag::Purpose,
            KeyParameterValue::AttestationChallenge(_) => Tag::AttestationChallenge,
            KeyParameterValue::AttestationApplicationId(_) => Tag::AttestationApplicationId,
            _ => Tag::Invalid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyParameter {
    pub tag: Tag,
    pub value: KeyParameterValue,
}

pub type KeyParameters = Vec<KeyParameter>;

impl KeyParameter {
    pub fn new(tag: Tag, value: KeyParameterValue) -> Self {
        Self { tag, value }
    }
}
