#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    #[error("System error: {0}")]
    System(String),
}

impl Error {
    pub fn sys() -> Self {
        Error::Rc(ResponseCode::SystemError)
    }

    pub fn perm() -> Self {
        Error::Rc(ResponseCode::PermissionDenied)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    Ok = 0,
    SystemError = 1,
    PermissionDenied = 2,
    KeyNotFound = 3,
    ValueCorrupted = 4,
    InvalidArgument = 5,
    KeyAlreadyExists = 6,
    Locked = 7,
    Unimplemented = 8,
}

impl From<i32> for ResponseCode {
    fn from(code: i32) -> Self {
        match code {
            0 => ResponseCode::Ok,
            1 => ResponseCode::SystemError,
            2 => ResponseCode::PermissionDenied,
            3 => ResponseCode::KeyNotFound,
            4 => ResponseCode::ValueCorrupted,
            5 => ResponseCode::InvalidArgument,
            6 => ResponseCode::KeyAlreadyExists,
            7 => ResponseCode::Locked,
            8 => ResponseCode::Unimplemented,
            _ => ResponseCode::SystemError,
        }
    }
}
