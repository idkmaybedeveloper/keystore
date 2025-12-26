#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

impl SecurityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Software => "SOFTWARE",
            SecurityLevel::TrustedEnvironment => "TRUSTED_ENVIRONMENT",
            SecurityLevel::StrongBox => "STRONGBOX",
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Software
    }
}
