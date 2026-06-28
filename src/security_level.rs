#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SecurityLevel {
    #[default]
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
