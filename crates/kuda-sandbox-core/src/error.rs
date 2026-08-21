use thiserror::Error;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("Execution timeout after {0} seconds")]
    Timeout(u64),

    #[error("Process killed: {0}")]
    ProcessKilled(String),

    #[error("Sandbox setup failed: {0}")]
    SetupFailed(String),

    #[error("Platform unsupported or feature disabled: {0}")]
    Unsupported(String),

    #[error("General error: {0}")]
    General(String),
}

pub type Result<T> = std::result::Result<T, SandboxError>;
