//! Error types for Yersinia-RS

use thiserror::Error;

/// Result type alias for Yersinia operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for Yersinia-RS
#[derive(Error, Debug)]
pub enum Error {
    /// Network I/O error
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol-specific error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Attack execution error
    #[error("Attack error: {0}")]
    Attack(String),

    /// Invalid parameter error
    #[error("Invalid parameter '{name}': {reason}")]
    InvalidParameter { name: String, reason: String },

    /// Interface not found
    #[error("Interface '{0}' not found")]
    InterfaceNotFound(String),

    /// Interface error
    #[error("Interface error: {0}")]
    Interface(String),

    /// Invalid attack ID
    #[error("Invalid attack ID: {0}")]
    InvalidAttackId(u8),

    /// Packet construction error
    #[error("Packet construction error: {0}")]
    PacketConstruction(String),

    /// Packet parsing error
    #[error("Packet parsing error: {0}")]
    PacketParsing(String),

    /// Capture error
    #[error("Packet capture error: {0}")]
    Capture(String),

    /// Insufficient privileges
    #[error("Insufficient privileges: {0}")]
    InsufficientPrivileges(String),

    /// Not implemented
    #[error("Feature not implemented: {0}")]
    NotImplemented(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Resource already exists
    #[error("Resource already exists: {0}")]
    AlreadyExists(String),

    /// Execution failed
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    /// Operation interrupted
    #[error("Operation interrupted: {0}")]
    Interrupted(String),
}

impl Error {
    /// Create a protocol error with a custom message
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        Error::Protocol(msg.into())
    }

    /// Create an attack error with a custom message
    pub fn attack<S: Into<String>>(msg: S) -> Self {
        Error::Attack(msg.into())
    }

    /// Create an invalid parameter error
    pub fn invalid_parameter<S: Into<String>>(name: S, reason: S) -> Self {
        Error::InvalidParameter {
            name: name.into(),
            reason: reason.into(),
        }
    }
}
