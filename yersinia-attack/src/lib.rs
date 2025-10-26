//! Attack orchestration and management for Yersinia-RS
//!
//! This crate provides the attack execution and management infrastructure
//! for Yersinia-RS. It includes:
//!
//! - `AttackManager`: Orchestrates multiple concurrent attacks using Tokio
//! - `AttackExecutor`: Executes individual attacks with proper error handling
//! - `AttackContext`: Enhanced context for attack execution
//! - `ProtocolRegistry`: Dynamic protocol registration and lookup
//!
//! # Example
//!
//! ```no_run
//! use yersinia_attack::AttackManager;
//! use yersinia_core::{AttackId, Interface};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let manager = AttackManager::new();
//!
//!     // Launch an attack (example - requires a protocol implementation)
//!     // let attack_id = manager.launch(
//!     //     &protocol,
//!     //     AttackId(0),
//!     //     params,
//!     //     &interface
//!     // ).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod context;
pub mod executor;
pub mod manager;
pub mod registry;

pub use context::EnhancedAttackContext;
pub use executor::AttackExecutor;
pub use manager::{AttackInfo, AttackManager};
pub use registry::{ProtocolInfo, ProtocolRegistry};
