//! TUI interface for Yersinia-RS
//!
//! This module provides a Terminal User Interface for Yersinia-RS using ratatui.
//! It allows interactive protocol and attack selection, parameter configuration,
//! and real-time monitoring of active attacks.

pub mod app;
pub mod runner;

pub use app::{App, ActiveAttack, AttackConfig, AttackEntry, AttackParameter, InterfaceEntry, ProtocolEntry, Screen};
pub use runner::run_tui;
