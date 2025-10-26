//! Telnet remote administration server for Yersinia-RS
//!
//! This module provides a full-featured telnet server for remote management
//! of Yersinia-RS attacks and protocol operations.
//!
//! # Security Warning
//!
//! The telnet server transmits data in plain text and provides powerful
//! network attack capabilities. Only use on trusted networks and consider
//! using firewall rules to restrict access.

mod attack_manager;
mod command;
pub mod server;

pub use attack_manager::AttackManager;
pub use command::{Command, CommandParser};
pub use server::TelnetServer;
