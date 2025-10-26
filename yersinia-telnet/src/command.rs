//! Command Parser
//!
//! Parses and executes telnet commands for remote management.

use std::collections::HashMap;
use uuid::Uuid;

/// Telnet command
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Show help
    Help,
    /// List available protocols
    ListProtocols,
    /// List attacks for a protocol
    ListAttacks { protocol: String },
    /// Launch an attack
    Launch {
        protocol: String,
        attack_id: u8,
        interface: String,
        params: HashMap<String, String>,
    },
    /// List running attacks
    ListRunning,
    /// List all attacks (including stopped)
    ListAll,
    /// Stop an attack
    Stop { attack_id: Uuid },
    /// Pause an attack
    Pause { attack_id: Uuid },
    /// Resume an attack
    Resume { attack_id: Uuid },
    /// Get attack info
    Info { attack_id: Uuid },
    /// Show server status
    Status,
    /// Cleanup stopped attacks
    Cleanup,
    /// Stop all attacks
    StopAll,
    /// Exit the session
    Exit,
}

/// Command parser
pub struct CommandParser;

impl CommandParser {
    /// Parse a command line
    pub fn parse(line: &str) -> Result<Command, String> {
        let line = line.trim();
        if line.is_empty() {
            return Err("Empty command".to_string());
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let cmd = parts[0].to_lowercase();

        match cmd.as_str() {
            "help" | "?" => Ok(Command::Help),
            "list-protocols" | "protocols" => Ok(Command::ListProtocols),
            "list-attacks" | "attacks" => {
                if parts.len() < 2 {
                    Err("Usage: list-attacks <protocol>".to_string())
                } else {
                    Ok(Command::ListAttacks {
                        protocol: parts[1].to_string(),
                    })
                }
            }
            "launch" => Self::parse_launch(&parts[1..]),
            "list-running" | "running" => Ok(Command::ListRunning),
            "list-all" | "list" => Ok(Command::ListAll),
            "stop" => {
                if parts.len() < 2 {
                    Err("Usage: stop <attack-id>".to_string())
                } else {
                    let id = Uuid::parse_str(parts[1])
                        .map_err(|_| format!("Invalid UUID: {}", parts[1]))?;
                    Ok(Command::Stop { attack_id: id })
                }
            }
            "pause" => {
                if parts.len() < 2 {
                    Err("Usage: pause <attack-id>".to_string())
                } else {
                    let id = Uuid::parse_str(parts[1])
                        .map_err(|_| format!("Invalid UUID: {}", parts[1]))?;
                    Ok(Command::Pause { attack_id: id })
                }
            }
            "resume" => {
                if parts.len() < 2 {
                    Err("Usage: resume <attack-id>".to_string())
                } else {
                    let id = Uuid::parse_str(parts[1])
                        .map_err(|_| format!("Invalid UUID: {}", parts[1]))?;
                    Ok(Command::Resume { attack_id: id })
                }
            }
            "info" => {
                if parts.len() < 2 {
                    Err("Usage: info <attack-id>".to_string())
                } else {
                    let id = Uuid::parse_str(parts[1])
                        .map_err(|_| format!("Invalid UUID: {}", parts[1]))?;
                    Ok(Command::Info { attack_id: id })
                }
            }
            "status" => Ok(Command::Status),
            "cleanup" => Ok(Command::Cleanup),
            "stop-all" | "stopall" => Ok(Command::StopAll),
            "exit" | "quit" | "q" => Ok(Command::Exit),
            _ => Err(format!("Unknown command: {}. Type 'help' for available commands.", cmd)),
        }
    }

    /// Parse launch command arguments
    fn parse_launch(parts: &[&str]) -> Result<Command, String> {
        // launch <protocol> <attack-id> <interface> [param=value ...]
        if parts.len() < 3 {
            return Err("Usage: launch <protocol> <attack-id> <interface> [param=value ...]".to_string());
        }

        let protocol = parts[0].to_string();
        let attack_id = parts[1]
            .parse::<u8>()
            .map_err(|_| format!("Invalid attack ID: {}", parts[1]))?;
        let interface = parts[2].to_string();

        // Parse optional parameters
        let mut params = HashMap::new();
        for part in &parts[3..] {
            if let Some((key, value)) = part.split_once('=') {
                params.insert(key.to_string(), value.to_string());
            } else {
                return Err(format!("Invalid parameter format: {}. Expected key=value", part));
            }
        }

        Ok(Command::Launch {
            protocol,
            attack_id,
            interface,
            params,
        })
    }

    /// Get help text
    pub fn help_text() -> &'static str {
        r#"
Available Commands:
==================

Protocol Management:
  list-protocols, protocols           - List all available protocols
  list-attacks <protocol>, attacks    - List attacks for a specific protocol

Attack Management:
  launch <protocol> <id> <iface>      - Launch an attack
                                        Example: launch cdp 0 eth0 device_id=hacker
  list-running, running               - List currently running attacks
  list-all, list                      - List all attacks (including stopped)
  stop <uuid>                         - Stop a specific attack
  pause <uuid>                        - Pause a specific attack
  resume <uuid>                       - Resume a paused attack
  info <uuid>                         - Show detailed attack information
  stop-all, stopall                   - Stop all running attacks
  cleanup                             - Remove stopped attacks from list

Server Status:
  status                              - Show server status

General:
  help, ?                             - Show this help message
  exit, quit, q                       - Close connection

Notes:
  - All attack UUIDs are shown when launching attacks or listing
  - Parameters for launch are in key=value format
  - Multiple parameters can be specified: launch cdp 0 eth0 count=100 interval=50
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_help() {
        assert_eq!(CommandParser::parse("help").unwrap(), Command::Help);
        assert_eq!(CommandParser::parse("?").unwrap(), Command::Help);
        assert_eq!(CommandParser::parse("  help  ").unwrap(), Command::Help);
    }

    #[test]
    fn test_parse_list_protocols() {
        assert_eq!(
            CommandParser::parse("list-protocols").unwrap(),
            Command::ListProtocols
        );
        assert_eq!(
            CommandParser::parse("protocols").unwrap(),
            Command::ListProtocols
        );
    }

    #[test]
    fn test_parse_list_attacks() {
        match CommandParser::parse("list-attacks cdp").unwrap() {
            Command::ListAttacks { protocol } => assert_eq!(protocol, "cdp"),
            _ => panic!("Wrong command type"),
        }
    }

    #[test]
    fn test_parse_launch() {
        match CommandParser::parse("launch cdp 0 eth0 device_id=test count=100").unwrap() {
            Command::Launch {
                protocol,
                attack_id,
                interface,
                params,
            } => {
                assert_eq!(protocol, "cdp");
                assert_eq!(attack_id, 0);
                assert_eq!(interface, "eth0");
                assert_eq!(params.get("device_id"), Some(&"test".to_string()));
                assert_eq!(params.get("count"), Some(&"100".to_string()));
            }
            _ => panic!("Wrong command type"),
        }
    }

    #[test]
    fn test_parse_exit() {
        assert_eq!(CommandParser::parse("exit").unwrap(), Command::Exit);
        assert_eq!(CommandParser::parse("quit").unwrap(), Command::Exit);
        assert_eq!(CommandParser::parse("q").unwrap(), Command::Exit);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(CommandParser::parse("invalid").is_err());
        assert!(CommandParser::parse("").is_err());
    }
}
