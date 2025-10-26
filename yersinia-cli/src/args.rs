//! CLI argument parsing
//!
//! Complete CLI interface for Yersinia-RS with support for all protocols and attacks.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "yersinia")]
#[command(version, about = "Network protocol security testing tool", long_about = None)]
pub struct Cli {
    /// Network interface to use
    #[arg(short = 'I', long, global = true)]
    pub interface: Option<String>,

    /// Enable interactive mode (TUI)
    #[arg(short = 'i', long, conflicts_with = "daemon")]
    pub interactive: bool,

    /// Daemon mode (no UI, run in background)
    #[arg(short = 'D', long, conflicts_with = "interactive")]
    pub daemon: bool,

    /// Protocol to use
    #[arg(short = 'G', long, value_name = "PROTOCOL")]
    pub protocol: Option<String>,

    /// Attack ID to launch
    #[arg(short = 'a', long, requires = "protocol")]
    pub attack: Option<u8>,

    /// Attack parameters (key=value pairs)
    #[arg(short = 'M', long, value_name = "KEY=VALUE")]
    pub params: Vec<String>,

    /// List available protocols
    #[arg(short = 'l', long)]
    pub list_protocols: bool,

    /// List attacks for a protocol
    #[arg(short = 'L', long, value_name = "PROTOCOL")]
    pub list_attacks: Option<String>,

    /// Verbose output (-v, -vv, -vvv for increasing verbosity)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable color output
    #[arg(long)]
    pub no_color: bool,

    /// Timeout for attacks in seconds
    #[arg(short = 't', long, value_name = "SECONDS", default_value = "0")]
    pub timeout: u64,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List available network interfaces
    Interfaces,

    /// List protocols and their attacks
    Protocols {
        /// Specific protocol to show
        #[arg(value_name = "PROTOCOL")]
        protocol: Option<String>,
    },

    /// Launch an attack
    Attack {
        /// Protocol name (cdp, stp, dhcp, vtp, dtp, hsrp, dot1q, dot1x, isl)
        #[arg(short = 'P', long)]
        protocol: String,

        /// Attack ID or name
        #[arg(short, long)]
        attack: String,

        /// Network interface name
        #[arg(short, long)]
        interface: String,

        /// Attack parameters (key=value pairs)
        #[arg(short = 'p', long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,

        /// Verbose output
        #[arg(short = 'v', long, action = clap::ArgAction::Count)]
        verbose: u8,
    },

    /// Interactive TUI mode
    Interactive {
        /// Network interface to use
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Run in daemon mode (no UI)
    Daemon {
        /// Network interface to use
        #[arg(short, long)]
        interface: Option<String>,

        /// Enable remote control via telnet
        #[arg(short, long)]
        remote: bool,

        /// Port for remote control
        #[arg(short, long, default_value = "12000")]
        port: u16,
    },
}

impl Cli {
    /// Parse command-line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Convert parameter strings (key=value) into a HashMap
    pub fn parse_params(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        for param in &self.params {
            if let Some((key, value)) = param.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }
        map
    }
}
