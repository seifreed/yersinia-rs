# Yersinia-RS Telnet Server

A fully functional telnet server for remote administration of Yersinia-RS attacks and protocol operations.

## Features

- **Full Attack Management**: Launch, stop, pause, resume, and monitor attacks remotely
- **Protocol Discovery**: List available protocols and their attacks
- **Real-time Statistics**: Track packets sent, bytes transferred, errors, and attack status
- **Multi-client Support**: Handle multiple concurrent telnet connections
- **Async Architecture**: Built on tokio for efficient concurrent operations
- **Security Warnings**: Prominent banner warning about plain-text transmission

## Security Considerations

**WARNING:** The telnet protocol transmits all data in **PLAIN TEXT**, including any commands and responses. This includes attack parameters and system information.

### Security Recommendations

1. **Network Isolation**: Only run on trusted, isolated networks (e.g., lab environments)
2. **Firewall Rules**: Use firewall rules to restrict access to specific IP addresses
3. **VPN/SSH Tunneling**: Consider tunneling telnet through SSH or VPN for remote access
4. **Local Only**: Bind to localhost (127.0.0.1) if only local access is needed
5. **Temporary Use**: Start the server only when needed, stop when done
6. **Monitoring**: Log all connections and commands for security auditing

### Future Enhancements

- TLS/SSL encryption support
- Password authentication
- Role-based access control (RBAC)
- Command logging and audit trail
- Rate limiting and connection throttling

## Usage

### Starting the Server

```rust
use yersinia_telnet::TelnetServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create server on default port 12000
    let server = TelnetServer::new(12000);

    // Or bind to localhost only
    let server = TelnetServer::new(12000)
        .with_bind_addr("127.0.0.1".to_string());

    // Start the server
    server.start().await?;

    Ok(())
}
```

### Connecting to the Server

```bash
# Connect using telnet
telnet localhost 12000

# Or using netcat
nc localhost 12000
```

## Available Commands

### Protocol Management

```
list-protocols, protocols
  List all available protocols

list-attacks <protocol>, attacks <protocol>
  List attacks for a specific protocol
  Example: list-attacks cdp
```

### Attack Management

```
launch <protocol> <id> <interface> [param=value ...]
  Launch an attack with optional parameters
  Example: launch cdp 0 eth0 device_id=hacker count=100

list-running, running
  List currently running attacks

list-all, list
  List all attacks (including stopped)

stop <uuid>
  Stop a specific attack
  Example: stop 01234567-89ab-cdef-0123-456789abcdef

pause <uuid>
  Pause a specific attack

resume <uuid>
  Resume a paused attack

info <uuid>
  Show detailed information about an attack

stop-all, stopall
  Stop all running attacks

cleanup
  Remove stopped attacks from the list
```

### Server Status

```
status
  Show server status including:
  - Version
  - Number of protocols loaded
  - Number of running attacks
  - Total attacks tracked
```

### General

```
help, ?
  Show help message with all available commands

exit, quit, q
  Close connection
```

## Example Session

```
$ telnet localhost 12000
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.

================================================================

    Yersinia-RS - Network Protocol Security Testing Tool
    Telnet Remote Administration Interface

    WARNING: This interface transmits in PLAIN TEXT!
             Use only on trusted networks!
             Unauthorized access is prohibited!

================================================================

Type 'help' for available commands.

yersinia> status
Yersinia-RS Server Status:
==================
Version: 0.1.0
Protocols Loaded: 38
Running Attacks: 0
Total Attacks: 0

yersinia> list-protocols
Available Protocols (38):
==================
  - arp
  - bfd
  - bgp
  - cdp
  - dhcp
  ... (more protocols)

Use 'list-attacks <protocol>' to see attacks for a protocol.

yersinia> list-attacks cdp
Protocol: Cisco Discovery Protocol (cdp)
Available Attacks (2):
==================

ID: 0
Name: CDP Flooding
Description: Flood network with CDP packets to exhaust neighbor tables
Parameters:
  - device_id_prefix (String)
  - interval_ms (U32)
  - randomize_mac (Bool)

ID: 1
Name: CDP Impersonation
Description: Spoof CDP packets to impersonate a specific device
Parameters:
  - device_id (String) [required]
  - target_mac (MacAddr)

yersinia> launch cdp 0 eth0 device_id_prefix=attacker interval_ms=100
Launching attack: CDP Flooding (ID: 0) on eth0
Attack launched successfully!
Attack UUID: 01234567-89ab-cdef-0123-456789abcdef

yersinia> list-running
Running Attacks (1):
==================

UUID:      01234567-89ab-cdef-0123-456789abcdef
Protocol:  cdp
Attack:    CDP Flooding
Interface: eth0
Started:   2025-01-15 10:30:45 UTC
Status:    RUNNING
Packets:   1234
Bytes:     567890
Errors:    0

yersinia> stop 01234567-89ab-cdef-0123-456789abcdef
Attack 01234567-89ab-cdef-0123-456789abcdef stopped.

yersinia> exit
Goodbye!
Connection closed by foreign host.
```

## Architecture

### Components

1. **TelnetServer**: Main server that accepts connections and manages clients
2. **AttackManager**: Tracks and controls running attacks
3. **CommandParser**: Parses telnet commands
4. **ProtocolRegistry**: Interface to access available protocols

### Design Decisions

- **Async/Await**: All I/O operations are asynchronous using tokio
- **Connection Isolation**: Each client runs in its own tokio task
- **Lock-free Reads**: Uses tokio::sync::RwLock for concurrent read access
- **Shared State**: AttackManager uses Arc + DashMap for thread-safe shared state
- **Graceful Disconnection**: Properly handles client disconnects without panics

## Configuration

### Default Settings

- **Port**: 12000
- **Bind Address**: 0.0.0.0 (all interfaces)
- **Max Clients**: Unlimited (system-limited by file descriptors)

### Environment Integration

The telnet server integrates with the existing Yersinia-RS infrastructure:

- **Protocol Registry**: Accesses the centralized protocol registry
- **Attack Launching**: Uses protocol.launch_attack() for consistency
- **Interface Handling**: Uses yersinia_core::Interface types

## Testing

Run tests with:

```bash
cargo test -p yersinia-telnet
```

Tests cover:
- Command parsing (all command types)
- Attack manager operations
- Server initialization
- Configuration

## Performance

The telnet server is designed for low-to-moderate load:

- Each client connection spawns a separate async task
- Command processing is lightweight
- Attack operations are delegated to protocol implementations
- Statistics are read-only operations on atomic counters

## Error Handling

- Client disconnects are handled gracefully
- Invalid commands show helpful error messages
- Attack launch failures are reported to the client
- Server errors are logged but don't crash the server

## Future Enhancements

1. **Authentication**: Password or token-based authentication
2. **Encryption**: TLS support for encrypted connections
3. **Access Control**: Per-user or per-IP command restrictions
4. **Command History**: Track command history per client
5. **Batch Operations**: Support for executing multiple commands
6. **JSON Output**: Optional JSON format for programmatic access
7. **WebSocket Support**: Alternative real-time protocol
8. **Metrics**: Prometheus metrics endpoint

## License

GPL-2.0-or-later (same as Yersinia-RS)

## Contributing

See the main Yersinia-RS CONTRIBUTING.md for guidelines.
