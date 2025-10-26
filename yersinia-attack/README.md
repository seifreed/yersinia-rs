# yersinia-attack

Attack orchestration system for Yersinia-RS with support for concurrent execution using Tokio.

## Features

- **AttackManager**: Main orchestrator for multiple concurrent attacks
- **AttackExecutor**: Executes individual attacks with error and panic handling
- **EnhancedAttackContext**: Enhanced context with rate limiting and logging
- **ProtocolRegistry**: Dynamic protocol registration system

## Architecture

### AttackManager

The `AttackManager` is the main entry point for launching and managing attacks:

- Thread-safe using `DashMap`
- Support for multiple concurrent attacks
- Methods for launch, pause, resume, stop, and stop_all
- Real-time statistics tracking
- Graceful shutdown

### AttackExecutor

The `AttackExecutor` handles the lifecycle of individual attacks:

- Asynchronous execution with Tokio
- Automatic panic handling (captured by Tokio runtime)
- Integrated logging with tracing
- Automatic statistics updates

### EnhancedAttackContext

Enhanced context passed to each attack:

- Packet sending with optional rate limiting
- Pause handling
- Thread-safe statistics tracking
- Integrated logging

### ProtocolRegistry

Centralized protocol registry:

- Dynamic runtime registration
- Lookup by name or ID
- Thread-safe with RwLock
- Optional global singleton

## Usage Example

```rust
use yersinia_attack::{AttackManager, ProtocolRegistry};
use yersinia_core::{AttackId, Interface, protocol::AttackParams};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create manager
    let manager = AttackManager::new();

    // Register a protocol (example with CDP)
    // let cdp = Arc::new(CdpProtocol::new());
    // ProtocolRegistry::register(cdp.clone())?;

    // Get protocol from registry
    // let protocol = ProtocolRegistry::get("cdp")
    //     .expect("CDP protocol not registered");

    // Configure parameters
    let params = AttackParams::new()
        .set("source_mac", "00:11:22:33:44:55")
        .set("device_id", "Router-1");

    // Create interface
    // let interface = Interface::by_name("eth0")?;

    // Launch attack
    // let attack_id = manager.launch(
    //     protocol.as_ref(),
    //     AttackId(0),
    //     params,
    //     &interface
    // ).await?;

    // println!("Attack launched: {}", attack_id);

    // Monitor statistics
    // tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    // let stats = manager.get_stats(attack_id)?;
    // println!("Packets sent: {}", stats.packets_sent);

    // Pause attack
    // manager.pause(attack_id)?;
    // tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Resume attack
    // manager.resume(attack_id)?;
    // tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Stop attack
    // manager.stop(attack_id).await?;

    // Or stop all attacks
    manager.stop_all().await?;

    Ok(())
}
```

## Launching Custom Attacks

You can also launch custom attacks without using the protocol system:

```rust
use yersinia_attack::AttackManager;
use yersinia_core::{Attack, AttackContext, Result};
use async_trait::async_trait;
use std::sync::Arc;

struct MyCustomAttack {
    name: String,
}

#[async_trait]
impl Attack for MyCustomAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        while ctx.running.load(std::sync::atomic::Ordering::Relaxed) {
            // Wait if paused
            while ctx.paused.load(std::sync::atomic::Ordering::Relaxed)
                && ctx.running.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if !ctx.running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            // Your attack logic here
            println!("Executing attack: {}", self.name);
            ctx.stats.increment_packets_sent();

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        Ok(())
    }

    fn pause(&self) {}
    fn resume(&self) {}
    fn stop(&self) {}

    fn stats(&self) -> yersinia_core::AttackStats {
        Default::default()
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let manager = AttackManager::new();
    let attack = Arc::new(MyCustomAttack {
        name: "MyAttack".to_string(),
    });

    // let interface = Interface::by_name("eth0")?;
    // let attack_id = manager.launch_custom(
    //     "custom".to_string(),
    //     "my_attack".to_string(),
    //     attack,
    //     interface,
    // )?;

    // ... manage attack lifecycle ...

    Ok(())
}
```

## Rate Limiting

The enhanced context supports rate limiting:

```rust
use yersinia_attack::EnhancedAttackContext;

// Create context with rate limiting (100 packets per second)
let ctx = EnhancedAttackContext::new(
    interface,
    running,
    paused,
    stats,
    "attack_name".to_string(),
).with_rate_limiter(100);

// Rate limiting is applied automatically in send_packet
ctx.send_packet(&packet).await?;
```

## Tests

The crate includes 23 comprehensive tests covering:

- Context creation and configuration
- Rate limiting
- Pause/Resume of attacks
- Error and panic handling
- Manager lifecycle (launch, stop, cleanup)
- Protocol registry operations

```bash
cargo test -p yersinia-attack
```

## Statistics

```
Total lines of code: ~1,700
Files:
- lib.rs: Exports and documentation
- manager.rs: Attack orchestration (~450 lines + tests)
- executor.rs: Attack execution (~350 lines + tests)
- context.rs: Enhanced context (~300 lines + tests)
- registry.rs: Protocol registry (~400 lines + tests)
```

## Dependencies

- `tokio`: Asynchronous runtime
- `dashmap`: Thread-safe HashMap for active attacks
- `uuid`: Unique identifiers for attack instances (v7 time-ordered)
- `tracing`: Structured logging
- `parking_lot`: High-performance locks
- `async-trait`: Support for async traits

## Technical Features

- **Thread-safe**: All structures are safe for concurrent use
- **No memory leaks**: Automatic resource cleanup
- **Graceful shutdown**: Orderly stopping of all attacks
- **Panic recovery**: Panics in attacks are captured by the Tokio runtime
- **Stats tracking**: Atomic counters for real-time statistics
- **Rate limiting**: Precise control of packet sending speed

## Known Limitations

- Rate limiter is per-attack, not global
- Panics in attacks are not explicitly captured (delegated to Tokio runtime)
- No limit on the number of concurrent attacks (future: implement pool)

## License

GPL-2.0-or-later (inherited from Yersinia project)

## Contributing

This crate is part of the Yersinia-RS project, a Rust rewrite of the classic Yersinia network vulnerability testing tool. See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.
