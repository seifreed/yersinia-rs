# Contributing to Yersinia-RS

Thank you for your interest in contributing to Yersinia-RS! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [License](#license)

---

## Code of Conduct

This project follows professional open source standards. Contributors are expected to:

- Be respectful and constructive in all communications
- Focus on technical merit and project improvement
- Welcome new contributors and help them learn
- Respect differing viewpoints and experiences
- Accept constructive criticism gracefully

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- Rust 1.75 or later installed
- libpcap development libraries
- Git for version control
- A GitHub account
- Familiarity with network protocols (recommended)

### Development Setup

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/yersinia-rs.git
cd yersinia-rs
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/seifreed/yersinia-rs.git
```

4. Install dependencies and build:

```bash
cargo build
```

5. Run the test suite to verify everything works:

```bash
cargo test
```

## How to Contribute

### Reporting Bugs

Before creating a bug report:

1. Check existing issues to avoid duplicates
2. Verify the bug exists in the latest version
3. Collect relevant information (OS, Rust version, error messages)

Create a bug report with:

- Clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Error messages and stack traces
- System information (OS, Rust version)
- Minimal code example if applicable

### Suggesting Enhancements

Enhancement suggestions are welcome! Include:

- Clear description of the proposed feature
- Use cases and benefits
- Potential implementation approach
- Any drawbacks or alternatives considered

### Contributing Code

Areas where contributions are particularly welcome:

1. **New protocol implementations**: Add support for additional network protocols
2. **Attack implementations**: Expand existing protocol attack vectors
3. **Documentation**: Improve inline docs, examples, and guides
4. **Testing**: Add tests to increase coverage
5. **Performance**: Optimize packet construction and parsing
6. **Bug fixes**: Address issues in the issue tracker
7. **CI/CD**: Improve GitHub Actions workflows
8. **TUI**: Complete the terminal user interface
9. **Cross-platform support**: Test and fix platform-specific issues

## Coding Standards

### Rust Style Guide

Follow the official Rust style guide:

- Use `rustfmt` for code formatting: `cargo fmt`
- Use `clippy` for linting: `cargo clippy`
- Fix all clippy warnings before submitting

### Code Organization

- Keep functions focused and small (ideally under 50 lines)
- Use meaningful variable and function names
- Organize code into logical modules
- Separate concerns appropriately

### Documentation

All code must include:

1. **Module-level documentation**: Explain the module's purpose

```rust
//! This module provides packet construction utilities for the CDP protocol.
//!
//! CDP (Cisco Discovery Protocol) is a Layer 2 protocol used for device discovery.
```

2. **Public API documentation**: Document all public functions, structs, and traits

```rust
/// Constructs a CDP packet with the specified device ID.
///
/// # Arguments
///
/// * `device_id` - The device identifier to advertise
/// * `port_id` - The port identifier
///
/// # Returns
///
/// Returns a byte vector containing the constructed CDP packet.
///
/// # Examples
///
/// ```
/// let packet = build_cdp_packet("Router-1", "FastEthernet0/1");
/// ```
pub fn build_cdp_packet(device_id: &str, port_id: &str) -> Vec<u8> {
    // Implementation
}
```

3. **Inline comments**: Explain complex logic or non-obvious decisions

```rust
// Use saturating_add to prevent integer overflow when incrementing counters
stats.packets_sent.saturating_add(1);
```

### Error Handling

- Use `Result<T, E>` for operations that can fail
- Define custom error types with `thiserror`
- Provide context with error messages
- Avoid panicking in library code (use `Result` instead)

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid packet length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Protocol parsing failed: {0}")]
    ParseError(String),
}
```

### Type Safety

- Use newtype patterns for domain-specific types
- Prefer strong typing over primitive types
- Use enums for state and variants

```rust
// Good: Type-safe port number
pub struct Port(u16);

// Bad: Raw integer
pub fn connect(port: u16) { }
```

## Testing Requirements

### Test Coverage

All contributions must include tests:

- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test module interactions
- **Documentation tests**: Ensure examples in docs work

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdp_packet_construction() {
        let packet = build_cdp_packet("Router-1", "Fa0/1");
        assert!(!packet.is_empty());
        assert_eq!(packet[0], 0x02); // CDP version
    }

    #[test]
    fn test_invalid_input_handling() {
        let result = parse_cdp_packet(&[]);
        assert!(result.is_err());
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p yersinia-protocols

# Run tests with output
cargo test -- --nocapture

# Run tests with coverage (requires tarpaulin)
cargo tarpaulin --out Html
```

### Test Requirements

- All public APIs must have tests
- Tests must pass before PR submission
- Aim for high code coverage (target: 80%+)
- Test edge cases and error conditions

## Pull Request Process

### Before Submitting

1. Create a feature branch from `master`:

```bash
git checkout -b feature/your-feature-name
```

2. Make your changes following the coding standards

3. Format your code:

```bash
cargo fmt
```

4. Run clippy and fix warnings:

```bash
cargo clippy --all-targets --all-features
```

5. Run all tests:

```bash
cargo test
```

6. Update documentation if needed

7. Commit your changes with clear messages:

```bash
git commit -m "Add CDP packet validation
- Implement length checking
- Add checksum validation
- Include error handling for malformed packets"
```

### Commit Message Format

Follow conventional commit format:

```
<type>: <short summary>

<detailed description>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Example:

```
feat: Add VLAN hopping attack for 802.1Q

Implement double-tagging attack that allows access to restricted VLANs
by exploiting native VLAN configuration issues.

- Add attack parameter parsing
- Implement double-tag packet construction
- Include comprehensive tests
- Update protocol documentation

Closes #42
```

### Submitting the Pull Request

1. Push your branch to your fork:

```bash
git push origin feature/your-feature-name
```

2. Create a Pull Request on GitHub

3. Fill out the PR template with:
   - Clear description of changes
   - Related issue numbers
   - Testing performed
   - Breaking changes (if any)

4. Wait for review and address feedback

### PR Review Process

- Maintainers will review within 1 week
- Address reviewer comments and push updates
- Once approved, maintainers will merge your PR
- Your contribution will be included in the next release

### PR Requirements

- [ ] Code follows project coding standards
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] No merge conflicts with master
- [ ] `cargo fmt` and `cargo clippy` pass

## Adding New Protocols

To add a new protocol implementation:

1. Create a new module in `yersinia-protocols/src/`

```
yersinia-protocols/src/
├── your_protocol/
│   ├── mod.rs          # Module exports and Protocol trait impl
│   ├── parser.rs       # Packet parsing logic
│   ├── builder.rs      # Packet construction
│   ├── attacks.rs      # Attack implementations
│   └── tests.rs        # Unit tests
```

2. Implement the `Protocol` trait:

```rust
use yersinia_core::{Protocol, Attack, ProtocolInfo};

pub struct YourProtocol;

impl Protocol for YourProtocol {
    fn info(&self) -> ProtocolInfo {
        ProtocolInfo {
            id: "your_protocol",
            name: "Your Protocol Name",
            description: "Protocol description",
            layer: yersinia_core::Layer::Layer2,
        }
    }

    fn attacks(&self) -> Vec<Box<dyn Attack>> {
        vec![
            Box::new(YourAttack1),
            Box::new(YourAttack2),
        ]
    }
}
```

3. Implement attacks following the `Attack` trait

4. Add comprehensive tests

5. Register the protocol in the main binary

6. Update documentation and README

## Coding Best Practices

### Security

- Validate all input data
- Use safe Rust (avoid `unsafe` unless absolutely necessary)
- Be cautious with external data
- Follow principle of least privilege
- Document security implications

### Performance

- Profile before optimizing
- Use appropriate data structures
- Minimize allocations in hot paths
- Consider async/await for I/O operations
- Benchmark critical code paths

### Maintainability

- Write self-documenting code
- Keep functions focused and small
- Avoid premature abstraction
- Refactor duplicated code
- Add comments for complex logic

## License

By contributing to Yersinia-RS, you agree that your contributions will be licensed under the GNU General Public License v2.0 or later (GPL-2.0-or-later).

All contributed code must:

- Be your original work or properly attributed
- Be compatible with GPL-2.0-or-later
- Not include proprietary or incompatible licenses
- Include appropriate copyright headers

### Copyright Header

Add this header to new files:

```rust
// Copyright (C) 2025 Marc Rivero | @seifreed <mriverolopez@gmail.com>
//
// This file is part of Yersinia-RS.
//
// Yersinia-RS is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
```

## Questions?

If you have questions about contributing:

- Open a GitHub Discussion
- Check existing documentation
- Review closed PRs for examples
- Ask in your PR for guidance

Thank you for contributing to Yersinia-RS!
