//! Protocol registry for dynamic protocol registration and lookup
//!
//! This module provides a centralized registry for protocol implementations,
//! allowing protocols to be registered at runtime and looked up by name or ID.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};
use yersinia_core::{Error, Protocol, ProtocolId, Result};

/// Information about a registered protocol
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// Protocol ID
    pub id: ProtocolId,
    /// Full name
    pub name: String,
    /// Short name
    pub shortname: String,
    /// Number of available attacks
    pub attack_count: usize,
    /// Protocol description (if available)
    pub description: Option<String>,
}

/// Protocol registry for managing available protocols
///
/// This is a thread-safe registry that allows protocols to be registered
/// dynamically at runtime and looked up by name or ID.
pub struct ProtocolRegistry {
    /// Map of protocol ID to protocol implementation
    protocols_by_id: Arc<RwLock<HashMap<ProtocolId, Arc<dyn Protocol>>>>,
    /// Map of shortname to protocol ID
    protocols_by_name: Arc<RwLock<HashMap<String, ProtocolId>>>,
}

impl ProtocolRegistry {
    /// Create a new empty protocol registry
    pub fn new() -> Self {
        info!("Creating new ProtocolRegistry");
        Self {
            protocols_by_id: Arc::new(RwLock::new(HashMap::new())),
            protocols_by_name: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a protocol
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol implementation to register
    ///
    /// # Returns
    ///
    /// Returns an error if a protocol with the same ID or name is already registered
    pub fn register(&self, protocol: Arc<dyn Protocol>) -> Result<()> {
        let id = protocol.id();
        let shortname = protocol.shortname().to_string();
        let name = protocol.name();

        info!(
            id = ?id,
            name = name,
            shortname = %shortname,
            "Registering protocol"
        );

        // Check if already registered
        {
            let by_id = self.protocols_by_id.read();
            if by_id.contains_key(&id) {
                warn!(id = ?id, "Protocol already registered by ID");
                return Err(Error::AlreadyExists(format!(
                    "Protocol with ID {:?} already registered",
                    id
                )));
            }
        }

        {
            let by_name = self.protocols_by_name.read();
            if by_name.contains_key(&shortname) {
                warn!(shortname = %shortname, "Protocol already registered by name");
                return Err(Error::AlreadyExists(format!(
                    "Protocol with shortname '{}' already registered",
                    shortname
                )));
            }
        }

        // Register
        {
            let mut by_id = self.protocols_by_id.write();
            by_id.insert(id, protocol);
        }

        {
            let mut by_name = self.protocols_by_name.write();
            by_name.insert(shortname, id);
        }

        info!(id = ?id, name = name, "Protocol registered successfully");
        Ok(())
    }

    /// Unregister a protocol by ID
    pub fn unregister(&self, id: ProtocolId) -> Result<()> {
        debug!(id = ?id, "Unregistering protocol");

        let protocol = {
            let mut by_id = self.protocols_by_id.write();
            by_id.remove(&id)
        };

        if let Some(protocol) = protocol {
            let shortname = protocol.shortname().to_string();

            // Remove from name map
            let mut by_name = self.protocols_by_name.write();
            by_name.remove(&shortname);

            info!(id = ?id, shortname = %shortname, "Protocol unregistered");
            Ok(())
        } else {
            warn!(id = ?id, "Protocol not found");
            Err(Error::NotFound(format!(
                "Protocol with ID {:?} not found",
                id
            )))
        }
    }

    /// Get a protocol by its short name
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn Protocol>> {
        let by_name = self.protocols_by_name.read();
        let id = by_name.get(name)?;

        let by_id = self.protocols_by_id.read();
        by_id.get(id).cloned()
    }

    /// Get a protocol by its ID
    pub fn get_by_id(&self, id: ProtocolId) -> Option<Arc<dyn Protocol>> {
        let by_id = self.protocols_by_id.read();
        by_id.get(&id).cloned()
    }

    /// List all registered protocols
    pub fn list_protocols(&self) -> Vec<ProtocolInfo> {
        let by_id = self.protocols_by_id.read();

        by_id
            .values()
            .map(|protocol| ProtocolInfo {
                id: protocol.id(),
                name: protocol.name().to_string(),
                shortname: protocol.shortname().to_string(),
                attack_count: protocol.attacks().len(),
                description: None, // Could be extended to include description
            })
            .collect()
    }

    /// Get the number of registered protocols
    pub fn count(&self) -> usize {
        self.protocols_by_id.read().len()
    }

    /// Check if a protocol is registered
    pub fn contains(&self, name: &str) -> bool {
        self.protocols_by_name.read().contains_key(name)
    }

    /// Clear all registered protocols
    pub fn clear(&self) {
        info!("Clearing all registered protocols");

        let mut by_id = self.protocols_by_id.write();
        let mut by_name = self.protocols_by_name.write();

        by_id.clear();
        by_name.clear();
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global protocol registry instance
///
/// This provides a convenient singleton for accessing the protocol registry.
pub struct GlobalRegistry;

impl GlobalRegistry {
    /// Get the global protocol registry instance
    ///
    /// This uses a lazy static to ensure the registry is only created once.
    pub fn instance() -> &'static ProtocolRegistry {
        static INSTANCE: std::sync::OnceLock<ProtocolRegistry> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(ProtocolRegistry::new)
    }

    /// Register a protocol with the global registry
    pub fn register(protocol: Arc<dyn Protocol>) -> Result<()> {
        Self::instance().register(protocol)
    }

    /// Get a protocol by name from the global registry
    pub fn get(name: &str) -> Option<Arc<dyn Protocol>> {
        Self::instance().get_by_name(name)
    }

    /// List all protocols in the global registry
    pub fn list() -> Vec<ProtocolInfo> {
        Self::instance().list_protocols()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use yersinia_core::{
        protocol::ProtocolStats, AttackDescriptor, AttackHandle, AttackId, Interface, Packet,
        Parameter,
    };

    struct TestProtocol {
        name: &'static str,
        shortname: &'static str,
        id: ProtocolId,
    }

    #[async_trait]
    impl Protocol for TestProtocol {
        fn name(&self) -> &'static str {
            self.name
        }

        fn shortname(&self) -> &'static str {
            self.shortname
        }

        fn id(&self) -> ProtocolId {
            self.id
        }

        fn attacks(&self) -> &[AttackDescriptor] {
            &[]
        }

        fn parameters(&self) -> Vec<Box<dyn Parameter>> {
            vec![]
        }

        fn handle_packet(&mut self, _packet: &Packet) -> Result<()> {
            Ok(())
        }

        async fn launch_attack(
            &self,
            _attack_id: AttackId,
            _params: yersinia_core::protocol::AttackParams,
            _interface: &Interface,
        ) -> Result<AttackHandle> {
            Err(Error::NotImplemented("test".to_string()))
        }

        fn stats(&self) -> ProtocolStats {
            Default::default()
        }

        fn reset_stats(&mut self) {}
    }

    #[test]
    fn test_registry_register() {
        let registry = ProtocolRegistry::new();
        let protocol = Arc::new(TestProtocol {
            name: "Test Protocol",
            shortname: "test",
            id: ProtocolId::CDP,
        });

        assert!(registry.register(protocol.clone()).is_ok());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_registry_duplicate_registration() {
        let registry = ProtocolRegistry::new();
        let protocol = Arc::new(TestProtocol {
            name: "Test Protocol",
            shortname: "test",
            id: ProtocolId::CDP,
        });

        assert!(registry.register(protocol.clone()).is_ok());
        assert!(registry.register(protocol.clone()).is_err());
    }

    #[test]
    fn test_registry_get_by_name() {
        let registry = ProtocolRegistry::new();
        let protocol = Arc::new(TestProtocol {
            name: "Test Protocol",
            shortname: "test",
            id: ProtocolId::CDP,
        });

        registry.register(protocol.clone()).unwrap();

        let retrieved = registry.get_by_name("test");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().shortname(), "test");
    }

    #[test]
    fn test_registry_get_by_id() {
        let registry = ProtocolRegistry::new();
        let protocol = Arc::new(TestProtocol {
            name: "Test Protocol",
            shortname: "test",
            id: ProtocolId::CDP,
        });

        registry.register(protocol.clone()).unwrap();

        let retrieved = registry.get_by_id(ProtocolId::CDP);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id(), ProtocolId::CDP);
    }

    #[test]
    fn test_registry_list() {
        let registry = ProtocolRegistry::new();

        let protocol1 = Arc::new(TestProtocol {
            name: "Test Protocol 1",
            shortname: "test1",
            id: ProtocolId::CDP,
        });

        let protocol2 = Arc::new(TestProtocol {
            name: "Test Protocol 2",
            shortname: "test2",
            id: ProtocolId::STP,
        });

        registry.register(protocol1).unwrap();
        registry.register(protocol2).unwrap();

        let list = registry.list_protocols();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_registry_unregister() {
        let registry = ProtocolRegistry::new();
        let protocol = Arc::new(TestProtocol {
            name: "Test Protocol",
            shortname: "test",
            id: ProtocolId::CDP,
        });

        registry.register(protocol.clone()).unwrap();
        assert_eq!(registry.count(), 1);

        registry.unregister(ProtocolId::CDP).unwrap();
        assert_eq!(registry.count(), 0);

        assert!(registry.get_by_name("test").is_none());
    }

    #[test]
    fn test_registry_contains() {
        let registry = ProtocolRegistry::new();
        let protocol = Arc::new(TestProtocol {
            name: "Test Protocol",
            shortname: "test",
            id: ProtocolId::CDP,
        });

        assert!(!registry.contains("test"));

        registry.register(protocol.clone()).unwrap();
        assert!(registry.contains("test"));
    }

    #[test]
    fn test_registry_clear() {
        let registry = ProtocolRegistry::new();
        let protocol = Arc::new(TestProtocol {
            name: "Test Protocol",
            shortname: "test",
            id: ProtocolId::CDP,
        });

        registry.register(protocol.clone()).unwrap();
        assert_eq!(registry.count(), 1);

        registry.clear();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_global_registry() {
        // Note: This test might interfere with other tests if they use the global registry
        // In production code, you might want to avoid using the global registry in tests

        let protocol = Arc::new(TestProtocol {
            name: "Global Test Protocol",
            shortname: "global_test",
            id: ProtocolId::VTP,
        });

        // Clean up first
        if GlobalRegistry::instance().contains("global_test") {
            GlobalRegistry::instance().unregister(ProtocolId::VTP).ok();
        }

        assert!(GlobalRegistry::register(protocol.clone()).is_ok());
        assert!(GlobalRegistry::get("global_test").is_some());

        // Clean up
        GlobalRegistry::instance().unregister(ProtocolId::VTP).ok();
    }
}
