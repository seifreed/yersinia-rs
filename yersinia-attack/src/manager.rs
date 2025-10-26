//! Attack manager for orchestrating multiple concurrent attacks
//!
//! The `AttackManager` is the main entry point for launching and managing
//! attacks in Yersinia-RS. It provides:
//!
//! - Concurrent attack execution using Tokio
//! - Attack lifecycle management (launch, pause, resume, stop)
//! - Thread-safe attack tracking with DashMap
//! - Statistics collection
//! - Graceful shutdown

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use yersinia_core::{
    Attack, AttackContext, AttackHandle, AttackId, AttackStats, AttackStatsCounters, Error,
    Interface, Protocol, Result,
};

use crate::executor::{stop_and_wait, AttackExecutor};

/// Information about a running attack
#[derive(Debug, Clone)]
pub struct AttackInfo {
    /// Unique attack instance ID
    pub id: Uuid,
    /// Protocol name
    pub protocol: String,
    /// Attack name
    pub attack_name: String,
    /// When the attack started
    pub started_at: SystemTime,
    /// Is the attack running?
    pub is_running: bool,
    /// Is the attack paused?
    pub is_paused: bool,
    /// Current statistics
    pub stats: AttackStats,
}

/// Attack manager that orchestrates multiple concurrent attacks
pub struct AttackManager {
    /// Map of active attacks (UUID -> AttackHandle)
    attacks: Arc<DashMap<Uuid, AttackHandle>>,
    /// Is the manager shutting down?
    shutting_down: Arc<AtomicBool>,
}

impl AttackManager {
    /// Create a new attack manager
    pub fn new() -> Self {
        info!("Creating new AttackManager");
        Self {
            attacks: Arc::new(DashMap::new()),
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Launch an attack
    ///
    /// # Arguments
    ///
    /// * `protocol` - The protocol implementation
    /// * `attack_id` - The ID of the attack to launch (from the protocol's attack list)
    /// * `params` - Parameters for the attack
    /// * `interface` - Network interface to use
    ///
    /// # Returns
    ///
    /// Returns the UUID of the launched attack instance
    pub async fn launch(
        &self,
        protocol: &dyn Protocol,
        attack_id: AttackId,
        params: yersinia_core::protocol::AttackParams,
        interface: &Interface,
    ) -> Result<Uuid> {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err(Error::ExecutionFailed(
                "Manager is shutting down".to_string(),
            ));
        }

        info!(
            protocol = %protocol.shortname(),
            attack_id = ?attack_id,
            interface = %interface.name,
            "Launching attack"
        );

        // Launch the attack through the protocol
        let handle = protocol.launch_attack(attack_id, params, interface).await?;
        let attack_uuid = handle.id;

        // Store the handle
        self.attacks.insert(attack_uuid, handle);

        info!(
            id = %attack_uuid,
            protocol = %protocol.shortname(),
            "Attack launched successfully"
        );

        Ok(attack_uuid)
    }

    /// Launch an attack with a custom Attack implementation
    ///
    /// This is a lower-level method that bypasses the protocol and directly
    /// executes an Attack trait object.
    pub fn launch_custom(
        &self,
        protocol_name: String,
        attack_name: String,
        attack: Arc<dyn Attack>,
        interface: Interface,
    ) -> Result<Uuid> {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err(Error::ExecutionFailed(
                "Manager is shutting down".to_string(),
            ));
        }

        info!(
            protocol = %protocol_name,
            attack = %attack_name,
            interface = %interface.name,
            "Launching custom attack"
        );

        // Create executor
        let executor = AttackExecutor::new(protocol_name.clone(), attack_name.clone());

        // Create context
        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        let context = AttackContext {
            interface,
            running,
            paused,
            stats,
        };

        // Execute the attack
        let handle = executor.execute(attack, context)?;
        let attack_uuid = handle.id;

        // Store the handle
        self.attacks.insert(attack_uuid, handle);

        info!(
            id = %attack_uuid,
            protocol = %protocol_name,
            attack = %attack_name,
            "Custom attack launched successfully"
        );

        Ok(attack_uuid)
    }

    /// Pause an attack
    pub fn pause(&self, id: Uuid) -> Result<()> {
        debug!(id = %id, "Pausing attack");

        if let Some(handle) = self.attacks.get(&id) {
            handle.pause();
            info!(id = %id, "Attack paused");
            Ok(())
        } else {
            warn!(id = %id, "Attack not found");
            Err(Error::NotFound(format!("Attack {} not found", id)))
        }
    }

    /// Resume a paused attack
    pub fn resume(&self, id: Uuid) -> Result<()> {
        debug!(id = %id, "Resuming attack");

        if let Some(handle) = self.attacks.get(&id) {
            handle.resume();
            info!(id = %id, "Attack resumed");
            Ok(())
        } else {
            warn!(id = %id, "Attack not found");
            Err(Error::NotFound(format!("Attack {} not found", id)))
        }
    }

    /// Stop an attack
    pub async fn stop(&self, id: Uuid) -> Result<()> {
        info!(id = %id, "Stopping attack");

        // Remove the handle from the map
        if let Some((_, mut handle)) = self.attacks.remove(&id) {
            // Stop and wait for completion
            stop_and_wait(&mut handle).await?;
            info!(id = %id, "Attack stopped successfully");
            Ok(())
        } else {
            warn!(id = %id, "Attack not found");
            Err(Error::NotFound(format!("Attack {} not found", id)))
        }
    }

    /// Stop all running attacks
    pub async fn stop_all(&self) -> Result<()> {
        info!("Stopping all attacks");
        self.shutting_down.store(true, Ordering::Relaxed);

        let attack_ids: Vec<Uuid> = self.attacks.iter().map(|entry| *entry.key()).collect();

        let mut errors = Vec::new();
        for id in attack_ids {
            if let Err(e) = self.stop(id).await {
                error!(id = %id, error = %e, "Failed to stop attack");
                errors.push(e);
            }
        }

        if errors.is_empty() {
            info!("All attacks stopped successfully");
            Ok(())
        } else {
            Err(Error::ExecutionFailed(format!(
                "Failed to stop {} attacks",
                errors.len()
            )))
        }
    }

    /// List all active attacks
    pub fn list_active(&self) -> Vec<AttackInfo> {
        self.attacks
            .iter()
            .map(|entry| {
                let handle = entry.value();
                AttackInfo {
                    id: handle.id,
                    protocol: handle.protocol.clone(),
                    attack_name: handle.attack_name.clone(),
                    started_at: handle.started_at,
                    is_running: handle.running.load(Ordering::Relaxed),
                    is_paused: handle.paused.load(Ordering::Relaxed),
                    stats: handle.stats(),
                }
            })
            .collect()
    }

    /// Get statistics for a specific attack
    pub fn get_stats(&self, id: Uuid) -> Result<AttackStats> {
        if let Some(handle) = self.attacks.get(&id) {
            Ok(handle.stats())
        } else {
            Err(Error::NotFound(format!("Attack {} not found", id)))
        }
    }

    /// Get the number of active attacks
    pub fn active_count(&self) -> usize {
        self.attacks.len()
    }

    /// Check if an attack is running
    pub fn is_running(&self, id: Uuid) -> bool {
        self.attacks
            .get(&id)
            .map(|h| h.running.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Check if an attack is paused
    pub fn is_paused(&self, id: Uuid) -> bool {
        self.attacks
            .get(&id)
            .map(|h| h.paused.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Clean up completed attacks
    ///
    /// This removes attack handles that are no longer running.
    /// Should be called periodically to prevent memory leaks.
    pub fn cleanup_completed(&self) -> usize {
        let completed: Vec<Uuid> = self
            .attacks
            .iter()
            .filter(|entry| !entry.value().running.load(Ordering::Relaxed))
            .map(|entry| *entry.key())
            .collect();

        let count = completed.len();
        for id in completed {
            self.attacks.remove(&id);
            debug!(id = %id, "Cleaned up completed attack");
        }

        if count > 0 {
            info!(count = count, "Cleaned up completed attacks");
        }

        count
    }
}

impl Default for AttackManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AttackManager {
    fn drop(&mut self) {
        // Mark as shutting down
        self.shutting_down.store(true, Ordering::Relaxed);

        // Stop all attacks
        let attack_ids: Vec<Uuid> = self.attacks.iter().map(|entry| *entry.key()).collect();

        for id in attack_ids {
            if let Some(handle) = self.attacks.get(&id) {
                handle.stop();
            }
        }

        warn!("AttackManager dropped, all attacks stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::time::Duration;
    use yersinia_core::MacAddr;

    struct TestAttack {
        name: String,
    }

    #[async_trait]
    impl Attack for TestAttack {
        async fn execute(&self, ctx: AttackContext) -> Result<()> {
            let mut count = 0;
            while ctx.running.load(Ordering::Relaxed) && count < 100 {
                // Wait if paused
                while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }

                if !ctx.running.load(Ordering::Relaxed) {
                    break;
                }

                tokio::time::sleep(Duration::from_millis(10)).await;
                ctx.stats.increment_packets_sent();
                count += 1;
            }
            Ok(())
        }

        fn pause(&self) {}
        fn resume(&self) {}
        fn stop(&self) {}

        fn stats(&self) -> AttackStats {
            Default::default()
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    fn create_test_interface() -> Interface {
        Interface::new(
            "test0".to_string(),
            0,
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        )
    }

    #[tokio::test]
    async fn test_manager_launch_custom() {
        let manager = AttackManager::new();
        let attack = Arc::new(TestAttack {
            name: "test_attack".to_string(),
        });
        let interface = create_test_interface();

        let id = manager
            .launch_custom(
                "test".to_string(),
                "test_attack".to_string(),
                attack,
                interface,
            )
            .unwrap();

        assert!(manager.is_running(id));
        assert_eq!(manager.active_count(), 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats = manager.get_stats(id).unwrap();
        assert!(stats.packets_sent > 0);

        manager.stop(id).await.unwrap();
        assert!(!manager.is_running(id));
    }

    #[tokio::test]
    async fn test_manager_pause_resume() {
        let manager = AttackManager::new();
        let attack = Arc::new(TestAttack {
            name: "test_attack".to_string(),
        });
        let interface = create_test_interface();

        let id = manager
            .launch_custom(
                "test".to_string(),
                "test_attack".to_string(),
                attack,
                interface,
            )
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let stats_before = manager.get_stats(id).unwrap().packets_sent;

        manager.pause(id).unwrap();
        assert!(manager.is_paused(id));

        tokio::time::sleep(Duration::from_millis(50)).await;
        let stats_paused = manager.get_stats(id).unwrap().packets_sent;

        // Should not have sent many packets while paused
        assert!(stats_paused - stats_before < 5);

        manager.resume(id).unwrap();
        assert!(!manager.is_paused(id));

        tokio::time::sleep(Duration::from_millis(50)).await;
        let stats_after = manager.get_stats(id).unwrap().packets_sent;

        // Should have sent more packets after resume
        assert!(stats_after > stats_paused);

        manager.stop(id).await.unwrap();
    }

    #[tokio::test]
    async fn test_manager_stop_all() {
        let manager = AttackManager::new();

        // Launch multiple attacks
        for i in 0..3 {
            let attack = Arc::new(TestAttack {
                name: format!("test_attack_{}", i),
            });
            let interface = create_test_interface();

            manager
                .launch_custom(
                    "test".to_string(),
                    format!("test_attack_{}", i),
                    attack,
                    interface,
                )
                .unwrap();
        }

        assert_eq!(manager.active_count(), 3);

        manager.stop_all().await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // All attacks should be stopped
        for info in manager.list_active() {
            assert!(!manager.is_running(info.id));
        }
    }

    #[tokio::test]
    async fn test_manager_list_active() {
        let manager = AttackManager::new();

        let attack = Arc::new(TestAttack {
            name: "test_attack".to_string(),
        });
        let interface = create_test_interface();

        manager
            .launch_custom(
                "test".to_string(),
                "test_attack".to_string(),
                attack,
                interface,
            )
            .unwrap();

        let active = manager.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].protocol, "test");
        assert_eq!(active[0].attack_name, "test_attack");

        manager.stop_all().await.unwrap();
    }

    #[tokio::test]
    async fn test_manager_cleanup_completed() {
        let manager = AttackManager::new();

        let attack = Arc::new(TestAttack {
            name: "test_attack".to_string(),
        });
        let interface = create_test_interface();

        let id = manager
            .launch_custom(
                "test".to_string(),
                "test_attack".to_string(),
                attack,
                interface,
            )
            .unwrap();

        // Stop the attack by setting the running flag to false
        // (instead of calling manager.stop which removes it)
        if let Some(handle) = manager.attacks.get(&id) {
            handle.stop();
        }

        // Wait for the attack to complete
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now cleanup should find it
        let cleaned = manager.cleanup_completed();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.active_count(), 0);
    }
}
