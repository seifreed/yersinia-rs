//! Attack Manager
//!
//! Manages running attacks, tracking their state and providing operations
//! to launch, stop, pause, and query attacks remotely.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;
use yersinia_core::{AttackHandle, AttackStats};

/// Information about a running attack
#[derive(Debug, Clone)]
pub struct AttackInfo {
    /// Unique attack identifier
    pub id: Uuid,
    /// Protocol name
    pub protocol: String,
    /// Attack name
    pub attack_name: String,
    /// Interface used
    pub interface: String,
    /// When the attack was started
    pub started_at: DateTime<Utc>,
    /// Current statistics
    pub stats: AttackStats,
}

/// Manager for tracking and controlling running attacks
pub struct AttackManager {
    /// Map of attack ID to attack handle
    attacks: Arc<DashMap<Uuid, AttackHandle>>,
    /// Map of attack ID to attack metadata
    metadata: Arc<DashMap<Uuid, AttackMetadata>>,
}

#[derive(Debug, Clone)]
struct AttackMetadata {
    protocol: String,
    attack_name: String,
    interface: String,
    started_at: DateTime<Utc>,
}

impl AttackManager {
    /// Create a new attack manager
    pub fn new() -> Self {
        Self {
            attacks: Arc::new(DashMap::new()),
            metadata: Arc::new(DashMap::new()),
        }
    }

    /// Register a new attack
    pub fn register(
        &self,
        handle: AttackHandle,
        protocol: String,
        attack_name: String,
        interface: String,
    ) -> Uuid {
        let id = handle.id;
        let metadata = AttackMetadata {
            protocol,
            attack_name,
            interface,
            started_at: Utc::now(),
        };

        self.attacks.insert(id, handle);
        self.metadata.insert(id, metadata);

        id
    }

    /// Stop an attack by ID
    pub fn stop(&self, id: Uuid) -> Result<(), String> {
        if let Some(handle) = self.attacks.get(&id) {
            handle.stop();
            Ok(())
        } else {
            Err(format!("Attack {} not found", id))
        }
    }

    /// Pause an attack by ID
    pub fn pause(&self, id: Uuid) -> Result<(), String> {
        if let Some(handle) = self.attacks.get(&id) {
            handle.pause();
            Ok(())
        } else {
            Err(format!("Attack {} not found", id))
        }
    }

    /// Resume an attack by ID
    pub fn resume(&self, id: Uuid) -> Result<(), String> {
        if let Some(handle) = self.attacks.get(&id) {
            handle.resume();
            Ok(())
        } else {
            Err(format!("Attack {} not found", id))
        }
    }

    /// Get information about a specific attack
    pub fn get_info(&self, id: Uuid) -> Option<AttackInfo> {
        let handle = self.attacks.get(&id)?;
        let metadata = self.metadata.get(&id)?;

        Some(AttackInfo {
            id,
            protocol: metadata.protocol.clone(),
            attack_name: metadata.attack_name.clone(),
            interface: metadata.interface.clone(),
            started_at: metadata.started_at,
            stats: handle.stats(),
        })
    }

    /// List all running attacks
    pub fn list_running(&self) -> Vec<AttackInfo> {
        let mut attacks = Vec::new();

        for entry in self.attacks.iter() {
            let id = *entry.key();
            if let Some(info) = self.get_info(id) {
                if info.stats.is_running {
                    attacks.push(info);
                }
            }
        }

        attacks.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        attacks
    }

    /// List all attacks (including stopped ones)
    pub fn list_all(&self) -> Vec<AttackInfo> {
        let mut attacks = Vec::new();

        for entry in self.attacks.iter() {
            let id = *entry.key();
            if let Some(info) = self.get_info(id) {
                attacks.push(info);
            }
        }

        attacks.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        attacks
    }

    /// Remove stopped attacks from tracking
    pub fn cleanup_stopped(&self) {
        let stopped: Vec<Uuid> = self
            .attacks
            .iter()
            .filter_map(|entry| {
                let id = *entry.key();
                if let Some(info) = self.get_info(id) {
                    if !info.stats.is_running {
                        Some(id)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        for id in stopped {
            self.attacks.remove(&id);
            self.metadata.remove(&id);
        }
    }

    /// Get the number of running attacks
    pub fn running_count(&self) -> usize {
        self.attacks
            .iter()
            .filter(|entry| {
                let id = *entry.key();
                self.get_info(id)
                    .map(|info| info.stats.is_running)
                    .unwrap_or(false)
            })
            .count()
    }

    /// Stop all running attacks
    pub fn stop_all(&self) {
        for entry in self.attacks.iter() {
            entry.value().stop();
        }
    }
}

impl Default for AttackManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_manager_new() {
        let manager = AttackManager::new();
        assert_eq!(manager.running_count(), 0);
    }
}
