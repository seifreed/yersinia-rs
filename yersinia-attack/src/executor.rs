//! Attack executor that runs attacks with proper error handling
//!
//! This module provides the `AttackExecutor` which is responsible for:
//! - Executing attack implementations
//! - Handling panics and errors
//! - Automatically updating statistics
//! - Providing logging via tracing

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use yersinia_core::{Attack, AttackContext, AttackHandle, Error, Result};

/// Attack executor that handles the lifecycle of an attack
pub struct AttackExecutor {
    /// Unique identifier for this attack instance
    id: Uuid,
    /// Protocol name
    protocol_name: String,
    /// Attack name
    attack_name: String,
}

impl AttackExecutor {
    /// Create a new attack executor
    pub fn new(protocol_name: String, attack_name: String) -> Self {
        Self {
            id: Uuid::now_v7(),
            protocol_name,
            attack_name,
        }
    }

    /// Execute an attack and return a handle
    ///
    /// This method spawns a tokio task that runs the attack's execute method.
    /// It handles:
    /// - Panic recovery
    /// - Error logging
    /// - Statistics updates
    /// - Graceful shutdown
    pub fn execute(self, attack: Arc<dyn Attack>, context: AttackContext) -> Result<AttackHandle> {
        let id = self.id;
        let protocol_name = self.protocol_name.clone();
        let attack_name = self.attack_name.clone();
        let running = context.running.clone();
        let paused = context.paused.clone();
        let stats = context.stats.clone();
        let started_at = SystemTime::now();

        info!(
            id = %id,
            protocol = %protocol_name,
            attack = %attack_name,
            "Starting attack"
        );

        // Clone for the async task
        let protocol_name_task = protocol_name.clone();
        let attack_name_task = attack_name.clone();

        // Spawn the attack task
        let task_handle = tokio::spawn(async move {
            let result = Self::run_with_panic_handler(attack, context).await;

            match &result {
                Ok(_) => {
                    info!(
                        id = %id,
                        protocol = %protocol_name_task,
                        attack = %attack_name_task,
                        "Attack completed successfully"
                    );
                }
                Err(e) => {
                    error!(
                        id = %id,
                        protocol = %protocol_name_task,
                        attack = %attack_name_task,
                        error = %e,
                        "Attack failed"
                    );
                }
            }

            result
        });

        Ok(AttackHandle {
            id,
            protocol: protocol_name,
            attack_name,
            running,
            paused,
            stats,
            started_at,
            task_handle: Some(task_handle),
        })
    }

    /// Run the attack with panic handling
    ///
    /// Note: Due to limitations in catching panics in async code,
    /// this will let panics propagate. The tokio runtime will catch them
    /// and the task will be aborted.
    async fn run_with_panic_handler(attack: Arc<dyn Attack>, context: AttackContext) -> Result<()> {
        // Simply execute the attack
        // If it panics, tokio will catch it and the JoinHandle will return an error
        attack.execute(context).await
    }
}

/// Helper struct for managing multiple concurrent attack executors
pub struct ExecutorPool {
    /// Maximum number of concurrent attacks
    max_concurrent: usize,
    /// Currently running attacks
    _running_count: Arc<AtomicBool>,
}

impl ExecutorPool {
    /// Create a new executor pool
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent,
            _running_count: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if the pool can accept more attacks
    pub fn can_accept(&self) -> bool {
        // For now, simplified - just check if any are running
        // In a real implementation, we'd track the actual count
        true
    }

    /// Get the maximum number of concurrent attacks
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
}

/// Helper function to wait for an attack to complete
pub async fn wait_for_attack(handle: &mut AttackHandle) -> Result<()> {
    if let Some(task_handle) = handle.task_handle.take() {
        match task_handle.await {
            Ok(result) => result,
            Err(e) => {
                if e.is_panic() {
                    error!(
                        id = %handle.id,
                        "Attack task panicked"
                    );
                    Err(Error::ExecutionFailed("Attack task panicked".to_string()))
                } else {
                    error!(
                        id = %handle.id,
                        error = %e,
                        "Failed to join attack task"
                    );
                    Err(Error::ExecutionFailed(format!(
                        "Failed to join attack task: {}",
                        e
                    )))
                }
            }
        }
    } else {
        warn!(
            id = %handle.id,
            "Attack task already joined"
        );
        Ok(())
    }
}

/// Helper function to stop an attack and wait for it to complete
pub async fn stop_and_wait(handle: &mut AttackHandle) -> Result<()> {
    debug!(
        id = %handle.id,
        "Stopping attack"
    );

    handle.stop();
    wait_for_attack(handle).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use yersinia_core::{AttackStatsCounters, Interface, MacAddr};

    struct TestAttack {
        should_panic: bool,
        should_error: bool,
        duration: Duration,
    }

    #[async_trait]
    impl Attack for TestAttack {
        async fn execute(&self, ctx: AttackContext) -> Result<()> {
            if self.should_panic {
                panic!("Test panic");
            }

            if self.should_error {
                return Err(Error::ExecutionFailed("Test error".to_string()));
            }

            let mut count = 0;
            while ctx.running.load(Ordering::Relaxed) && count < 10 {
                tokio::time::sleep(self.duration).await;
                ctx.stats.increment_packets_sent();
                count += 1;
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
            "test_attack"
        }
    }

    fn create_test_interface() -> Interface {
        Interface::new(
            "test0".to_string(),
            0,
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        )
    }

    fn create_test_context() -> AttackContext {
        let interface = create_test_interface();
        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        AttackContext {
            interface,
            running,
            paused,
            stats,
        }
    }

    #[tokio::test]
    async fn test_executor_success() {
        let executor = AttackExecutor::new("test".to_string(), "test_attack".to_string());
        let attack = Arc::new(TestAttack {
            should_panic: false,
            should_error: false,
            duration: Duration::from_millis(10),
        });
        let context = create_test_context();

        let mut handle = executor.execute(attack, context).unwrap();

        // Wait a bit for some packets to be sent
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop the attack
        let result = stop_and_wait(&mut handle).await;
        assert!(result.is_ok());

        // Check that some packets were sent
        let stats = handle.stats();
        assert!(stats.packets_sent > 0);
    }

    #[tokio::test]
    async fn test_executor_handles_error() {
        let executor = AttackExecutor::new("test".to_string(), "test_attack".to_string());
        let attack = Arc::new(TestAttack {
            should_panic: false,
            should_error: true,
            duration: Duration::from_millis(10),
        });
        let context = create_test_context();

        let mut handle = executor.execute(attack, context).unwrap();
        let result = wait_for_attack(&mut handle).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_executor_handles_panic() {
        let executor = AttackExecutor::new("test".to_string(), "test_attack".to_string());
        let attack = Arc::new(TestAttack {
            should_panic: true,
            should_error: false,
            duration: Duration::from_millis(10),
        });
        let context = create_test_context();

        let mut handle = executor.execute(attack, context).unwrap();
        let result = wait_for_attack(&mut handle).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_executor_pool() {
        let pool = ExecutorPool::new(10);
        assert_eq!(pool.max_concurrent(), 10);
        assert!(pool.can_accept());
    }
}
