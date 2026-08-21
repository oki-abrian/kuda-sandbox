use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    pub sandbox_id: Uuid,
    pub setup_duration_ms: u64,
    pub execution_duration_ms: u64,
    pub total_duration_ms: u64,
    pub peak_memory_bytes: u64,
    pub exit_code: i32,
    pub platform: String,
    pub resource_violation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsageSnapshot {
    pub memory_bytes: u64,
    pub cpu_time_ms: u64,
    pub pid_count: u32,
}
