use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

// ============================================================================
// EVENTOS DEL SISTEMA
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    FileCreated,
    FileModified,
    FileDeleted,
    ProcessStarted,
    ProcessTerminated,
    NetworkConnection,
    RegistryModified,
    MemoryAllocation,
    DllInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub id: u64,
    pub timestamp: SystemTime,
    pub event_type: EventType,
    pub process_id: u32,
    pub process_name: String,
    pub details: EventDetails,
    pub threat_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventDetails {
    FileOp { path: String, hash: Option<String> },
    ProcessOp { parent_pid: u32, command_line: String },
    NetworkOp {
        remote_ip: String,
        remote_port: u16,
        protocol: String,
    },
    RegistryOp { key: String, value: String },
    MemoryOp {
        address: u64,
        size: usize,
        protection: u32,
    },
}

// ============================================================================
// VEREDICTOS Y RESPUESTAS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    Benign,
    Ransomware,
    Trojan,
    Spyware,
    Rootkit,
    Worm,
    Adware,
    PUP,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    Allow,
    Monitor,
    Suspend,
    Terminate,
    Quarantine,
    Block,
    BlockNetwork,
    Remediate,
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatVerdict {
    pub is_malicious: bool,
    pub confidence: f32,
    pub threat_type: ThreatType,
    pub reasons: Vec<String>,
    pub recommended_action: ResponseAction,
}

// ============================================================================
// AMENAZAS Y REMEDIACION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub confidence: f32,
    pub process_id: u32,
    pub process_name: String,
    pub process_path: PathBuf,
    pub parent_process_id: u32,
    pub affected_files: Vec<PathBuf>,
    pub network_connections: Vec<NetworkConnection>,
    pub registry_changes: Vec<RegistryChange>,
    pub detection_time: SystemTime,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub established_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryChange {
    pub key: String,
    pub value_name: String,
    pub old_value: Option<String>,
    pub new_value: String,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    pub success: bool,
    pub actions_taken: Vec<String>,
    pub files_restored: usize,
    pub registry_restored: usize,
    pub processes_terminated: usize,
    pub duration: Duration,
    pub errors: Vec<String>,
}
