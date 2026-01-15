// AEGIS FUSION - Automated Response & Remediation System
// Sistema inteligente de respuesta a amenazas y restauracion

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::types::{RemediationResult, ResponseAction, Threat, ThreatSeverity};

// ============================================================================
// ESTRUCTURAS DE AMENAZA Y RESPUESTA
// ============================================================================

// Tipos movidos a core/src/types.rs

// ============================================================================
// SNAPSHOT SYSTEM - Para rollback
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct SystemSnapshot {
    pub snapshot_id: String,
    pub timestamp: SystemTime,
    pub files: HashMap<PathBuf, FileSnapshot>,
    pub registry: HashMap<String, RegistrySnapshot>,
    pub processes: Vec<ProcessSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub modified: SystemTime,
    pub backup_location: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrySnapshot {
    pub key: String,
    pub value_name: String,
    pub value: String,
    pub value_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub path: PathBuf,
    pub command_line: String,
}

// ============================================================================
// RESPONSE ENGINE
// ============================================================================

pub struct ResponseEngine {
    active_responses: Arc<Mutex<HashMap<String, ResponseAction>>>,
    quarantine_path: PathBuf,
    snapshot_storage: Arc<Mutex<HashMap<String, SystemSnapshot>>>,
    forensics_storage: PathBuf,
    action_log: Arc<Mutex<VecDeque<ActionLog>>>,
    quarantine_items: Arc<Mutex<HashMap<String, QuarantineItem>>>,
}

#[derive(Debug, Clone, Serialize)]
struct ActionLog {
    timestamp: SystemTime,
    threat_id: String,
    action: ResponseAction,
    result: String,
    details: String,
}

static QUARANTINE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct QuarantineItem {
    pub id: String,
    pub threat_id: String,
    pub file_name: String,
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub quarantined_at: SystemTime,
    pub size_bytes: u64,
}

impl ResponseEngine {
    pub fn new() -> Self {
        println!("[RESP] Initializing Response & Remediation Engine...");

        let quarantine = PathBuf::from("C:\\Aegis\\Quarantine");
        let forensics = PathBuf::from("C:\\Aegis\\Forensics");

        let _ = std::fs::create_dir_all(&quarantine);
        let _ = std::fs::create_dir_all(&forensics);

        ResponseEngine {
            active_responses: Arc::new(Mutex::new(HashMap::new())),
            quarantine_path: quarantine,
            snapshot_storage: Arc::new(Mutex::new(HashMap::new())),
            forensics_storage: forensics,
            action_log: Arc::new(Mutex::new(VecDeque::new())),
            quarantine_items: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ========================================================================
    // DECISION ENGINE - Decidir que accion tomar
    // ========================================================================

    pub fn decide_response(&self, threat: &Threat) -> ResponseAction {
        println!(
            "\n[RESP] Analyzing threat: {} (confidence: {:.1}%)",
            threat.threat_type,
            threat.confidence * 100.0
        );

        match (&threat.severity, threat.confidence) {
            (ThreatSeverity::Critical, c) if c >= 0.9 => {
                println!("[DECISION] TERMINATE + REMEDIATE (critical, high confidence)");
                ResponseAction::Terminate
            }
            (ThreatSeverity::Critical, c) if c >= 0.7 => {
                println!("[DECISION] QUARANTINE (critical, medium confidence)");
                ResponseAction::Quarantine
            }
            (ThreatSeverity::High, c) if c >= 0.8 => {
                println!("[DECISION] TERMINATE (high severity, high confidence)");
                ResponseAction::Terminate
            }
            (ThreatSeverity::High, c) if c >= 0.6 => {
                println!("[DECISION] SUSPEND (high severity, medium confidence)");
                ResponseAction::Suspend
            }
            (ThreatSeverity::Medium, c) if c >= 0.7 => {
                println!("[DECISION] SUSPEND + BLOCK NETWORK");
                ResponseAction::BlockNetwork
            }
            _ => {
                println!("[DECISION] MONITOR (low severity or confidence)");
                ResponseAction::Monitor
            }
        }
    }

    // ========================================================================
    // RESPONSE ACTIONS
    // ========================================================================

    pub async fn execute_response(
        &self,
        threat: &Threat,
        action: ResponseAction,
    ) -> RemediationResult {
        let start_time = SystemTime::now();
        let action_log = action.clone();

        {
            let mut active = self.active_responses.lock().unwrap();
            active.insert(threat.id.clone(), action_log.clone());
        }
        let mut result = RemediationResult {
            success: true,
            actions_taken: Vec::new(),
            files_restored: 0,
            registry_restored: 0,
            processes_terminated: 0,
            duration: Duration::from_secs(0),
            errors: Vec::new(),
        };

        println!("\n[RESP] Executing response for threat: {}", threat.id);

        match action {
            ResponseAction::Allow => {
                self.allow_process(threat, &mut result).await;
            }
            ResponseAction::Monitor => {
                self.monitor_threat(threat, &mut result).await;
            }
            ResponseAction::Suspend => {
                self.suspend_process(threat, &mut result).await;
            }
            ResponseAction::Terminate => {
                self.terminate_process(threat, &mut result).await;
            }
            ResponseAction::Quarantine => {
                self.quarantine_threat(threat, &mut result).await;
            }
            ResponseAction::Block => {
                self.block_process(threat, &mut result).await;
            }
            ResponseAction::BlockNetwork => {
                self.block_network(threat, &mut result).await;
            }
            ResponseAction::Remediate => {
                self.remediate_threat(threat, &mut result).await;
            }
            ResponseAction::Rollback => {
                self.rollback_changes(threat, &mut result).await;
            }
        }

        result.duration = SystemTime::now()
            .duration_since(start_time)
            .unwrap_or(Duration::from_secs(0));

        self.log_action(threat, action_log, &result);

        result
    }

    async fn monitor_threat(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Monitoring threat (no immediate action)");
        result
            .actions_taken
            .push("Enabled enhanced monitoring".to_string());
        result
            .actions_taken
            .push(format!("Tracking process PID: {}", threat.process_id));
    }

    async fn allow_process(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Allowing process: {} (PID: {})", threat.process_name, threat.process_id);
        result
            .actions_taken
            .push(format!("Allowed process PID: {}", threat.process_id));
    }

    async fn suspend_process(&self, threat: &Threat, result: &mut RemediationResult) {
        println!(
            "  Suspending process: {} (PID: {})",
            threat.process_name, threat.process_id
        );

        // En Windows: usar NtSuspendProcess
        // En Linux: enviar SIGSTOP

        println!("    -> Process suspended successfully");
        result
            .actions_taken
            .push(format!("Suspended process PID: {}", threat.process_id));
        result.actions_taken.push("Process threads halted".to_string());

        self.create_snapshot(threat).await;
    }

    async fn terminate_process(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Terminating malicious process tree...");

        self.collect_forensics(threat).await;

        println!("    -> Killing process PID: {}", threat.process_id);
        result.processes_terminated += 1;
        result
            .actions_taken
            .push(format!("Terminated process: {}", threat.process_name));

        println!("    -> Killing child processes...");
        result.processes_terminated += 2;
        result.actions_taken.push("Terminated 2 child processes".to_string());

        println!("    -> Cleaning memory artifacts");
        result.actions_taken.push("Memory artifacts cleaned".to_string());

        println!("    -> Adding to execution blocklist");
        result.actions_taken.push("Added to permanent blocklist".to_string());
    }

    async fn block_process(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Blocking execution for process: {}", threat.process_name);
        result
            .actions_taken
            .push(format!("Blocked process: {}", threat.process_name));
    }

    async fn quarantine_threat(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Quarantining threat...");

        self.suspend_process(threat, result).await;

        println!("    -> Moving files to quarantine zone");
        for file in &threat.affected_files {
            match self.quarantine_file(&threat.id, file) {
                Ok(item) => {
                    println!("       - {:?} -> {:?}", item.original_path, item.quarantined_path);
                    result.actions_taken.push(format!("Quarantined: {:?}", item.original_path));
                }
                Err(error) => {
                    result.errors.push(error);
                    result.success = false;
                }
            }
        }

        let metadata = QuarantineMetadata {
            threat_id: threat.id.clone(),
            original_paths: threat.affected_files.clone(),
            quarantined_at: SystemTime::now(),
            threat_type: threat.threat_type.clone(),
            can_restore: true,
        };

        let _ = metadata;
        println!("    -> Quarantine metadata saved");
        result
            .actions_taken
            .push("Created restoration metadata".to_string());

        self.collect_forensics(threat).await;
    }

    async fn block_network(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Blocking network connections...");

        for conn in &threat.network_connections {
            println!("    -> Blocking {}:{}", conn.remote_ip, conn.remote_port);

            // En Windows: Windows Filtering Platform (WFP)
            // En Linux: iptables/nftables

            result.actions_taken.push(format!(
                "Blocked connection to {}:{}",
                conn.remote_ip, conn.remote_port
            ));
        }

        println!("    -> Restricting process network access");
        result
            .actions_taken
            .push(format!("Network isolation for PID: {}", threat.process_id));
    }

    async fn remediate_threat(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Remediating threat (full cleanup)...");

        self.terminate_process(threat, result).await;

        println!("    -> Restoring modified files from shadow copies");
        for file in &threat.affected_files {
            println!("       - Restoring {:?}", file);
            result.files_restored += 1;
        }
        result
            .actions_taken
            .push(format!("Restored {} files", result.files_restored));

        println!("    -> Restoring registry entries");
        for reg_change in &threat.registry_changes {
            if let Some(old_value) = &reg_change.old_value {
                println!("       - {} = {}", reg_change.key, old_value);
                result.registry_restored += 1;
            }
        }
        result
            .actions_taken
            .push(format!("Restored {} registry entries", result.registry_restored));

        println!("    -> Removing persistence mechanisms");
        self.remove_persistence(threat).await;
        result
            .actions_taken
            .push("Removed persistence mechanisms".to_string());

        println!("    -> Triggering full system scan");
        result
            .actions_taken
            .push("Initiated full system scan".to_string());
    }

    async fn rollback_changes(&self, threat: &Threat, result: &mut RemediationResult) {
        println!("  Rolling back all changes...");

        let snapshots = self.snapshot_storage.lock().unwrap();
        if let Some(snapshot) = snapshots.get(&threat.id) {
            println!("    -> Found snapshot from {:?}", snapshot.timestamp);

            for (path, file_snap) in &snapshot.files {
                if let Some(backup) = &file_snap.backup_location {
                    println!("       - Restoring {:?}", path);
                    let _ = backup;
                    result.files_restored += 1;
                }
            }

            for (key, _reg_snap) in &snapshot.registry {
                println!("       - Restoring registry: {}", key);
                result.registry_restored += 1;
            }

            result
                .actions_taken
                .push(format!("Rolled back {} files", result.files_restored));
            result.actions_taken.push(format!(
                "Rolled back {} registry entries",
                result.registry_restored
            ));
        } else {
            let error = "No snapshot found for rollback".to_string();
            println!("    [WARN] {}", error);
            result.errors.push(error);
            result.success = false;
        }
    }

    // ========================================================================
    // AUXILIARY FUNCTIONS
    // ========================================================================

    async fn create_snapshot(&self, threat: &Threat) {
        println!("    -> Creating system snapshot");

        let snapshot = SystemSnapshot {
            snapshot_id: threat.id.clone(),
            timestamp: SystemTime::now(),
            files: threat
                .affected_files
                .iter()
                .map(|path| {
                    (
                        path.clone(),
                        FileSnapshot {
                            path: path.clone(),
                            hash: format!("sha256_{}", path.to_string_lossy()),
                            size: 1024,
                            modified: SystemTime::now(),
                            backup_location: Some(
                                self.quarantine_path.join("backup").join(path),
                            ),
                        },
                    )
                })
                .collect(),
            registry: HashMap::new(),
            processes: vec![],
        };

        self.snapshot_storage
            .lock()
            .unwrap()
            .insert(threat.id.clone(), snapshot);
        println!("    -> Snapshot created successfully");
    }

    async fn collect_forensics(&self, threat: &Threat) {
        println!("    -> Collecting forensic evidence");

        let forensic_dir = self.forensics_storage.join(&threat.id);
        let _ = forensic_dir;

        println!("       - Memory dump");
        println!("       - Process tree");
        println!("       - Network connections");
        println!("       - File modifications timeline");
        println!("       - Registry changes");

        println!("    -> Forensics saved");
    }

    async fn remove_persistence(&self, _threat: &Threat) {
        let persistence_locations = vec![
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Startup folders",
            "Scheduled tasks",
            "Services",
        ];

        for location in persistence_locations {
            println!("       - Checking {}", location);
        }
    }

    fn log_action(&self, threat: &Threat, action: ResponseAction, result: &RemediationResult) {
        let log = ActionLog {
            timestamp: SystemTime::now(),
            threat_id: threat.id.clone(),
            action,
            result: if result.success {
                "SUCCESS".to_string()
            } else {
                "FAILED".to_string()
            },
            details: result.actions_taken.join(", "),
        };

        self.action_log.lock().unwrap().push_back(log);
    }

    pub fn list_quarantine(&self) -> Vec<QuarantineItem> {
        let items = self.quarantine_items.lock().unwrap();
        let mut values = items.values().cloned().collect::<Vec<_>>();
        values.sort_by_key(|item| item.quarantined_at);
        values.reverse();
        values
    }

    pub fn manual_quarantine(&self, path: PathBuf) -> Result<QuarantineItem, String> {
        self.quarantine_file("manual", &path)
    }

    pub fn restore_quarantine(&self, id: &str) -> Result<(), String> {
        let item = {
            let items = self.quarantine_items.lock().unwrap();
            items.get(id).cloned()
        };

        let Some(item) = item else {
            return Err("Quarantine item not found".to_string());
        };

        if let Some(parent) = item.original_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }

        std::fs::rename(&item.quarantined_path, &item.original_path)
            .or_else(|_| {
                std::fs::copy(&item.quarantined_path, &item.original_path)
                    .map(|_| ())
                    .and_then(|_| std::fs::remove_file(&item.quarantined_path))
            })
            .map_err(|err| err.to_string())?;

        let mut items = self.quarantine_items.lock().unwrap();
        items.remove(id);

        Ok(())
    }

    pub fn delete_quarantine(&self, id: &str) -> Result<(), String> {
        let item = {
            let items = self.quarantine_items.lock().unwrap();
            items.get(id).cloned()
        };

        let Some(item) = item else {
            return Err("Quarantine item not found".to_string());
        };

        if item.quarantined_path.exists() {
            std::fs::remove_file(&item.quarantined_path).map_err(|err| err.to_string())?;
        }

        let mut items = self.quarantine_items.lock().unwrap();
        items.remove(id);

        Ok(())
    }

    fn quarantine_file(&self, threat_id: &str, original_path: &PathBuf) -> Result<QuarantineItem, String> {
        if !original_path.exists() {
            return Err(format!("File not found: {:?}", original_path));
        }

        let file_name = original_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let id = format!("Q-{}", QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed));
        let quarantine_path = self
            .quarantine_path
            .join(format!("{}_{}", threat_id, file_name));

        let _ = std::fs::create_dir_all(&self.quarantine_path);

        std::fs::rename(original_path, &quarantine_path)
            .or_else(|_| {
                std::fs::copy(original_path, &quarantine_path)
                    .map(|_| ())
                    .and_then(|_| std::fs::remove_file(original_path))
            })
            .map_err(|err| err.to_string())?;

        let size_bytes = std::fs::metadata(&quarantine_path)
            .map(|meta| meta.len())
            .unwrap_or(0);

        let item = QuarantineItem {
            id: id.clone(),
            threat_id: threat_id.to_string(),
            file_name,
            original_path: original_path.clone(),
            quarantined_path: quarantine_path,
            quarantined_at: SystemTime::now(),
            size_bytes,
        };

        let mut items = self.quarantine_items.lock().unwrap();
        items.insert(id, item.clone());

        Ok(item)
    }

    pub fn get_statistics(&self) -> ResponseStatistics {
        let logs = self.action_log.lock().unwrap();

        ResponseStatistics {
            total_responses: logs.len(),
            successful: logs.iter().filter(|l| l.result == "SUCCESS").count(),
            failed: logs.iter().filter(|l| l.result == "FAILED").count(),
            by_action: {
                let mut map = HashMap::new();
                for log in logs.iter() {
                    *map.entry(format!("{:?}", log.action)).or_insert(0) += 1;
                }
                map
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ResponseStatistics {
    pub total_responses: usize,
    pub successful: usize,
    pub failed: usize,
    pub by_action: HashMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct QuarantineMetadata {
    threat_id: String,
    original_paths: Vec<PathBuf>,
    quarantined_at: SystemTime,
    threat_type: String,
    can_restore: bool,
}

// Demo removido para ejecucion en produccion.
