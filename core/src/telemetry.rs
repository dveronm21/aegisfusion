use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sysinfo::{Disks, Networks, System};
use tokio::sync::Mutex;

use crate::types::{ResponseAction, Threat, ThreatSeverity};

#[derive(Debug, Clone, Serialize)]
pub struct ApiThreat {
    pub id: String,
    pub timestamp: u64,
    pub name: String,
    pub file: String,
    pub action: String,
    pub confidence: f32,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub scanned: u64,
    pub blocked: u64,
    pub quarantined: u64,
    pub uptime: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemHealth {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub memory_percent: f32,
    pub disk_used_percent: f32,
    pub network_kbps: f32,
}

#[derive(Debug, Default)]
struct StatsCounters {
    scanned: u64,
    blocked: u64,
    quarantined: u64,
}

struct NetSample {
    last_bytes: u64,
    last_checked: SystemTime,
}

pub struct TelemetryStore {
    start_time: SystemTime,
    stats: Mutex<StatsCounters>,
    threats: Mutex<VecDeque<ApiThreat>>,
    system: Mutex<System>,
    networks: Mutex<Networks>,
    disks: Mutex<Disks>,
    net_sample: Mutex<NetSample>,
}

impl TelemetryStore {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        let networks = Networks::new_with_refreshed_list();
        let disks = Disks::new_with_refreshed_list();

        TelemetryStore {
            start_time: SystemTime::now(),
            stats: Mutex::new(StatsCounters::default()),
            threats: Mutex::new(VecDeque::with_capacity(64)),
            system: Mutex::new(system),
            networks: Mutex::new(networks),
            disks: Mutex::new(disks),
            net_sample: Mutex::new(NetSample {
                last_bytes: 0,
                last_checked: SystemTime::now(),
            }),
        }
    }

    pub async fn snapshot_stats(&self) -> StatsSnapshot {
        let stats = self.stats.lock().await;
        StatsSnapshot {
            scanned: stats.scanned,
            blocked: stats.blocked,
            quarantined: stats.quarantined,
            uptime: format_uptime(
                SystemTime::now()
                    .duration_since(self.start_time)
                    .unwrap_or(Duration::from_secs(0)),
            ),
        }
    }

    pub async fn snapshot_threats(&self) -> Vec<ApiThreat> {
        let threats = self.threats.lock().await;
        threats.iter().cloned().collect()
    }

    pub async fn health_snapshot(&self) -> SystemHealth {
        let mut system = self.system.lock().await;
        system.refresh_cpu();
        system.refresh_memory();
        let cpu_percent = system.global_cpu_info().cpu_usage();
        let total_mem_kb = system.total_memory();
        let used_mem_kb = system.used_memory();
        let memory_percent = if total_mem_kb > 0 {
            (used_mem_kb as f32 / total_mem_kb as f32) * 100.0
        } else {
            0.0
        };

        drop(system);

        let mut disks = self.disks.lock().await;
        disks.refresh();
        let mut total_space = 0u64;
        let mut available_space = 0u64;
        for disk in disks.list() {
            total_space = total_space.saturating_add(disk.total_space());
            available_space = available_space.saturating_add(disk.available_space());
        }

        let disk_used_percent = if total_space > 0 {
            ((total_space - available_space) as f32 / total_space as f32) * 100.0
        } else {
            0.0
        };

        drop(disks);

        let mut networks = self.networks.lock().await;
        networks.refresh();
        let mut total_bytes = 0u64;
        for (_name, data) in networks.iter() {
            total_bytes = total_bytes.saturating_add(data.total_received());
            total_bytes = total_bytes.saturating_add(data.total_transmitted());
        }
        drop(networks);

        let mut net_sample = self.net_sample.lock().await;
        let now = SystemTime::now();
        let elapsed = now
            .duration_since(net_sample.last_checked)
            .unwrap_or(Duration::from_secs(1));
        let delta_bytes = total_bytes.saturating_sub(net_sample.last_bytes);
        net_sample.last_bytes = total_bytes;
        net_sample.last_checked = now;

        let network_kbps = if elapsed.as_secs_f32() > 0.0 {
            (delta_bytes as f32 / 1024.0) / elapsed.as_secs_f32()
        } else {
            0.0
        };

        SystemHealth {
            cpu_percent,
            memory_mb: used_mem_kb / 1024,
            memory_percent,
            disk_used_percent,
            network_kbps,
        }
    }

    pub async fn record_scan(&self, scanned: u64) {
        let mut stats = self.stats.lock().await;
        stats.scanned = stats.scanned.saturating_add(scanned);
    }

    pub fn record_scan_blocking(&self, scanned: u64) {
        let mut stats = self.stats.blocking_lock();
        stats.scanned = stats.scanned.saturating_add(scanned);
    }

    pub async fn record_threat(&self, threat: &Threat, action: ResponseAction) {
        self.record_threat_entry(ApiThreat {
            id: threat.id.clone(),
            timestamp: to_epoch_seconds(threat.detection_time),
            name: threat.threat_type.clone(),
            file: threat
                .affected_files
                .first()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_else(|| threat.process_name.clone()),
            action: action_label(&action).to_string(),
            confidence: threat.confidence,
            severity: severity_label(&threat.severity).to_string(),
        })
        .await;
    }

    pub fn record_threat_entry_blocking(&self, entry: ApiThreat) {
        let mut threats = self.threats.blocking_lock();
        threats.push_front(entry);
        while threats.len() > 50 {
            threats.pop_back();
        }
    }

    pub async fn record_threat_entry(&self, entry: ApiThreat) {
        let mut threats = self.threats.lock().await;
        threats.push_front(entry);
        while threats.len() > 50 {
            threats.pop_back();
        }
    }

    pub async fn update_threat_action(&self, threat_id: &str, action: &str) -> bool {
        let mut threats = self.threats.lock().await;
        if let Some(entry) = threats.iter_mut().find(|entry| entry.id == threat_id) {
            entry.action = action.to_string();
            return true;
        }
        false
    }

    pub async fn record_action(&self, action: ResponseAction) {
        let mut stats = self.stats.lock().await;
        match action {
            ResponseAction::Quarantine => {
                stats.quarantined = stats.quarantined.saturating_add(1);
            }
            ResponseAction::Terminate | ResponseAction::Block | ResponseAction::BlockNetwork => {
                stats.blocked = stats.blocked.saturating_add(1);
            }
            _ => {}
        }
    }

    pub fn record_action_blocking(&self, action: ResponseAction) {
        let mut stats = self.stats.blocking_lock();
        match action {
            ResponseAction::Quarantine => {
                stats.quarantined = stats.quarantined.saturating_add(1);
            }
            ResponseAction::Terminate | ResponseAction::Block | ResponseAction::BlockNetwork => {
                stats.blocked = stats.blocked.saturating_add(1);
            }
            _ => {}
        }
    }
}

pub fn system_status_from_threats(threats: &[ApiThreat]) -> String {
    if threats.iter().any(|threat| threat.severity == "critical") {
        "critical".to_string()
    } else if threats.iter().any(|threat| threat.severity == "high") {
        "warning".to_string()
    } else {
        "protected".to_string()
    }
}

fn to_epoch_seconds(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn action_label(action: &ResponseAction) -> &'static str {
    match action {
        ResponseAction::Allow => "Allowed",
        ResponseAction::Monitor => "Monitored",
        ResponseAction::Suspend => "Suspended",
        ResponseAction::Terminate => "Terminated",
        ResponseAction::Quarantine => "Quarantined",
        ResponseAction::Block => "Blocked",
        ResponseAction::BlockNetwork => "Network Blocked",
        ResponseAction::Remediate => "Remediated",
        ResponseAction::Rollback => "Rolled Back",
    }
}

fn severity_label(severity: &ThreatSeverity) -> &'static str {
    match severity {
        ThreatSeverity::Low => "low",
        ThreatSeverity::Medium => "medium",
        ThreatSeverity::High => "high",
        ThreatSeverity::Critical => "critical",
    }
}

fn format_uptime(duration: Duration) -> String {
    let total_minutes = duration.as_secs() / 60;
    let days = total_minutes / (24 * 60);
    let hours = (total_minutes / 60) % 24;
    let minutes = total_minutes % 60;
    format!("{}d {}h {}m", days, hours, minutes)
}
