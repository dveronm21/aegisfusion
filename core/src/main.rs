// AEGIS FUSION - Core Engine
// Arquitectura principal del motor de analisis

mod config;
mod device_monitor;
mod http;
mod ipc;
mod response;
mod scan;
mod service;
mod telemetry;
mod types;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use config::{matches_exclusion, CoreConfig};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use crate::http::ApiState;
use crate::ipc::cloud_sync::CloudSync;
use crate::ipc::kernel_comm::KernelComm;
use crate::response::{ResponseEngine, ResponseStatistics};
use crate::scan::{ScanManager, ScanRuntimeConfig};
use crate::telemetry::TelemetryStore;
use crate::types::{
    EventDetails, EventType, NetworkConnection, RegistryChange, ResponseAction, SystemEvent,
    Threat, ThreatSeverity, ThreatType, ThreatVerdict,
};

// ============================================================================
// BEHAVIOR GRAPH - Analisis de relaciones
// ============================================================================

#[derive(Debug)]
pub struct BehaviorNode {
    pub id: String,
    pub node_type: NodeType,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub reputation_score: f32,
    pub connections: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum NodeType {
    Process,
    File,
    Network,
    Registry,
}

pub struct BehaviorGraph {
    nodes: HashMap<String, BehaviorNode>,
    edges: Vec<(String, String, String)>, // (from, to, action)
}

impl BehaviorGraph {
    pub fn new() -> Self {
        BehaviorGraph {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, id: String, node_type: NodeType) {
        let node = BehaviorNode {
            id: id.clone(),
            node_type,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            reputation_score: 0.5,
            connections: Vec::new(),
        };
        self.nodes.insert(id, node);
    }

    pub fn add_edge(&mut self, from: String, to: String, action: String) {
        self.edges.push((from.clone(), to.clone(), action));

        if let Some(node) = self.nodes.get_mut(&from) {
            node.connections.push(to.clone());
        }
    }

    pub fn detect_anomalies(&self) -> Vec<String> {
        let mut anomalies = Vec::new();

        // Detectar procesos con demasiadas conexiones (comportamiento de C2)
        for (id, node) in &self.nodes {
            if node.connections.len() > 50 {
                anomalies.push(format!(
                    "Process {} has {} connections (potential C2)",
                    id,
                    node.connections.len()
                ));
            }
        }

        // Detectar cadenas sospechosas: proceso -> archivo -> proceso
        for (from, to, action) in &self.edges {
            if action == "created" || action == "modified" {
                if let (Some(from_node), Some(to_node)) =
                    (self.nodes.get(from), self.nodes.get(to))
                {
                    if matches!(from_node.node_type, NodeType::Process)
                        && matches!(to_node.node_type, NodeType::File)
                    {
                        anomalies.push(format!(
                            "Suspicious file creation chain: {} -> {}",
                            from, to
                        ));
                    }
                }
            }
        }

        anomalies
    }
}

// ============================================================================
// INTELLIGENT ANALYSIS ENGINE
// ============================================================================

pub struct AnalysisEngine {
    event_tx: mpsc::Sender<SystemEvent>,
    event_rx: Arc<Mutex<mpsc::Receiver<SystemEvent>>>,
    behavior_graph: Arc<Mutex<BehaviorGraph>>,
    ml_cache: Arc<RwLock<HashMap<String, ThreatVerdict>>>,
    whitelist: Arc<RwLock<Vec<String>>>,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(1024);

        AnalysisEngine {
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            behavior_graph: Arc::new(Mutex::new(BehaviorGraph::new())),
            ml_cache: Arc::new(RwLock::new(HashMap::new())),
            whitelist: Arc::new(RwLock::new(vec![
                "explorer.exe".to_string(),
                "svchost.exe".to_string(),
                "System".to_string(),
            ])),
        }
    }

    pub async fn enqueue_event(&self, event: SystemEvent) {
        if let Err(error) = self.event_tx.send(event).await {
            eprintln!("[AEGIS] Failed to enqueue event: {:?}", error);
        }
    }

    pub async fn analyze_event(&self, event: &SystemEvent) -> ThreatVerdict {
        let whitelisted = self.is_whitelisted(&event.process_name).await;

        if whitelisted {
            return ThreatVerdict {
                is_malicious: false,
                confidence: 1.0,
                threat_type: ThreatType::Benign,
                reasons: vec!["Process is whitelisted".to_string()],
                recommended_action: ResponseAction::Allow,
            };
        }

        let cache_key = self.get_cache_key(event);
        if let Some(cached) = {
            let cache = self.ml_cache.read().await;
            cache.get(&cache_key).cloned()
        } {
            return cached;
        }

        let heuristic_score = self.heuristic_analysis(event, whitelisted);
        let behavior_score = self.behavior_analysis(event).await;
        let final_score = (heuristic_score * 0.4) + (behavior_score * 0.6);

        let verdict = self.generate_verdict(final_score, event);

        self.ml_cache
            .write()
            .await
            .insert(cache_key, verdict.clone());

        verdict
    }

    async fn is_whitelisted(&self, process_name: &str) -> bool {
        let whitelist = self.whitelist.read().await;
        whitelist
            .iter()
            .any(|p| p.eq_ignore_ascii_case(process_name))
    }

    fn get_cache_key(&self, event: &SystemEvent) -> String {
        format!("{:?}_{}", event.event_type, event.process_name)
    }

    fn heuristic_analysis(&self, event: &SystemEvent, is_whitelisted: bool) -> f32 {
        let mut score: f32 = 0.0;

        match &event.details {
            EventDetails::FileOp { path, .. } => {
                // Archivos en System32 por procesos no privilegiados
                if path.contains("System32") && event.process_id > 1000 {
                    score += 0.3;
                }
                // Archivos ocultos o con doble extension
                if path.contains(".exe.") || path.starts_with('.') {
                    score += 0.4;
                }
                // Modificacion de archivos criticos
                if path.contains("hosts") || path.contains("boot.ini") {
                    score += 0.5;
                }
            }
            EventDetails::ProcessOp { command_line, .. } => {
                // Comandos sospechosos
                let suspicious_commands = [
                    "powershell -enc",
                    "cmd /c",
                    "certutil -decode",
                    "bitsadmin",
                    "reg add",
                    "schtasks /create",
                ];
                for cmd in &suspicious_commands {
                    if command_line.contains(cmd) {
                        score += 0.3;
                    }
                }
            }
            EventDetails::NetworkOp {
                remote_ip,
                remote_port,
                ..
            } => {
                // Conexiones a puertos sospechosos
                let suspicious_ports: [u16; 5] = [4444, 5555, 6666, 8081, 31337];
                if suspicious_ports.contains(&remote_port) {
                    score += 0.4;
                }
                // IPs privadas desde procesos no sistema
                if remote_ip.starts_with("10.") || remote_ip.starts_with("192.168.") {
                    if !is_whitelisted {
                        score += 0.2;
                    }
                }
            }
            EventDetails::MemoryOp { protection, .. } => {
                // RWX memory (read-write-execute) es sospechoso
                if protection & 0x40 != 0 {
                    score += 0.5;
                }
            }
            _ => {}
        }

        score.min(1.0)
    }

    async fn behavior_analysis(&self, event: &SystemEvent) -> f32 {
        let mut graph = self.behavior_graph.lock().await;

        // Agregar al grafo
        let node_id = format!("{}_{}", event.process_name, event.process_id);
        graph.add_node(node_id.clone(), NodeType::Process);

        match &event.details {
            EventDetails::FileOp { path, .. } => {
                let file_id = path.clone();
                graph.add_node(file_id.clone(), NodeType::File);
                graph.add_edge(node_id, file_id, "modified".to_string());
            }
            EventDetails::NetworkOp { remote_ip, .. } => {
                let net_id = remote_ip.clone();
                graph.add_node(net_id.clone(), NodeType::Network);
                graph.add_edge(node_id, net_id, "connected".to_string());
            }
            _ => {}
        }

        // Detectar anomalias en el grafo
        let anomalies = graph.detect_anomalies();

        let score = if anomalies.is_empty() {
            0.0
        } else {
            0.3 * anomalies.len() as f32
        };

        score.min(1.0)
    }

    fn generate_verdict(&self, score: f32, event: &SystemEvent) -> ThreatVerdict {
        let (is_malicious, confidence, threat_type, action) = match score {
            s if s < 0.3 => (false, 1.0 - s, ThreatType::Benign, ResponseAction::Allow),
            s if s < 0.6 => (false, s, ThreatType::PUP, ResponseAction::Monitor),
            s if s < 0.8 => (true, s, ThreatType::Unknown, ResponseAction::Quarantine),
            s => (true, s, ThreatType::Trojan, ResponseAction::Terminate),
        };

        let mut reasons = Vec::new();
        if score > 0.3 {
            reasons.push(format!("Suspicious behavior score: {:.2}", score));
        }
        if matches!(event.event_type, EventType::DllInjection) {
            reasons.push("DLL injection detected".to_string());
        }

        ThreatVerdict {
            is_malicious,
            confidence,
            threat_type,
            reasons,
            recommended_action: action,
        }
    }

    pub async fn process_queue(&self) -> Vec<(SystemEvent, ThreatVerdict)> {
        let mut events = Vec::new();

        {
            let mut receiver = self.event_rx.lock().await;
            while let Ok(event) = receiver.try_recv() {
                events.push(event);
            }
        }

        let mut verdicts = Vec::new();
        for evt in events {
            let verdict = self.analyze_event(&evt).await;
            if verdict.is_malicious {
                verdicts.push((evt, verdict));
            }
        }

        verdicts
    }
}

// ============================================================================
// AEGIS FUSION MAIN ENGINE
// ============================================================================

pub struct AegisFusion {
    analysis_engine: Arc<AnalysisEngine>,
    response_engine: Arc<ResponseEngine>,
    telemetry: Arc<TelemetryStore>,
    scan_manager: Arc<ScanManager>,
    kernel_comm: KernelComm,
    cloud_sync: CloudSync,
    running: Arc<RwLock<bool>>,
    config: Arc<RwLock<CoreConfig>>,
}

impl AegisFusion {
    pub fn new(
        config: Arc<RwLock<CoreConfig>>,
        telemetry: Arc<TelemetryStore>,
        response_engine: Arc<ResponseEngine>,
        scan_manager: Arc<ScanManager>,
    ) -> Self {
        println!("==========================================");
        println!("=     AEGIS FUSION - INITIALIZING        =");
        println!("=   Next-Generation Threat Protection    =");
        println!("==========================================\n");

        AegisFusion {
            analysis_engine: Arc::new(AnalysisEngine::new()),
            response_engine,
            telemetry,
            scan_manager,
            kernel_comm: KernelComm::new(),
            cloud_sync: CloudSync::new(),
            running: Arc::new(RwLock::new(false)),
            config,
        }
    }

    pub async fn start(&self) {
        *self.running.write().await = true;

        println!("[OK] Kernel Monitor: ACTIVE");
        println!("[OK] Behavior Graph: INITIALIZED");
        println!("[OK] ML Engine: READY");
        println!("[OK] Response System: ARMED\n");
        println!("===========================================\n");

        self.monitoring_loop().await;
    }

    async fn monitoring_loop(&self) {
        loop {
            if !*self.running.read().await {
                break;
            }

            let (tick_interval, log_kernel_events, log_kernel_filter, scan_config) = {
                let config = self.config.read().await;
                (
                    config.tick_interval,
                    config.log_kernel_events,
                    config.log_kernel_filter.clone(),
                    ScanRuntimeConfig::from_config(&config),
                )
            };

            let kernel_events = self.kernel_comm.poll_events().await;
            let exclude_programs = scan_config.exclude_programs.clone();
            let firewall_enabled = scan_config.firewall_enabled;
            if log_kernel_events && !kernel_events.is_empty() {
                println!("[KERNEL] Received {} event(s)", kernel_events.len());
                for event in &kernel_events {
                    if event_is_excluded(&exclude_programs, event) {
                        continue;
                    }
                    if !should_log_kernel_event(&log_kernel_filter, &event.event_type) {
                        continue;
                    }
                    let detail = match &event.details {
                        EventDetails::FileOp { path, .. } => path.clone(),
                        EventDetails::ProcessOp { command_line, .. } => command_line.clone(),
                        EventDetails::RegistryOp { key, .. } => key.clone(),
                        _ => String::new(),
                    };
                    println!(
                        "[KERNEL] {:?} pid={} proc={} {}",
                        event.event_type,
                        event.process_id,
                        event.process_name,
                        detail
                    );
                }
            }
            for event in kernel_events {
                if event_is_excluded(&exclude_programs, &event) {
                    continue;
                }
                if matches!(event.event_type, EventType::FileCreated | EventType::FileModified) {
                    if let EventDetails::FileOp { path, .. } = &event.details {
                        if !path.is_empty() {
                            self.scan_manager.spawn_event_scan(
                                PathBuf::from(path),
                                event.event_type.clone(),
                                scan_config.clone(),
                            );
                        }
                    }
                }

                if let Err(error) = self.cloud_sync.push_event(&event).await {
                    eprintln!("[CLOUD] Failed to push event: {}", error);
                }
                self.analysis_engine.enqueue_event(event).await;
            }

            let verdicts = self.analysis_engine.process_queue().await;

            for (event, verdict) in verdicts {
                let threat = build_threat(&event, &verdict);
                let action = self.response_engine.decide_response(&threat);
                let action = apply_firewall_policy(action, firewall_enabled);
                let result = self.response_engine.execute_response(&threat, action.clone()).await;

                self.telemetry.record_action(action.clone()).await;
                self.telemetry.record_threat(&threat, action).await;

                if !result.success {
                    eprintln!(
                        "[RESP] Remediation failed for {}: {:?}",
                        threat.id, result.errors
                    );
                }
            }

            tokio::time::sleep(tick_interval).await;
        }
    }

    pub fn response_stats(&self) -> ResponseStatistics {
        self.response_engine.get_statistics()
    }

    pub async fn stop(&self) {
        *self.running.write().await = false;
        println!("\n[AEGIS] Shutting down gracefully...");
    }
}

fn should_log_kernel_event(filter: &str, event_type: &EventType) -> bool {
    match filter {
        "file" => matches!(
            event_type,
            EventType::FileCreated | EventType::FileModified | EventType::FileDeleted
        ),
        "process" => matches!(
            event_type,
            EventType::ProcessStarted | EventType::ProcessTerminated
        ),
        "registry" => matches!(event_type, EventType::RegistryModified),
        _ => true,
    }
}

fn event_is_excluded(exclusions: &[String], event: &SystemEvent) -> bool {
    if exclusions.is_empty() {
        return false;
    }

    let path = match &event.details {
        EventDetails::FileOp { path, .. } => Some(PathBuf::from(path)),
        EventDetails::ProcessOp { command_line, .. } => command_line_path(command_line),
        _ => None,
    };

    matches_exclusion(exclusions, &event.process_name, path.as_deref())
}

fn command_line_path(command_line: &str) -> Option<PathBuf> {
    let trimmed = command_line.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(stripped) = trimmed.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            let candidate = &stripped[..end];
            if !candidate.is_empty() {
                return Some(PathBuf::from(candidate));
            }
        }
    }

    trimmed.split_whitespace().next().map(PathBuf::from)
}

fn apply_firewall_policy(action: ResponseAction, firewall_enabled: bool) -> ResponseAction {
    if !firewall_enabled && matches!(action, ResponseAction::BlockNetwork) {
        ResponseAction::Monitor
    } else {
        action
    }
}

// ============================================================================
// EJECUCION
// ============================================================================

fn main() {
    let _ = env_logger::try_init();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--service") {
        if let Err(error) = service::run_service() {
            eprintln!("[SERVICE] {}", error);
        }
        return;
    }

    if let Err(error) = run_console() {
        eprintln!("[AEGIS] {}", error);
    }
}

fn run_console() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            if let Err(error) = tokio::signal::ctrl_c().await {
                eprintln!("[AEGIS] Failed to listen for shutdown: {}", error);
            }
            let _ = shutdown_tx.send(());
        });

        let stats = run_until_shutdown(shutdown_rx).await;
        println!(
            "[RESP] Stats: total={}, ok={}, failed={}",
            stats.total_responses, stats.successful, stats.failed
        );
    });

    Ok(())
}

pub async fn run_until_shutdown(
    shutdown_rx: oneshot::Receiver<()>,
) -> ResponseStatistics {
    let config = Arc::new(RwLock::new(CoreConfig::from_env()));
    let telemetry = Arc::new(TelemetryStore::new());
    let response_engine = Arc::new(ResponseEngine::new());
    let scan_manager = Arc::new(ScanManager::new(
        Arc::clone(&telemetry),
        Arc::clone(&response_engine),
    ));
    let aegis = Arc::new(AegisFusion::new(
        Arc::clone(&config),
        Arc::clone(&telemetry),
        Arc::clone(&response_engine),
        Arc::clone(&scan_manager),
    ));

    let device_handle = {
        let config = Arc::clone(&config);
        let scan_manager = Arc::clone(&scan_manager);
        tokio::spawn(async move {
            crate::device_monitor::run_device_monitor(config, scan_manager).await;
        })
    };

    let runner = {
        let aegis = Arc::clone(&aegis);
        tokio::spawn(async move {
            aegis.start().await;
        })
    };

    let api_addr =
        std::env::var("AEGIS_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".to_string());
    let api_state = ApiState {
        telemetry,
        scan_manager,
        response_engine,
        config,
    };
    let api_handle = tokio::spawn(async move {
        if let Err(error) = crate::http::serve(api_addr, api_state).await {
            eprintln!("[API] Server error: {}", error);
        }
    });

    let _ = shutdown_rx.await;

    aegis.stop().await;
    let _ = runner.await;
    api_handle.abort();
    device_handle.abort();

    aegis.response_stats()
}

fn build_threat(event: &SystemEvent, verdict: &ThreatVerdict) -> Threat {
    let mut affected_files = Vec::new();
    let mut network_connections = Vec::new();
    let mut registry_changes = Vec::new();
    let mut indicators = verdict.reasons.clone();

    let mut parent_process_id = 0u32;
    let mut process_path = PathBuf::from(&event.process_name);

    match &event.details {
        EventDetails::FileOp { path, hash } => {
            affected_files.push(PathBuf::from(path));
            if let Some(hash) = hash {
                indicators.push(format!("File hash: {}", hash));
            }
        }
        EventDetails::ProcessOp {
            parent_pid,
            command_line,
        } => {
            parent_process_id = *parent_pid;
            indicators.push(format!("Command line: {}", command_line));
        }
        EventDetails::NetworkOp {
            remote_ip,
            remote_port,
            protocol,
        } => {
            network_connections.push(NetworkConnection {
                remote_ip: remote_ip.clone(),
                remote_port: *remote_port,
                protocol: protocol.clone(),
                established_at: event.timestamp,
            });
        }
        EventDetails::RegistryOp { key, value } => {
            registry_changes.push(RegistryChange {
                key: key.clone(),
                value_name: "default".to_string(),
                old_value: None,
                new_value: value.clone(),
                timestamp: event.timestamp,
            });
        }
        EventDetails::MemoryOp {
            address,
            size,
            protection,
        } => {
            indicators.push(format!(
                "Memory op at 0x{:x} size {}",
                address, size
            ));
            if protection & 0x40 != 0 {
                indicators.push("RWX memory allocation".to_string());
            }
        }
    }

    if let EventDetails::ProcessOp { command_line, .. } = &event.details {
        if let Some((first, _)) = command_line.split_once(' ') {
            process_path = PathBuf::from(first);
        }
    }

    Threat {
        id: format!("EVT-{}", event.id),
        threat_type: format!("{:?}", verdict.threat_type),
        severity: map_severity(verdict),
        confidence: verdict.confidence,
        process_id: event.process_id,
        process_name: event.process_name.clone(),
        process_path,
        parent_process_id,
        affected_files,
        network_connections,
        registry_changes,
        detection_time: event.timestamp,
        indicators,
    }
}

fn map_severity(verdict: &ThreatVerdict) -> ThreatSeverity {
    let mut severity = if verdict.confidence >= 0.9 {
        ThreatSeverity::Critical
    } else if verdict.confidence >= 0.75 {
        ThreatSeverity::High
    } else if verdict.confidence >= 0.5 {
        ThreatSeverity::Medium
    } else {
        ThreatSeverity::Low
    };

    match verdict.threat_type {
        ThreatType::Ransomware | ThreatType::Rootkit => {
            severity = match severity {
                ThreatSeverity::Low => ThreatSeverity::Medium,
                ThreatSeverity::Medium => ThreatSeverity::High,
                ThreatSeverity::High | ThreatSeverity::Critical => ThreatSeverity::Critical,
            };
        }
        _ => {}
    }

    severity
}
