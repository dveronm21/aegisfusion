use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock as StdRwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};
use walkdir::{DirEntry, WalkDir};
use yara_x::{Compiler, Rules, Scanner, SourceCode};
use zip::ZipArchive;

use crate::config::{matches_exclusion, CoreConfig};
use crate::response::ResponseEngine;
use crate::telemetry::{ApiThreat, TelemetryStore};
use crate::types::{EventType, ResponseAction, Threat, ThreatSeverity};

const MAX_QUICK_FILE_BYTES: u64 = 20 * 1024 * 1024;
const MAX_FULL_FILE_BYTES: u64 = 50 * 1024 * 1024;
const MAX_EICAR_BYTES: usize = 4 * 1024;
const MAX_ML_INDICATORS: usize = 8;
const EICAR_TEST_BYTES: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

static SCAN_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize)]
pub enum ScanMode {
    Quick,
    Full,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub mode: ScanMode,
    pub status: ScanStatus,
    pub scanned_files: u64,
    pub threats_found: u64,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanRuntimeConfig {
    pub ai_enabled: bool,
    pub firewall_enabled: bool,
    pub exclude_programs: Vec<String>,
    pub yara_enabled: bool,
    pub yara_rules_path: String,
    pub yara_max_bytes: u64,
    pub ml_model_path: String,
    pub ml_score_threshold: f32,
    pub ml_max_bytes: u64,
    pub archive_scan_enabled: bool,
    pub archive_max_bytes: u64,
    pub archive_max_entries: u64,
    pub archive_entry_max_bytes: u64,
    pub external_scan_enabled: bool,
    pub external_scan_mode: String,
    pub external_scan_max_bytes: u64,
}

impl ScanRuntimeConfig {
    pub fn from_config(config: &CoreConfig) -> Self {
        Self {
            ai_enabled: config.ai_scan_enabled,
            firewall_enabled: config.firewall_enabled,
            exclude_programs: config.exclude_programs.clone(),
            yara_enabled: config.yara_enabled,
            yara_rules_path: config.yara_rules_path.clone(),
            yara_max_bytes: config.yara_max_bytes,
            ml_model_path: config.ml_model_path.clone(),
            ml_score_threshold: config.ml_score_threshold,
            ml_max_bytes: config.ml_max_bytes,
            archive_scan_enabled: config.archive_scan_enabled,
            archive_max_bytes: config.archive_max_bytes,
            archive_max_entries: config.archive_max_entries,
            archive_entry_max_bytes: config.archive_entry_max_bytes,
            external_scan_enabled: config.external_scan_enabled,
            external_scan_mode: config.external_scan_mode.clone(),
            external_scan_max_bytes: config.external_scan_max_bytes,
        }
    }
}

#[derive(Debug)]
struct YaraEngine {
    rules_path: PathBuf,
    rules: Option<Arc<Rules>>,
    last_error: Option<String>,
}

impl YaraEngine {
    fn new(rules_path: PathBuf) -> Self {
        let mut engine = Self {
            rules_path,
            rules: None,
            last_error: None,
        };
        engine.reload_rules();
        engine
    }

    fn update_rules_path(&mut self, rules_path: PathBuf) {
        if self.rules_path != rules_path {
            self.rules_path = rules_path;
            self.reload_rules();
        }
    }

    fn reload_rules(&mut self) {
        self.rules = None;
        self.last_error = None;

        if !self.rules_path.exists() {
            self.last_error = Some("YARA rules path not found".to_string());
            return;
        }

        let mut compiler = Compiler::new();
        compiler.enable_includes(true);
        compiler.add_include_dir(&self.rules_path);

        let mut loaded = false;
        let entries = match std::fs::read_dir(&self.rules_path) {
            Ok(entries) => entries,
            Err(err) => {
                self.last_error = Some(format!("YARA rules read error: {}", err));
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext != "yar" && ext != "yara" {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => {
                    self.last_error =
                        Some(format!("YARA rules read error: {}", err));
                    continue;
                }
            };

            let origin = path.to_string_lossy().to_string();
            if compiler
                .add_source(SourceCode::from(content.as_str()).with_origin(origin))
                .is_ok()
            {
                loaded = true;
            } else {
                self.last_error = Some("YARA rules compile error".to_string());
            }
        }

        if loaded {
            let rules = compiler.build();
            self.rules = Some(Arc::new(rules));
        } else if self.last_error.is_none() {
            self.last_error = Some("No YARA rules loaded".to_string());
        }
    }

    fn scan_file(&self, path: &Path) -> Vec<String> {
        let rules = match &self.rules {
            Some(rules) => Arc::clone(rules),
            None => return Vec::new(),
        };

        let mut scanner = Scanner::new(rules.as_ref());
        match scanner.scan_file(path) {
            Ok(results) => results
                .matching_rules()
                .map(|rule| rule.identifier().to_string())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        let rules = match &self.rules {
            Some(rules) => Arc::clone(rules),
            None => return Vec::new(),
        };

        let mut scanner = Scanner::new(rules.as_ref());
        match scanner.scan(data) {
            Ok(results) => results
                .matching_rules()
                .map(|rule| rule.identifier().to_string())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct MlWeights {
    bias: f32,
    weights: HashMap<String, f32>,
}

#[derive(Debug)]
struct MlEngine {
    model_path: PathBuf,
    weights: Option<MlWeights>,
    last_error: Option<String>,
}

impl MlEngine {
    fn new(model_path: PathBuf) -> Self {
        let mut engine = Self {
            model_path,
            weights: None,
            last_error: None,
        };
        engine.reload_model();
        engine
    }

    fn update_model_path(&mut self, model_path: PathBuf) {
        if self.model_path != model_path {
            self.model_path = model_path;
            self.reload_model();
        }
    }

    fn reload_model(&mut self) {
        self.weights = None;
        self.last_error = None;

        if !self.model_path.exists() {
            self.last_error = Some("ML model not found".to_string());
            return;
        }

        if self.model_path.is_dir() {
            self.last_error = Some("ML model path must be a file".to_string());
            return;
        }

        let data = match std::fs::read(&self.model_path) {
            Ok(data) => data,
            Err(err) => {
                self.last_error = Some(format!("ML model read error: {}", err));
                return;
            }
        };

        match serde_json::from_slice::<MlWeights>(&data) {
            Ok(weights) => {
                if weights.weights.is_empty() {
                    self.last_error = Some("ML model has no weights".to_string());
                } else {
                    self.weights = Some(weights);
                }
            }
            Err(err) => {
                self.last_error = Some(format!("ML model parse error: {}", err));
            }
        }
    }

    fn score(&self, features: &HashMap<String, f32>) -> Option<f32> {
        let weights = self.weights.as_ref()?;
        let mut total = weights.bias;
        for (name, value) in features {
            if let Some(weight) = weights.weights.get(name) {
                total += weight * value;
            }
        }
        Some(sigmoid(total))
    }
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}

#[derive(Debug, Clone)]
struct ExternalScanner {
    defender_path: Option<PathBuf>,
    clamav_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ExternalScanResult {
    engine: String,
    signature: Option<String>,
}

#[derive(Debug)]
enum ExternalScanOutcome {
    Clean,
    Infected(ExternalScanResult),
    Unavailable,
    Error(String),
}

impl ExternalScanner {
    fn new() -> Self {
        Self {
            defender_path: find_defender_path(),
            clamav_path: find_clamav_path(),
        }
    }

    fn scan(&self, path: &Path, mode: &str) -> ExternalScanOutcome {
        let normalized = mode.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "defender" => self.scan_defender(path),
            "clamav" => self.scan_clamav(path),
            "off" => ExternalScanOutcome::Clean,
            _ => {
                let outcome = self.scan_defender(path);
                match outcome {
                    ExternalScanOutcome::Unavailable => self.scan_clamav(path),
                    _ => outcome,
                }
            }
        }
    }

    fn scan_defender(&self, path: &Path) -> ExternalScanOutcome {
        let defender = match &self.defender_path {
            Some(path) => path,
            None => return ExternalScanOutcome::Unavailable,
        };

        let output = Command::new(defender)
            .arg("-Scan")
            .arg("-ScanType")
            .arg("3")
            .arg("-File")
            .arg(path)
            .arg("-DisableRemediation")
            .output();

        let output = match output {
            Ok(output) => output,
            Err(err) => {
                return ExternalScanOutcome::Error(format!(
                    "Defender scan failed: {}",
                    err
                ))
            }
        };

        let code = output.status.code().unwrap_or(-1);
        if code == 0 {
            return ExternalScanOutcome::Clean;
        }
        if code == 2 {
            let details = sanitize_output(&output.stdout, &output.stderr);
            return ExternalScanOutcome::Infected(ExternalScanResult {
                engine: "Defender".to_string(),
                signature: details,
            });
        }

        ExternalScanOutcome::Error(format!(
            "Defender scan error code {}",
            code
        ))
    }

    fn scan_clamav(&self, path: &Path) -> ExternalScanOutcome {
        let clamav = match &self.clamav_path {
            Some(path) => path,
            None => return ExternalScanOutcome::Unavailable,
        };

        let output = Command::new(clamav)
            .arg("--no-summary")
            .arg(path)
            .output();

        let output = match output {
            Ok(output) => output,
            Err(err) => {
                return ExternalScanOutcome::Error(format!(
                    "ClamAV scan failed: {}",
                    err
                ))
            }
        };

        let code = output.status.code().unwrap_or(-1);
        if code == 0 {
            return ExternalScanOutcome::Clean;
        }
        if code == 1 {
            let details = parse_clamav_output(&output.stdout)
                .or_else(|| sanitize_output(&output.stdout, &output.stderr));
            return ExternalScanOutcome::Infected(ExternalScanResult {
                engine: "ClamAV".to_string(),
                signature: details,
            });
        }

        ExternalScanOutcome::Error(format!(
            "ClamAV scan error code {}",
            code
        ))
    }
}

fn initial_yara_rules_path() -> PathBuf {
    std::env::var("AEGIS_YARA_RULES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules"))
}

fn initial_ml_model_path() -> PathBuf {
    std::env::var("AEGIS_ML_MODEL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("models")
                .join("aegis_ml_weights.json")
        })
}

fn find_defender_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("AEGIS_DEFENDER_PATH") {
        let candidate = PathBuf::from(custom);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let candidates = [
        PathBuf::from(r"C:\Program Files\Windows Defender\MpCmdRun.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"),
    ];
    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let platform_root = std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join("Microsoft")
        .join("Windows Defender")
        .join("Platform");
    if let Ok(entries) = std::fs::read_dir(platform_root) {
        let mut versions = entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        versions.sort();
        versions.reverse();
        for version in versions {
            let candidate = version.join("MpCmdRun.exe");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

fn find_clamav_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("AEGIS_CLAMAV_PATH") {
        let candidate = PathBuf::from(custom);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let candidates = [
        PathBuf::from(r"C:\Program Files\ClamAV\clamscan.exe"),
        PathBuf::from(r"C:\Program Files (x86)\ClamAV\clamscan.exe"),
        PathBuf::from(r"C:\ClamAV\clamscan.exe"),
    ];
    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn parse_clamav_output(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        if let Some((_, rest)) = line.split_once(": ") {
            if let Some((signature, _)) = rest.rsplit_once(" FOUND") {
                let trimmed = signature.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn sanitize_output(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(stdout));
    if !stderr.is_empty() {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(&String::from_utf8_lossy(stderr));
    }

    let mut cleaned: String = text
        .chars()
        .filter(|ch| ch.is_ascii() && !ch.is_ascii_control())
        .collect();
    cleaned = cleaned.replace('\n', " ").replace('\r', " ");
    let trimmed = cleaned.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    let limited = if trimmed.len() > 200 {
        trimmed[..200].to_string()
    } else {
        trimmed
    };
    Some(limited)
}

pub struct ScanManager {
    telemetry: Arc<TelemetryStore>,
    response_engine: Arc<ResponseEngine>,
    signatures: Arc<HashSet<String>>,
    current: Arc<Mutex<Option<ScanSummary>>>,
    event_scan_limit: Arc<Semaphore>,
    event_cache: Arc<Mutex<HashMap<String, Instant>>>,
    cancel_flag: Arc<AtomicBool>,
    yara_engine: Arc<StdRwLock<YaraEngine>>,
    ml_engine: Arc<StdRwLock<MlEngine>>,
    external_scanner: Arc<ExternalScanner>,
}

fn scan_debug_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("AEGIS_LOG_SCAN")
            .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    })
}

fn scan_debug_match() -> Option<&'static str> {
    static MATCH: OnceLock<Option<String>> = OnceLock::new();
    MATCH
        .get_or_init(|| std::env::var("AEGIS_LOG_SCAN_MATCH").ok())
        .as_deref()
}

fn event_scan_roots() -> Option<&'static Vec<String>> {
    static ROOTS: OnceLock<Option<Vec<String>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let value = std::env::var("AEGIS_EVENT_SCAN_ROOTS").ok()?;
        let roots = value
            .split(';')
            .filter_map(|entry| {
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let mut root = trimmed.to_ascii_lowercase();
                if !root.ends_with('\\') && !root.ends_with('/') {
                    root.push('\\');
                }
                Some(root)
            })
            .collect::<Vec<_>>();
        if roots.is_empty() {
            None
        } else {
            Some(roots)
        }
    })
    .as_ref()
}

fn event_scan_allowed(path: &Path) -> bool {
    let roots = match event_scan_roots() {
        Some(roots) => roots,
        None => return true,
    };

    let mut haystack = path.to_string_lossy().to_ascii_lowercase();
    if !haystack.ends_with('\\') {
        haystack.push('\\');
    }

    roots.iter().any(|root| haystack.starts_with(root))
}

fn log_scan_debug(path: &Path, message: &str) {
    if !scan_debug_enabled() {
        return;
    }

    if let Some(matcher) = scan_debug_match() {
        let haystack = path.to_string_lossy();
        if !haystack.contains(matcher) {
            return;
        }
    }

    println!("[SCAN] {} {}", message, path.to_string_lossy());
}

impl ScanManager {
    pub fn new(telemetry: Arc<TelemetryStore>, response_engine: Arc<ResponseEngine>) -> Self {
        let signatures = Arc::new(load_signatures());
        let yara_engine = Arc::new(StdRwLock::new(YaraEngine::new(
            initial_yara_rules_path(),
        )));
        let ml_engine = Arc::new(StdRwLock::new(MlEngine::new(
            initial_ml_model_path(),
        )));
        let external_scanner = Arc::new(ExternalScanner::new());
        Self {
            telemetry,
            response_engine,
            signatures,
            current: Arc::new(Mutex::new(None)),
            event_scan_limit: Arc::new(Semaphore::new(2)),
            event_cache: Arc::new(Mutex::new(HashMap::new())),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            yara_engine,
            ml_engine,
            external_scanner,
        }
    }

    pub async fn start_scan(
        &self,
        mode: ScanMode,
        scan_config: ScanRuntimeConfig,
    ) -> Result<ScanSummary, String> {
        let roots = scan_roots(&mode);
        self.start_scan_with_roots(mode, scan_config, roots).await
    }

    pub async fn start_scan_with_roots(
        &self,
        mode: ScanMode,
        scan_config: ScanRuntimeConfig,
        roots: Vec<PathBuf>,
    ) -> Result<ScanSummary, String> {
        {
            let current = self.current.lock().await;
            if let Some(active) = current.as_ref() {
                if active.status == ScanStatus::Running || active.status == ScanStatus::Queued {
                    return Err("Scan already running".to_string());
                }
            }
        }

        self.cancel_flag.store(false, Ordering::SeqCst);
        let roots = roots
            .into_iter()
            .filter(|path| path.exists())
            .collect::<Vec<_>>();

        let id = SCAN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let summary = ScanSummary {
            id: format!("SCAN-{}", id),
            mode: mode.clone(),
            status: ScanStatus::Queued,
            scanned_files: 0,
            threats_found: 0,
            started_at: epoch_seconds(),
            finished_at: None,
            last_error: None,
        };

        {
            let mut current = self.current.lock().await;
            *current = Some(summary.clone());
        }

        let telemetry = Arc::clone(&self.telemetry);
        let response_engine = Arc::clone(&self.response_engine);
        let signatures = Arc::clone(&self.signatures);
        let current = Arc::clone(&self.current);
        let cancel_flag = Arc::clone(&self.cancel_flag);
        let yara_engine = Arc::clone(&self.yara_engine);
        let ml_engine = Arc::clone(&self.ml_engine);
        let external_scanner = Arc::clone(&self.external_scanner);

        let summary_clone = summary.clone();
        tokio::task::spawn_blocking(move || {
            run_scan(
                summary_clone,
                roots,
                telemetry,
                response_engine,
                signatures,
                current,
                cancel_flag,
                yara_engine,
                ml_engine,
                external_scanner,
                scan_config,
            );
        });

        Ok(summary)
    }

    pub async fn status(&self) -> Option<ScanSummary> {
        let current = self.current.lock().await;
        current.clone()
    }

    pub async fn cancel_scan(&self) -> bool {
        let current = self.current.lock().await;
        if let Some(active) = current.as_ref() {
            if active.status == ScanStatus::Running || active.status == ScanStatus::Queued {
                self.cancel_flag.store(true, Ordering::SeqCst);
                return true;
            }
        }
        false
    }

    pub fn reload_yara(&self, rules_path: PathBuf) {
        if let Ok(mut engine) = self.yara_engine.write() {
            engine.update_rules_path(rules_path);
        }
    }

    pub fn reload_ml_model(&self, model_path: PathBuf) {
        if let Ok(mut engine) = self.ml_engine.write() {
            engine.update_model_path(model_path);
        }
    }

    pub fn spawn_event_scan(
        &self,
        path: PathBuf,
        event_type: EventType,
        scan_config: ScanRuntimeConfig,
    ) {
        if !event_scan_allowed(&path) {
            log_scan_debug(&path, "event_scan_root_skip");
            return;
        }

        if path_is_excluded(&path, &scan_config) {
            log_scan_debug(&path, "event_scan_excluded");
            return;
        }

        let should_scan = should_scan_file(&path);
        let candidate_eicar = if should_scan {
            false
        } else {
            path.metadata()
                .map(|metadata| metadata.len() <= MAX_EICAR_BYTES as u64)
                .unwrap_or(false)
        };

        if !should_scan && !candidate_eicar {
            return;
        }

        let delay = if matches!(event_type, EventType::FileCreated) {
            Duration::from_millis(250)
        } else {
            Duration::from_millis(0)
        };

        let path_str = path.to_string_lossy().to_string();
        let telemetry = Arc::clone(&self.telemetry);
        let response_engine = Arc::clone(&self.response_engine);
        let signatures = Arc::clone(&self.signatures);
        let yara_engine = Arc::clone(&self.yara_engine);
        let ml_engine = Arc::clone(&self.ml_engine);
        let external_scanner = Arc::clone(&self.external_scanner);
        let event_cache = Arc::clone(&self.event_cache);
        let limiter = Arc::clone(&self.event_scan_limit);
        let ttl = event_scan_ttl();
        let scan_config = scan_config.clone();

        tokio::spawn(async move {
            if delay.as_millis() > 0 {
                tokio::time::sleep(delay).await;
            }

            log_scan_debug(&path, "event_scan");
            let is_eicar = if candidate_eicar {
                is_eicar_file(&path)
            } else {
                false
            };

            if !should_scan && !is_eicar {
                log_scan_debug(&path, "event_scan_skip");
                return;
            }

            let now = Instant::now();
            {
                let mut cache = event_cache.lock().await;
                if let Some(last) = cache.get(&path_str) {
                    if now.duration_since(*last) < ttl {
                        log_scan_debug(&path, "event_scan_ttl_skip");
                        return;
                    }
                }
                cache.insert(path_str.clone(), now);
            }

            let permit = match limiter.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };

            let handle = tokio::runtime::Handle::current();
            let scan_config = scan_config.clone();
            let _ = tokio::task::spawn_blocking(move || {
                scan_single_file(
                    &path,
                    signatures.as_ref(),
                    telemetry,
                    response_engine,
                    yara_engine,
                    ml_engine,
                    external_scanner,
                    &scan_config,
                    &handle,
                );
            })
            .await;

            drop(permit);
        });
    }
}

fn run_scan(
    mut summary: ScanSummary,
    roots: Vec<PathBuf>,
    telemetry: Arc<TelemetryStore>,
    response_engine: Arc<ResponseEngine>,
    signatures: Arc<HashSet<String>>,
    current: Arc<Mutex<Option<ScanSummary>>>,
    cancel_flag: Arc<AtomicBool>,
    yara_engine: Arc<StdRwLock<YaraEngine>>,
    ml_engine: Arc<StdRwLock<MlEngine>>,
    external_scanner: Arc<ExternalScanner>,
    scan_config: ScanRuntimeConfig,
) {
    let mut scanned = 0u64;
    let mut threats = 0u64;

    if check_cancel(&mut summary, &current, cancel_flag.as_ref(), scanned, threats) {
        return;
    }

    if roots.is_empty() {
        summary.status = ScanStatus::Failed;
        summary.last_error = Some("No scan roots configured".to_string());
        summary.finished_at = Some(epoch_seconds());
        update_summary(&current, &summary);
        return;
    }

    summary.status = ScanStatus::Running;
    summary.started_at = epoch_seconds();
    update_summary(&current, &summary);

    let max_bytes = match summary.mode {
        ScanMode::Quick => MAX_QUICK_FILE_BYTES,
        ScanMode::Full => MAX_FULL_FILE_BYTES,
    };

    let handle = tokio::runtime::Handle::current();
    update_yara_engine(&yara_engine, &scan_config);
    update_ml_engine(&ml_engine, &scan_config);

    for root in roots {
        if check_cancel(&mut summary, &current, cancel_flag.as_ref(), scanned, threats) {
            return;
        }

        let walker = WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| !is_ignored_dir(entry));

        for entry in walker {
            if check_cancel(&mut summary, &current, cancel_flag.as_ref(), scanned, threats) {
                return;
            }

            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            if !entry.file_type().is_file() {
                continue;
            }

            if path_is_excluded(entry.path(), &scan_config) {
                log_scan_debug(entry.path(), "scan_excluded");
                continue;
            }

            let file_size = entry.metadata().map(|meta| meta.len()).unwrap_or(0);

            scanned = scanned.saturating_add(1);

            if scan_config.archive_scan_enabled
                && is_archive_path(entry.path())
                && file_size <= scan_config.archive_max_bytes
            {
                if let Some(outcome) = scan_archive_entries(
                    entry.path(),
                    signatures.as_ref(),
                    &yara_engine,
                    &scan_config,
                ) {
                    scanned = scanned.saturating_add(outcome.entries_scanned);
                    if scanned % 200 == 0 {
                        summary.scanned_files = scanned;
                        update_summary(&current, &summary);
                    }

                    if !outcome.hits.is_empty() {
                        threats = threats.saturating_add(1);
                        summary.threats_found = threats;
                        let threat =
                            build_archive_threat(entry.path(), summary.mode.clone(), &outcome);
                        process_threat(
                            threat,
                            response_engine.as_ref(),
                            telemetry.as_ref(),
                            scan_config.firewall_enabled,
                            &handle,
                        );
                        continue;
                    }
                }
            }

            if scanned % 200 == 0 {
                summary.scanned_files = scanned;
                update_summary(&current, &summary);
            }

            let hash = hash_file(entry.path(), max_bytes);
            if hash.is_none() {
                log_scan_debug(entry.path(), "hash_failed");
            }
            let hash_match = hash
                .as_ref()
                .map(|value| signatures.contains(value))
                .unwrap_or(false);
            let is_eicar = is_eicar_file(entry.path());

            let mut yara_matches = Vec::new();
            if !hash_match
                && !is_eicar
                && scan_config.yara_enabled
                && file_size <= scan_config.yara_max_bytes
            {
                yara_matches = scan_yara_file(&yara_engine, entry.path());
            }

            let external_outcome = if !hash_match
                && !is_eicar
                && yara_matches.is_empty()
                && scan_config.external_scan_enabled
                && should_external_scan(entry.path())
                && file_size <= scan_config.external_scan_max_bytes
            {
                external_scanner.scan(entry.path(), &scan_config.external_scan_mode)
            } else {
                ExternalScanOutcome::Clean
            };

            if let ExternalScanOutcome::Error(error) = &external_outcome {
                if scan_debug_enabled() {
                    eprintln!("[SCAN] External scan error: {}", error);
                }
            }

            let ai_assessment = if scan_config.ai_enabled && !hash_match && !is_eicar {
                ai_scan_assessment(
                    entry.path(),
                    file_size,
                    yara_matches.len(),
                    &scan_config,
                    &ml_engine,
                )
            } else {
                None
            };
            let ai_hit = ai_assessment
                .as_ref()
                .map(|assessment| assessment.score >= scan_config.ml_score_threshold)
                .unwrap_or(false);

            let mut include_ml = false;
            let threat = if hash_match || is_eicar {
                let mut threat = build_scan_threat(entry.path(), summary.mode.clone());
                if is_eicar {
                    threat.threat_type = "EICAR-Test".to_string();
                    threat.indicators = vec!["EICAR test string".to_string()];
                }
                log_scan_debug(entry.path(), "signature_match");
                include_ml = ai_hit;
                Some(threat)
            } else if let ExternalScanOutcome::Infected(result) = external_outcome {
                log_scan_debug(entry.path(), "external_match");
                include_ml = ai_hit;
                Some(build_external_threat(entry.path(), &result))
            } else if !yara_matches.is_empty() {
                log_scan_debug(entry.path(), "yara_match");
                include_ml = ai_hit;
                Some(build_yara_threat(entry.path(), summary.mode.clone(), &yara_matches))
            } else if ai_hit {
                log_scan_debug(entry.path(), "ai_match");
                Some(build_ai_threat(entry.path(), ai_assessment.as_ref()))
            } else {
                None
            };

            if let Some(mut threat) = threat {
                if include_ml {
                    append_ml_indicators(&mut threat, ai_assessment.as_ref());
                }
                threats = threats.saturating_add(1);
                summary.threats_found = threats;
                process_threat(
                    threat,
                    response_engine.as_ref(),
                    telemetry.as_ref(),
                    scan_config.firewall_enabled,
                    &handle,
                );
            }
        }
    }

    summary.scanned_files = scanned;
    summary.threats_found = threats;
    summary.status = ScanStatus::Completed;
    summary.finished_at = Some(epoch_seconds());
    update_summary(&current, &summary);

    telemetry.record_scan_blocking(scanned);
}

fn check_cancel(
    summary: &mut ScanSummary,
    current: &Arc<Mutex<Option<ScanSummary>>>,
    cancel_flag: &AtomicBool,
    scanned: u64,
    threats: u64,
) -> bool {
    if !cancel_flag.load(Ordering::Relaxed) {
        return false;
    }

    summary.status = ScanStatus::Cancelled;
    summary.scanned_files = scanned;
    summary.threats_found = threats;
    summary.last_error = Some("Cancelled by user".to_string());
    summary.finished_at = Some(epoch_seconds());
    update_summary(current, summary);
    true
}

fn update_summary(current: &Arc<Mutex<Option<ScanSummary>>>, summary: &ScanSummary) {
    let mut current = current.blocking_lock();
    *current = Some(summary.clone());
}

fn scan_roots(mode: &ScanMode) -> Vec<PathBuf> {
    let var_name = match mode {
        ScanMode::Quick => "AEGIS_QUICK_SCAN_ROOTS",
        ScanMode::Full => "AEGIS_FULL_SCAN_ROOTS",
    };

    if let Ok(value) = std::env::var(var_name) {
        let roots = value
            .split(';')
            .map(|entry| PathBuf::from(entry.trim()))
            .filter(|path| path.exists())
            .collect::<Vec<_>>();
        if !roots.is_empty() {
            return roots;
        }
    }

    match mode {
        ScanMode::Quick => default_quick_roots(),
        ScanMode::Full => default_full_roots(),
    }
}

fn default_quick_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let base = PathBuf::from(profile);
        roots.push(base.join("Desktop"));
        roots.push(base.join("Downloads"));
        roots.push(base.join("Documents"));
    }
    roots.into_iter().filter(|path| path.exists()).collect()
}

fn default_full_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if cfg!(windows) {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        roots.push(PathBuf::from(format!("{}\\", drive)));
    } else {
        roots.push(PathBuf::from("/"));
    }
    roots.into_iter().filter(|path| path.exists()).collect()
}

fn is_ignored_dir(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }

    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "node_modules"
            | ".git"
            | "target"
            | "dist"
            | "build"
            | "obj"
            | "bin"
            | "temp"
            | "tmp"
    )
}

fn hash_file(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut remaining = max_bytes;

    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }

        let to_hash = if remaining < read as u64 {
            remaining as usize
        } else {
            read
        };

        if to_hash > 0 {
            hasher.update(&buffer[..to_hash]);
        }

        if remaining <= read as u64 {
            break;
        }

        remaining = remaining.saturating_sub(read as u64);
    }

    Some(format!("{:x}", hasher.finalize()))
}

fn is_eicar_file(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut buffer = Vec::with_capacity(MAX_EICAR_BYTES);
    let mut chunk = [0u8; 512];
    let mut total = 0usize;

    loop {
        let read = match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => return false,
        };

        let remaining = MAX_EICAR_BYTES.saturating_sub(total);
        let to_copy = read.min(remaining);
        if to_copy > 0 {
            buffer.extend_from_slice(&chunk[..to_copy]);
            total += to_copy;
        }

        if total >= MAX_EICAR_BYTES {
            break;
        }
    }

    is_eicar_bytes(&buffer)
}

fn is_eicar_bytes(buffer: &[u8]) -> bool {
    if buffer.len() < EICAR_TEST_BYTES.len() {
        return false;
    }
    buffer
        .windows(EICAR_TEST_BYTES.len())
        .any(|window| window == EICAR_TEST_BYTES)
}

fn scan_single_file(
    path: &Path,
    signatures: &HashSet<String>,
    telemetry: Arc<TelemetryStore>,
    response_engine: Arc<ResponseEngine>,
    yara_engine: Arc<StdRwLock<YaraEngine>>,
    ml_engine: Arc<StdRwLock<MlEngine>>,
    external_scanner: Arc<ExternalScanner>,
    scan_config: &ScanRuntimeConfig,
    handle: &tokio::runtime::Handle,
) {
    if path_is_excluded(path, scan_config) {
        log_scan_debug(path, "scan_excluded");
        return;
    }

    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            log_scan_debug(path, "metadata_failed");
            return;
        }
    };

    if !metadata.is_file() || metadata.len() == 0 {
        log_scan_debug(path, "metadata_skip");
        return;
    }

    let file_size = metadata.len();
    let mut scanned_count = 1u64;

    update_yara_engine(&yara_engine, scan_config);
    update_ml_engine(&ml_engine, scan_config);

    if scan_config.archive_scan_enabled
        && is_archive_path(path)
        && file_size <= scan_config.archive_max_bytes
    {
        if let Some(outcome) = scan_archive_entries(
            path,
            signatures,
            &yara_engine,
            scan_config,
        ) {
            scanned_count = scanned_count.saturating_add(outcome.entries_scanned);
            if !outcome.hits.is_empty() {
                telemetry.record_scan_blocking(scanned_count);
                log_scan_debug(path, "archive_match");
                let threat = build_archive_threat(path, ScanMode::Quick, &outcome);
                process_threat(
                    threat,
                    response_engine.as_ref(),
                    telemetry.as_ref(),
                    scan_config.firewall_enabled,
                    handle,
                );
                return;
            }
        }
    }

    let hash = hash_file(path, MAX_QUICK_FILE_BYTES);
    if hash.is_none() {
        log_scan_debug(path, "hash_failed");
    }
    let hash_match = hash
        .as_ref()
        .map(|value| signatures.contains(value))
        .unwrap_or(false);
    let is_eicar = is_eicar_file(path);

    let mut yara_matches = Vec::new();
    if !hash_match
        && !is_eicar
        && scan_config.yara_enabled
        && file_size <= scan_config.yara_max_bytes
    {
        yara_matches = scan_yara_file(&yara_engine, path);
    }

    let external_outcome = if !hash_match
        && !is_eicar
        && yara_matches.is_empty()
        && scan_config.external_scan_enabled
        && should_external_scan(path)
        && file_size <= scan_config.external_scan_max_bytes
    {
        external_scanner.scan(path, &scan_config.external_scan_mode)
    } else {
        ExternalScanOutcome::Clean
    };

    if let ExternalScanOutcome::Error(error) = &external_outcome {
        if scan_debug_enabled() {
            eprintln!("[SCAN] External scan error: {}", error);
        }
    }

    let ai_assessment = if scan_config.ai_enabled && !hash_match && !is_eicar {
        ai_scan_assessment(
            path,
            file_size,
            yara_matches.len(),
            scan_config,
            &ml_engine,
        )
    } else {
        None
    };
    let ai_hit = ai_assessment
        .as_ref()
        .map(|assessment| assessment.score >= scan_config.ml_score_threshold)
        .unwrap_or(false);

    let mut include_ml = false;
    let threat = if hash_match || is_eicar {
        let mut threat = build_scan_threat(path, ScanMode::Quick);
        if is_eicar {
            threat.threat_type = "EICAR-Test".to_string();
            threat.indicators = vec!["EICAR test string".to_string()];
        }
        log_scan_debug(path, "signature_match");
        include_ml = ai_hit;
        Some(threat)
    } else if let ExternalScanOutcome::Infected(result) = external_outcome {
        log_scan_debug(path, "external_match");
        include_ml = ai_hit;
        Some(build_external_threat(path, &result))
    } else if !yara_matches.is_empty() {
        log_scan_debug(path, "yara_match");
        include_ml = ai_hit;
        Some(build_yara_threat(path, ScanMode::Quick, &yara_matches))
    } else if ai_hit {
        log_scan_debug(path, "ai_match");
        Some(build_ai_threat(path, ai_assessment.as_ref()))
    } else {
        log_scan_debug(path, "no_match");
        None
    };

    telemetry.record_scan_blocking(scanned_count);

    if let Some(mut threat) = threat {
        if include_ml {
            append_ml_indicators(&mut threat, ai_assessment.as_ref());
        }
        process_threat(
            threat,
            response_engine.as_ref(),
            telemetry.as_ref(),
            scan_config.firewall_enabled,
            handle,
        );
    }
}

#[derive(Debug, Clone)]
struct AiAssessment {
    score: f32,
    indicators: Vec<String>,
}

#[derive(Debug, Clone)]
struct MlFeatureData {
    features: HashMap<String, f32>,
    indicators: Vec<String>,
}

#[derive(Debug, Clone)]
struct ArchiveEntryHit {
    name: String,
    reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct ArchiveScanOutcome {
    entries_scanned: u64,
    hits: Vec<ArchiveEntryHit>,
}

fn update_yara_engine(yara_engine: &Arc<StdRwLock<YaraEngine>>, scan_config: &ScanRuntimeConfig) {
    if !scan_config.yara_enabled {
        return;
    }
    let rules_path = PathBuf::from(&scan_config.yara_rules_path);
    if let Ok(mut engine) = yara_engine.write() {
        engine.update_rules_path(rules_path);
    }
}

fn update_ml_engine(ml_engine: &Arc<StdRwLock<MlEngine>>, scan_config: &ScanRuntimeConfig) {
    let model_path = PathBuf::from(&scan_config.ml_model_path);
    if let Ok(mut engine) = ml_engine.write() {
        engine.update_model_path(model_path);
    }
}

fn scan_yara_file(
    yara_engine: &Arc<StdRwLock<YaraEngine>>,
    path: &Path,
) -> Vec<String> {
    if let Ok(engine) = yara_engine.read() {
        return engine.scan_file(path);
    }
    Vec::new()
}

fn scan_yara_bytes(
    yara_engine: &Arc<StdRwLock<YaraEngine>>,
    data: &[u8],
) -> Vec<String> {
    if let Ok(engine) = yara_engine.read() {
        return engine.scan_bytes(data);
    }
    Vec::new()
}

fn scan_archive_entries(
    path: &Path,
    signatures: &HashSet<String>,
    yara_engine: &Arc<StdRwLock<YaraEngine>>,
    scan_config: &ScanRuntimeConfig,
) -> Option<ArchiveScanOutcome> {
    let file = File::open(path).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;

    let mut hits = Vec::new();
    let mut entries_scanned = 0u64;
    let mut total_uncompressed = 0u64;

    let max_entries = scan_config.archive_max_entries;
    let entry_limit = scan_config.archive_entry_max_bytes;

    let len = archive.len().min(max_entries as usize);
    for index in 0..len {
        if entries_scanned >= max_entries {
            break;
        }

        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        if entry.is_dir() {
            continue;
        }

        let entry_size = entry.size();
        if entry_size == 0 || entry_size > entry_limit {
            continue;
        }

        total_uncompressed = total_uncompressed.saturating_add(entry_size);
        if total_uncompressed > scan_config.archive_max_bytes {
            break;
        }

        let mut buffer = Vec::with_capacity(entry_size as usize);
        if entry.read_to_end(&mut buffer).is_err() {
            continue;
        }

        entries_scanned = entries_scanned.saturating_add(1);

        let mut reasons = Vec::new();
        let hash = hash_bytes(&buffer);
        if signatures.contains(&hash) {
            reasons.push("Signature match".to_string());
        }
        if is_eicar_bytes(&buffer) {
            reasons.push("EICAR test string".to_string());
        }
        if scan_config.yara_enabled
            && (buffer.len() as u64) <= scan_config.yara_max_bytes
        {
            let matches = scan_yara_bytes(yara_engine, &buffer);
            for rule in matches {
                reasons.push(format!("YARA: {}", rule));
            }
        }

        if !reasons.is_empty() {
            hits.push(ArchiveEntryHit {
                name: entry.name().to_string(),
                reasons,
            });
        }
    }

    Some(ArchiveScanOutcome {
        entries_scanned,
        hits,
    })
}

fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn is_archive_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "zip"
            | "jar"
            | "apk"
            | "docx"
            | "xlsx"
            | "pptx"
            | "odt"
            | "ods"
            | "odp"
            | "nupkg"
            | "vsix"
    )
}

fn should_external_scan(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "scr"
            | "com"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "js"
            | "jar"
            | "msi"
            | "msix"
            | "sys"
            | "ocx"
            | "drv"
            | "doc"
            | "docm"
            | "xls"
            | "xlsm"
            | "ppt"
            | "pptm"
            | "pdf"
    )
}

fn path_is_excluded(path: &Path, scan_config: &ScanRuntimeConfig) -> bool {
    matches_exclusion(&scan_config.exclude_programs, "", Some(path))
}

fn push_indicator(
    indicators: &mut Vec<String>,
    seen: &mut HashSet<String>,
    value: &str,
) {
    if indicators.len() >= MAX_ML_INDICATORS {
        return;
    }
    if seen.insert(value.to_string()) {
        indicators.push(value.to_string());
    }
}

fn collect_ml_features(
    path: &Path,
    file_size: u64,
    yara_matches: usize,
    max_bytes: u64,
) -> MlFeatureData {
    let mut features = HashMap::new();
    let mut indicators = Vec::new();
    let mut seen = HashSet::new();

    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let path_str = path.to_string_lossy().to_ascii_lowercase();

    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let size_log = ((file_size as f32) / 1024.0 + 1.0).ln();
    features.insert("size_log".to_string(), size_log);

    if yara_matches > 0 {
        let capped = (yara_matches as f32).min(10.0);
        features.insert("yara_match_count".to_string(), capped);
        push_indicator(&mut indicators, &mut seen, "Coincidencias YARA");
    }

    let suspicious_locations = [
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\public\\",
    ];
    for location in suspicious_locations {
        if path_str.contains(location) {
            features.insert("path_suspicious".to_string(), 1.0);
            push_indicator(
                &mut indicators,
                &mut seen,
                &format!("Ubicacion sospechosa: {}", location),
            );
            break;
        }
    }

    if matches!(
        ext.as_str(),
        "exe" | "dll" | "sys" | "scr" | "com" | "ocx" | "drv" | "msi" | "msix"
    ) {
        features.insert("ext_exe".to_string(), 1.0);
    }
    if matches!(
        ext.as_str(),
        "ps1" | "vbs" | "js" | "jse" | "vbe" | "bat" | "cmd"
    ) {
        features.insert("ext_script".to_string(), 1.0);
        push_indicator(&mut indicators, &mut seen, "Script ejecutable");
    }
    if matches!(
        ext.as_str(),
        "doc" | "docm" | "xls" | "xlsm" | "ppt" | "pptm" | "pdf"
    ) {
        features.insert("ext_doc".to_string(), 1.0);
    }
    if matches!(
        ext.as_str(),
        "zip" | "rar" | "7z" | "jar" | "apk" | "iso" | "cab"
    ) {
        features.insert("ext_archive".to_string(), 1.0);
    }

    if filename.contains(".exe.")
        || filename.contains(".scr.")
        || filename.contains(".pdf.exe")
        || filename.contains(".doc.exe")
        || filename.contains(".xls.exe")
    {
        features.insert("name_double_ext".to_string(), 1.0);
        push_indicator(&mut indicators, &mut seen, "Doble extension detectada");
    }

    if filename.starts_with('.') {
        features.insert("name_hidden".to_string(), 1.0);
        push_indicator(&mut indicators, &mut seen, "Archivo oculto");
    }

    let keywords = [
        "crack",
        "keygen",
        "patch",
        "loader",
        "hack",
        "trojan",
        "rat",
        "stealer",
        "miner",
        "backdoor",
    ];
    for keyword in keywords {
        if filename.contains(keyword) {
            features.insert("name_keyword".to_string(), 1.0);
            push_indicator(
                &mut indicators,
                &mut seen,
                &format!("Nombre sospechoso: {}", keyword),
            );
            break;
        }
    }

    let sample = read_ml_sample(path, file_size, max_bytes);
    if let Some(sample) = sample {
        if sample.len() > 1 && sample[0] == b'M' && sample[1] == b'Z' {
            features.insert("is_pe".to_string(), 1.0);
            push_indicator(&mut indicators, &mut seen, "Cabecera PE detectada");
        }

        let entropy = shannon_entropy(&sample);
        if entropy > 0.0 {
            features.insert("entropy".to_string(), entropy);
            if entropy >= 7.2 {
                features.insert("entropy_high".to_string(), 1.0);
                push_indicator(&mut indicators, &mut seen, "Alta entropia");
            }
        }

        let text = String::from_utf8_lossy(&sample).to_ascii_lowercase();
        if text.contains("http://") || text.contains("https://") {
            features.insert("contains_url".to_string(), 1.0);
            push_indicator(&mut indicators, &mut seen, "URLs embebidas");
        }

        let patterns = [
            ("powershell", "has_powershell", "Uso de powershell"),
            ("pwsh", "has_powershell", "Uso de powershell"),
            ("cmd.exe", "has_cmd", "Uso de cmd.exe"),
            ("cmd /c", "has_cmd", "Uso de cmd /c"),
            ("base64", "has_base64", "Uso de base64"),
            ("frombase64string", "has_base64", "Decode base64"),
            ("invoke-webrequest", "has_downloadstring", "Descarga web"),
            ("downloadstring", "has_downloadstring", "Descarga web"),
            ("createremotethread", "has_injection", "Tecnica de inyeccion"),
            ("virtualalloc", "has_injection", "Tecnica de inyeccion"),
            ("rundll32", "has_rundll32", "Uso de rundll32"),
            ("schtasks", "has_schtasks", "Persistencia con schtasks"),
        ];

        let mut suspicious_count = 0u32;
        for (pattern, feature, reason) in patterns {
            if text.contains(pattern) {
                suspicious_count = suspicious_count.saturating_add(1);
                features.insert(feature.to_string(), 1.0);
                push_indicator(&mut indicators, &mut seen, reason);
            }
        }

        if suspicious_count > 0 {
            let capped = suspicious_count.min(10) as f32;
            features.insert("suspicious_string_count".to_string(), capped);
        }
    }

    MlFeatureData {
        features,
        indicators,
    }
}

fn read_ml_sample(path: &Path, file_size: u64, max_bytes: u64) -> Option<Vec<u8>> {
    if max_bytes == 0 || file_size == 0 {
        return None;
    }

    let limit = std::cmp::min(file_size, max_bytes) as usize;
    if limit == 0 {
        return None;
    }

    let mut file = File::open(path).ok()?;
    let mut buffer = vec![0u8; limit];
    let mut read_total = 0usize;

    while read_total < limit {
        let read = match file.read(&mut buffer[read_total..]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => return None,
        };
        read_total = read_total.saturating_add(read);
    }

    buffer.truncate(read_total);
    if buffer.is_empty() {
        None
    } else {
        Some(buffer)
    }
}

fn shannon_entropy(buffer: &[u8]) -> f32 {
    if buffer.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for byte in buffer {
        counts[*byte as usize] += 1;
    }

    let len = buffer.len() as f32;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn ai_scan_assessment(
    path: &Path,
    file_size: u64,
    yara_matches: usize,
    scan_config: &ScanRuntimeConfig,
    ml_engine: &Arc<StdRwLock<MlEngine>>,
) -> Option<AiAssessment> {
    let feature_data = collect_ml_features(
        path,
        file_size,
        yara_matches,
        scan_config.ml_max_bytes,
    );

    let score = if let Ok(engine) = ml_engine.read() {
        let score = engine.score(&feature_data.features);
        if score.is_none() && scan_debug_enabled() {
            if let Some(error) = engine.last_error.as_ref() {
                eprintln!("[SCAN] ML model error: {}", error);
            }
        }
        score
    } else {
        None
    }?;

    if score.is_nan() {
        return None;
    }

    Some(AiAssessment {
        score,
        indicators: feature_data.indicators,
    })
}

fn append_ml_indicators(threat: &mut Threat, assessment: Option<&AiAssessment>) {
    let assessment = match assessment {
        Some(assessment) => assessment,
        None => return,
    };

    threat
        .indicators
        .push(format!("ML score: {:.2}", assessment.score));
    for indicator in assessment.indicators.iter().take(MAX_ML_INDICATORS) {
        threat.indicators.push(indicator.clone());
    }
}

fn build_ai_threat(path: &Path, assessment: Option<&AiAssessment>) -> Threat {
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let mut indicators = Vec::new();
    let mut confidence = 0.6;

    if let Some(assessment) = assessment {
        confidence = (assessment.score * 0.9).min(0.9).max(0.6);
        indicators.push(format!("ML score: {:.2}", assessment.score));
        indicators.extend(assessment.indicators.iter().cloned());
    } else {
        indicators.push("AI model match".to_string());
    }

    Threat {
        id: format!("AI-{}", filename),
        threat_type: "AI-ML".to_string(),
        severity: ThreatSeverity::Medium,
        confidence,
        process_id: 0,
        process_name: "aegis_scan".to_string(),
        process_path: path.to_path_buf(),
        parent_process_id: 0,
        affected_files: vec![path.to_path_buf()],
        network_connections: Vec::new(),
        registry_changes: Vec::new(),
        detection_time: SystemTime::now(),
        indicators,
    }
}

fn build_yara_threat(path: &Path, mode: ScanMode, matches: &[String]) -> Threat {
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let severity = match mode {
        ScanMode::Quick => ThreatSeverity::High,
        ScanMode::Full => ThreatSeverity::Critical,
    };

    let mut indicators = Vec::new();
    for rule in matches {
        indicators.push(format!("YARA rule: {}", rule));
    }

    Threat {
        id: format!("YARA-{}", filename),
        threat_type: "YARA".to_string(),
        severity,
        confidence: 0.8,
        process_id: 0,
        process_name: "aegis_scan".to_string(),
        process_path: path.to_path_buf(),
        parent_process_id: 0,
        affected_files: vec![path.to_path_buf()],
        network_connections: Vec::new(),
        registry_changes: Vec::new(),
        detection_time: SystemTime::now(),
        indicators,
    }
}

fn build_external_threat(path: &Path, result: &ExternalScanResult) -> Threat {
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let mut indicators = Vec::new();
    if let Some(signature) = &result.signature {
        indicators.push(format!("Signature: {}", signature));
    }
    indicators.push(format!("Engine: {}", result.engine));

    Threat {
        id: format!("EXT-{}", filename),
        threat_type: format!("External-{}", result.engine),
        severity: ThreatSeverity::Critical,
        confidence: 0.85,
        process_id: 0,
        process_name: "aegis_scan".to_string(),
        process_path: path.to_path_buf(),
        parent_process_id: 0,
        affected_files: vec![path.to_path_buf()],
        network_connections: Vec::new(),
        registry_changes: Vec::new(),
        detection_time: SystemTime::now(),
        indicators,
    }
}

fn build_archive_threat(path: &Path, mode: ScanMode, outcome: &ArchiveScanOutcome) -> Threat {
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let severity = match mode {
        ScanMode::Quick => ThreatSeverity::High,
        ScanMode::Full => ThreatSeverity::Critical,
    };

    let mut indicators = Vec::new();
    indicators.push(format!("Archive hits: {}", outcome.hits.len()));
    for hit in outcome.hits.iter().take(20) {
        let detail = format!("{}: {}", hit.name, hit.reasons.join(", "));
        indicators.push(detail);
    }
    if outcome.hits.len() > 20 {
        indicators.push("More entries matched".to_string());
    }

    Threat {
        id: format!("ARC-{}", filename),
        threat_type: "ArchiveThreat".to_string(),
        severity,
        confidence: 0.8,
        process_id: 0,
        process_name: "aegis_scan".to_string(),
        process_path: path.to_path_buf(),
        parent_process_id: 0,
        affected_files: vec![path.to_path_buf()],
        network_connections: Vec::new(),
        registry_changes: Vec::new(),
        detection_time: SystemTime::now(),
        indicators,
    }
}

fn process_threat(
    threat: Threat,
    response_engine: &ResponseEngine,
    telemetry: &TelemetryStore,
    firewall_enabled: bool,
    handle: &tokio::runtime::Handle,
) {
    let action = response_engine.decide_response(&threat);
    let action = apply_firewall_policy(action, firewall_enabled);
    telemetry.record_action_blocking(action.clone());
    telemetry.record_threat_entry_blocking(api_threat_from_scan(&threat, &action));
    let _ = handle.block_on(async { response_engine.execute_response(&threat, action).await });
}

fn apply_firewall_policy(action: ResponseAction, firewall_enabled: bool) -> ResponseAction {
    if !firewall_enabled && matches!(action, ResponseAction::BlockNetwork) {
        ResponseAction::Monitor
    } else {
        action
    }
}

fn load_signatures() -> HashSet<String> {
    let path = std::env::var("AEGIS_SIGNATURES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("signatures.txt")
        });

    let mut signatures = HashSet::new();
    let contents = std::fs::read_to_string(path).unwrap_or_default();
    for line in contents.lines() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        signatures.insert(value.to_ascii_lowercase());
    }
    signatures
}

fn build_scan_threat(path: &Path, mode: ScanMode) -> Threat {
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let severity = match mode {
        ScanMode::Quick => ThreatSeverity::High,
        ScanMode::Full => ThreatSeverity::Critical,
    };

    Threat {
        id: format!("FILE-{}", filename),
        threat_type: "SignatureMatch".to_string(),
        severity,
        confidence: 0.95,
        process_id: 0,
        process_name: "aegis_scan".to_string(),
        process_path: path.to_path_buf(),
        parent_process_id: 0,
        affected_files: vec![path.to_path_buf()],
        network_connections: Vec::new(),
        registry_changes: Vec::new(),
        detection_time: SystemTime::now(),
        indicators: vec!["Signature match".to_string()],
    }
}

fn api_threat_from_scan(threat: &Threat, action: &ResponseAction) -> ApiThreat {
    ApiThreat {
        id: threat.id.clone(),
        timestamp: epoch_seconds(),
        name: threat.threat_type.clone(),
        file: threat
            .affected_files
            .first()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| threat.process_name.clone()),
        action: action_label(action).to_string(),
        confidence: threat.confidence,
        severity: format!("{:?}", threat.severity).to_ascii_lowercase(),
    }
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

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn should_scan_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "scr"
            | "com"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "js"
            | "jar"
            | "msi"
            | "msix"
            | "sys"
            | "ocx"
            | "drv"
            | "doc"
            | "docm"
            | "xls"
            | "xlsm"
            | "ppt"
            | "pptm"
    )
}

fn event_scan_ttl() -> Duration {
    std::env::var("AEGIS_EVENT_SCAN_TTL_SEC")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(30))
}
