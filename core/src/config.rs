use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub tick_interval: Duration,
    pub log_kernel_events: bool,
    pub log_kernel_filter: String,
    pub exclude_programs: Vec<String>,
    pub firewall_enabled: bool,
    pub ai_scan_enabled: bool,
    pub device_scan_enabled: bool,
    pub device_scan_mode: String,
    pub device_scan_interval_ms: u64,
    pub device_scan_removable_only: bool,
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

impl CoreConfig {
    pub fn from_env() -> Self {
        let tick_ms = std::env::var("AEGIS_TICK_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(100);

        let log_kernel_events = parse_bool_env("AEGIS_LOG_KERNEL", false);

        let log_kernel_filter = std::env::var("AEGIS_LOG_KERNEL_FILTER")
            .unwrap_or_else(|_| "all".to_string())
            .trim()
            .to_ascii_lowercase();

        let exclude_programs = std::env::var("AEGIS_EXCLUDE_PROGRAMS")
            .ok()
            .map(|value| {
                value
                    .split(';')
                    .map(|entry| entry.to_string())
                    .collect::<Vec<_>>()
            })
            .map(normalize_exclusions)
            .unwrap_or_default();

        let firewall_enabled = parse_bool_env("AEGIS_FIREWALL_ENABLED", true);
        let ai_scan_enabled = parse_bool_env("AEGIS_AI_SCAN", true);
        let device_scan_enabled = parse_bool_env("AEGIS_DEVICE_SCAN", true);
        let device_scan_mode = normalize_device_scan_mode(
            std::env::var("AEGIS_DEVICE_SCAN_MODE").ok().as_deref(),
        );
        let device_scan_interval_ms = std::env::var("AEGIS_DEVICE_SCAN_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(clamp_device_scan_interval)
            .unwrap_or(3000);
        let device_scan_removable_only =
            parse_bool_env("AEGIS_DEVICE_SCAN_REMOVABLE_ONLY", false);
        let yara_enabled = parse_bool_env("AEGIS_YARA_ENABLED", true);
        let yara_rules_path = std::env::var("AEGIS_YARA_RULES_PATH")
            .unwrap_or_else(|_| default_yara_rules_path().to_string_lossy().to_string());
        let yara_max_bytes = std::env::var("AEGIS_YARA_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(clamp_yara_max_bytes)
            .unwrap_or(20 * 1024 * 1024);
        let ml_model_path = std::env::var("AEGIS_ML_MODEL_PATH")
            .unwrap_or_else(|_| default_ml_model_path().to_string_lossy().to_string());
        let ml_score_threshold = std::env::var("AEGIS_ML_THRESHOLD")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .map(clamp_ml_threshold)
            .unwrap_or(0.75);
        let ml_max_bytes = std::env::var("AEGIS_ML_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(clamp_ml_max_bytes)
            .unwrap_or(4 * 1024 * 1024);
        let archive_scan_enabled = parse_bool_env("AEGIS_ARCHIVE_SCAN", true);
        let archive_max_bytes = std::env::var("AEGIS_ARCHIVE_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(clamp_archive_max_bytes)
            .unwrap_or(200 * 1024 * 1024);
        let archive_max_entries = std::env::var("AEGIS_ARCHIVE_MAX_ENTRIES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(clamp_archive_max_entries)
            .unwrap_or(2000);
        let archive_entry_max_bytes =
            std::env::var("AEGIS_ARCHIVE_ENTRY_MAX_BYTES")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .map(clamp_archive_entry_max_bytes)
                .unwrap_or(20 * 1024 * 1024);
        let external_scan_enabled = parse_bool_env("AEGIS_EXTERNAL_SCAN", true);
        let external_scan_mode =
            normalize_external_scan_mode(std::env::var("AEGIS_EXTERNAL_SCAN_MODE").ok().as_deref());
        let external_scan_max_bytes =
            std::env::var("AEGIS_EXTERNAL_SCAN_MAX_BYTES")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .map(clamp_external_scan_max_bytes)
                .unwrap_or(50 * 1024 * 1024);

        CoreConfig {
            tick_interval: Duration::from_millis(tick_ms),
            log_kernel_events,
            log_kernel_filter,
            exclude_programs,
            firewall_enabled,
            ai_scan_enabled,
            device_scan_enabled,
            device_scan_mode,
            device_scan_interval_ms,
            device_scan_removable_only,
            yara_enabled,
            yara_rules_path,
            yara_max_bytes,
            ml_model_path,
            ml_score_threshold,
            ml_max_bytes,
            archive_scan_enabled,
            archive_max_bytes,
            archive_max_entries,
            archive_entry_max_bytes,
            external_scan_enabled,
            external_scan_mode,
            external_scan_max_bytes,
        }
    }

    pub fn tick_ms(&self) -> u64 {
        self.tick_interval.as_millis() as u64
    }

    pub fn set_tick_ms(&mut self, tick_ms: u64) {
        let value = if tick_ms == 0 { 1 } else { tick_ms };
        self.tick_interval = Duration::from_millis(value);
    }

    pub fn set_exclude_programs(&mut self, entries: Vec<String>) {
        self.exclude_programs = normalize_exclusions(entries);
    }

    pub fn set_device_scan_mode(&mut self, mode: &str) {
        self.device_scan_mode = normalize_device_scan_mode(Some(mode));
    }

    pub fn set_device_scan_interval_ms(&mut self, value: u64) {
        self.device_scan_interval_ms = clamp_device_scan_interval(value);
    }

    pub fn set_yara_rules_path(&mut self, value: String) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            self.yara_rules_path = default_yara_rules_path()
                .to_string_lossy()
                .to_string();
        } else {
            self.yara_rules_path = trimmed.to_string();
        }
    }

    pub fn set_yara_max_bytes(&mut self, value: u64) {
        self.yara_max_bytes = clamp_yara_max_bytes(value);
    }

    pub fn set_ml_model_path(&mut self, value: String) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            self.ml_model_path = default_ml_model_path()
                .to_string_lossy()
                .to_string();
        } else {
            self.ml_model_path = trimmed.to_string();
        }
    }

    pub fn set_ml_score_threshold(&mut self, value: f32) {
        self.ml_score_threshold = clamp_ml_threshold(value);
    }

    pub fn set_ml_max_bytes(&mut self, value: u64) {
        self.ml_max_bytes = clamp_ml_max_bytes(value);
    }

    pub fn set_archive_max_bytes(&mut self, value: u64) {
        self.archive_max_bytes = clamp_archive_max_bytes(value);
    }

    pub fn set_archive_max_entries(&mut self, value: u64) {
        self.archive_max_entries = clamp_archive_max_entries(value);
    }

    pub fn set_archive_entry_max_bytes(&mut self, value: u64) {
        self.archive_entry_max_bytes = clamp_archive_entry_max_bytes(value);
    }

    pub fn set_external_scan_mode(&mut self, value: &str) {
        self.external_scan_mode = normalize_external_scan_mode(Some(value));
    }

    pub fn set_external_scan_max_bytes(&mut self, value: u64) {
        self.external_scan_max_bytes = clamp_external_scan_max_bytes(value);
    }
}

pub fn normalize_exclusions(entries: Vec<String>) -> Vec<String> {
    let mut unique = HashSet::new();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.replace('/', "\\").to_ascii_lowercase();
        unique.insert(normalized);
    }

    let mut values = unique.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}

pub fn matches_exclusion(
    exclusions: &[String],
    process_name: &str,
    path: Option<&Path>,
) -> bool {
    if exclusions.is_empty() {
        return false;
    }

    let process_lower = process_name.to_ascii_lowercase();
    let path_lower = path.map(|candidate| normalize_path(candidate));
    let file_lower = path
        .and_then(|candidate| candidate.file_name())
        .and_then(|name| name.to_str())
        .map(|name| name.to_ascii_lowercase());

    for entry in exclusions {
        if entry.is_empty() {
            continue;
        }
        if is_path_entry(entry) {
            if let Some(path_lower) = path_lower.as_ref() {
                if path_lower == entry || path_lower.ends_with(entry) {
                    return true;
                }
            }
            continue;
        }

        if entry == &process_lower {
            return true;
        }
        if let Some(file_lower) = file_lower.as_ref() {
            if entry == file_lower {
                return true;
            }
        }
    }

    false
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn is_path_entry(entry: &str) -> bool {
    entry.contains('\\') || entry.contains('/') || entry.contains(':')
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

fn normalize_device_scan_mode(value: Option<&str>) -> String {
    let mode = value.unwrap_or("quick").trim().to_ascii_lowercase();
    if mode == "full" {
        "full".to_string()
    } else {
        "quick".to_string()
    }
}

fn clamp_device_scan_interval(value: u64) -> u64 {
    let normalized = if value < 500 { 500 } else { value };
    normalized.min(120_000)
}

fn default_yara_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")
}

fn default_ml_model_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("models")
        .join("aegis_ml_weights.json")
}

fn clamp_yara_max_bytes(value: u64) -> u64 {
    let normalized = if value < 64 * 1024 { 64 * 1024 } else { value };
    normalized.min(500 * 1024 * 1024)
}

fn clamp_ml_threshold(value: f32) -> f32 {
    if value < 0.1 {
        0.1
    } else if value > 0.99 {
        0.99
    } else {
        value
    }
}

fn clamp_ml_max_bytes(value: u64) -> u64 {
    let normalized = if value < 64 * 1024 { 64 * 1024 } else { value };
    normalized.min(50 * 1024 * 1024)
}

fn clamp_archive_max_bytes(value: u64) -> u64 {
    let normalized = if value < 1 * 1024 * 1024 {
        1 * 1024 * 1024
    } else {
        value
    };
    normalized.min(1024 * 1024 * 1024)
}

fn clamp_archive_max_entries(value: u64) -> u64 {
    let normalized = if value < 10 { 10 } else { value };
    normalized.min(50_000)
}

fn clamp_archive_entry_max_bytes(value: u64) -> u64 {
    let normalized = if value < 64 * 1024 { 64 * 1024 } else { value };
    normalized.min(200 * 1024 * 1024)
}

fn normalize_external_scan_mode(value: Option<&str>) -> String {
    let mode = value.unwrap_or("auto").trim().to_ascii_lowercase();
    match mode.as_str() {
        "defender" => "defender".to_string(),
        "clamav" => "clamav".to_string(),
        "off" => "off".to_string(),
        _ => "auto".to_string(),
    }
}

fn clamp_external_scan_max_bytes(value: u64) -> u64 {
    let normalized = if value < 64 * 1024 { 64 * 1024 } else { value };
    normalized.min(500 * 1024 * 1024)
}
