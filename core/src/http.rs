use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use crate::config::CoreConfig;
use crate::response::ResponseEngine;
use crate::scan::{ScanManager, ScanMode, ScanRuntimeConfig, ScanSummary};
use crate::telemetry::{system_status_from_threats, ApiThreat, StatsSnapshot, SystemHealth, TelemetryStore};
use crate::types::ResponseAction;

#[derive(Clone)]
pub struct ApiState {
    pub telemetry: Arc<TelemetryStore>,
    pub scan_manager: Arc<ScanManager>,
    pub response_engine: Arc<ResponseEngine>,
    pub config: Arc<tokio::sync::RwLock<CoreConfig>>,
}

#[derive(Debug, Serialize)]
struct ApiStatus {
    system_status: String,
    stats: StatsSnapshot,
    threats: Vec<ApiThreat>,
    health: SystemHealth,
    scan: Option<ScanSummary>,
}

#[derive(Debug, Serialize)]
struct ScanStartResponse {
    id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct ScanStopResponse {
    status: String,
}

#[derive(Debug, Serialize)]
struct SettingsResponse {
    tick_ms: u64,
    log_kernel_events: bool,
    log_kernel_filter: String,
    exclude_programs: Vec<String>,
    firewall_enabled: bool,
    ai_scan_enabled: bool,
    device_scan_enabled: bool,
    device_scan_mode: String,
    device_scan_interval_ms: u64,
    device_scan_removable_only: bool,
    yara_enabled: bool,
    yara_rules_path: String,
    yara_max_bytes: u64,
    ml_model_path: String,
    ml_score_threshold: f32,
    ml_max_bytes: u64,
    archive_scan_enabled: bool,
    archive_max_bytes: u64,
    archive_max_entries: u64,
    archive_entry_max_bytes: u64,
    external_scan_enabled: bool,
    external_scan_mode: String,
    external_scan_max_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct SettingsUpdate {
    tick_ms: Option<u64>,
    log_kernel_events: Option<bool>,
    log_kernel_filter: Option<String>,
    exclude_programs: Option<Vec<String>>,
    firewall_enabled: Option<bool>,
    ai_scan_enabled: Option<bool>,
    device_scan_enabled: Option<bool>,
    device_scan_mode: Option<String>,
    device_scan_interval_ms: Option<u64>,
    device_scan_removable_only: Option<bool>,
    yara_enabled: Option<bool>,
    yara_rules_path: Option<String>,
    yara_max_bytes: Option<u64>,
    ml_model_path: Option<String>,
    ml_score_threshold: Option<f32>,
    ml_max_bytes: Option<u64>,
    archive_scan_enabled: Option<bool>,
    archive_max_bytes: Option<u64>,
    archive_max_entries: Option<u64>,
    archive_entry_max_bytes: Option<u64>,
    external_scan_enabled: Option<bool>,
    external_scan_mode: Option<String>,
    external_scan_max_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct QuarantineItemResponse {
    id: String,
    threat_id: String,
    file_name: String,
    original_path: String,
    quarantined_path: String,
    quarantined_at: u64,
    size_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct QuarantineAddRequest {
    path: String,
}

#[derive(Debug, Deserialize)]
struct QuarantineActionRequest {
    id: String,
}

#[derive(Debug, Deserialize)]
struct ThreatAllowRequest {
    threat_id: Option<String>,
    target: String,
}

#[derive(Debug, Serialize)]
struct ActionResponse {
    status: String,
    message: Option<String>,
}

pub async fn serve(addr: String, state: ApiState) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/api/status", get(status))
        .route("/api/scan/quick", post(scan_quick))
        .route("/api/scan/full", post(scan_full))
        .route("/api/scan/status", get(scan_status))
        .route("/api/scan/stop", post(scan_stop))
        .route("/api/threats/allow", post(threat_allow))
        .route("/api/quarantine", get(quarantine_list))
        .route("/api/quarantine/add", post(quarantine_add))
        .route("/api/quarantine/restore", post(quarantine_restore))
        .route("/api/quarantine/delete", post(quarantine_delete))
        .route("/api/settings", get(settings_get).put(settings_update))
        .with_state(state)
        .layer(cors_layer());

    let addr: SocketAddr = addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn status(State(state): State<ApiState>) -> Json<ApiStatus> {
    let stats = state.telemetry.snapshot_stats().await;
    let threats = state.telemetry.snapshot_threats().await;
    let health = state.telemetry.health_snapshot().await;
    let scan = state.scan_manager.status().await;
    let system_status = system_status_from_threats(&threats);

    Json(ApiStatus {
        system_status,
        stats,
        threats,
        health,
        scan,
    })
}

async fn scan_quick(State(state): State<ApiState>) -> Json<ScanStartResponse> {
    let scan_config = {
        let config = state.config.read().await;
        ScanRuntimeConfig::from_config(&config)
    };

    match state
        .scan_manager
        .start_scan(ScanMode::Quick, scan_config)
        .await
    {
        Ok(summary) => Json(ScanStartResponse {
            id: summary.id,
            status: "started".to_string(),
        }),
        Err(error) => Json(ScanStartResponse {
            id: String::new(),
            status: error,
        }),
    }
}

async fn scan_full(State(state): State<ApiState>) -> Json<ScanStartResponse> {
    let scan_config = {
        let config = state.config.read().await;
        ScanRuntimeConfig::from_config(&config)
    };

    match state
        .scan_manager
        .start_scan(ScanMode::Full, scan_config)
        .await
    {
        Ok(summary) => Json(ScanStartResponse {
            id: summary.id,
            status: "started".to_string(),
        }),
        Err(error) => Json(ScanStartResponse {
            id: String::new(),
            status: error,
        }),
    }
}

async fn scan_status(State(state): State<ApiState>) -> Json<Option<ScanSummary>> {
    Json(state.scan_manager.status().await)
}

async fn scan_stop(State(state): State<ApiState>) -> Json<ScanStopResponse> {
    let status = if state.scan_manager.cancel_scan().await {
        "stopping"
    } else {
        "idle"
    };

    Json(ScanStopResponse {
        status: status.to_string(),
    })
}

async fn settings_get(State(state): State<ApiState>) -> Json<SettingsResponse> {
    let config = state.config.read().await;
    Json(settings_from_config(&config))
}

async fn settings_update(
    State(state): State<ApiState>,
    Json(payload): Json<SettingsUpdate>,
) -> Json<SettingsResponse> {
    let mut config = state.config.write().await;
    let previous_yara_enabled = config.yara_enabled;
    let previous_yara_path = config.yara_rules_path.clone();
    let previous_ml_path = config.ml_model_path.clone();

    if let Some(tick_ms) = payload.tick_ms {
        config.set_tick_ms(tick_ms);
    }

    if let Some(enabled) = payload.log_kernel_events {
        config.log_kernel_events = enabled;
    }

    if let Some(filter) = payload.log_kernel_filter {
        let normalized = filter.trim().to_ascii_lowercase();
        config.log_kernel_filter = if normalized.is_empty() {
            "all".to_string()
        } else {
            normalized
        };
    }

    if let Some(entries) = payload.exclude_programs {
        config.set_exclude_programs(entries);
    }

    if let Some(enabled) = payload.firewall_enabled {
        config.firewall_enabled = enabled;
    }

    if let Some(enabled) = payload.ai_scan_enabled {
        config.ai_scan_enabled = enabled;
    }

    if let Some(enabled) = payload.device_scan_enabled {
        config.device_scan_enabled = enabled;
    }

    if let Some(mode) = payload.device_scan_mode {
        config.set_device_scan_mode(&mode);
    }

    if let Some(value) = payload.device_scan_interval_ms {
        config.set_device_scan_interval_ms(value);
    }

    if let Some(enabled) = payload.device_scan_removable_only {
        config.device_scan_removable_only = enabled;
    }

    if let Some(enabled) = payload.yara_enabled {
        config.yara_enabled = enabled;
    }

    if let Some(path) = payload.yara_rules_path {
        config.set_yara_rules_path(path);
    }

    if let Some(value) = payload.yara_max_bytes {
        config.set_yara_max_bytes(value);
    }

    if let Some(path) = payload.ml_model_path {
        config.set_ml_model_path(path);
    }

    if let Some(value) = payload.ml_score_threshold {
        config.set_ml_score_threshold(value);
    }

    if let Some(value) = payload.ml_max_bytes {
        config.set_ml_max_bytes(value);
    }

    if let Some(enabled) = payload.archive_scan_enabled {
        config.archive_scan_enabled = enabled;
    }

    if let Some(value) = payload.archive_max_bytes {
        config.set_archive_max_bytes(value);
    }

    if let Some(value) = payload.archive_max_entries {
        config.set_archive_max_entries(value);
    }

    if let Some(value) = payload.archive_entry_max_bytes {
        config.set_archive_entry_max_bytes(value);
    }

    if let Some(enabled) = payload.external_scan_enabled {
        config.external_scan_enabled = enabled;
    }

    if let Some(mode) = payload.external_scan_mode {
        config.set_external_scan_mode(&mode);
    }

    if let Some(value) = payload.external_scan_max_bytes {
        config.set_external_scan_max_bytes(value);
    }

    if config.yara_enabled
        && (config.yara_rules_path != previous_yara_path
            || (!previous_yara_enabled && config.yara_enabled))
    {
        state
            .scan_manager
            .reload_yara(PathBuf::from(&config.yara_rules_path));
    }

    if config.ml_model_path != previous_ml_path {
        state
            .scan_manager
            .reload_ml_model(PathBuf::from(&config.ml_model_path));
    }

    Json(settings_from_config(&config))
}

async fn threat_allow(
    State(state): State<ApiState>,
    Json(payload): Json<ThreatAllowRequest>,
) -> (StatusCode, Json<ActionResponse>) {
    let target = payload.target.trim();
    if target.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                status: "error".to_string(),
                message: Some("Target is required".to_string()),
            }),
        );
    }

    {
        let mut config = state.config.write().await;
        let mut entries = config.exclude_programs.clone();
        entries.push(target.to_string());
        config.set_exclude_programs(entries);
    }

    if let Some(threat_id) = payload.threat_id.as_ref() {
        let _ = state
            .telemetry
            .update_threat_action(threat_id, "Allowed")
            .await;
    }

    (
        StatusCode::OK,
        Json(ActionResponse {
            status: "allowed".to_string(),
            message: None,
        }),
    )
}

async fn quarantine_list(State(state): State<ApiState>) -> Json<Vec<QuarantineItemResponse>> {
    let items = state.response_engine.list_quarantine();
    let response = items
        .into_iter()
        .map(|item| QuarantineItemResponse {
            id: item.id,
            threat_id: item.threat_id,
            file_name: item.file_name,
            original_path: item.original_path.to_string_lossy().to_string(),
            quarantined_path: item.quarantined_path.to_string_lossy().to_string(),
            quarantined_at: item
                .quarantined_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            size_bytes: item.size_bytes,
        })
        .collect();

    Json(response)
}

async fn quarantine_add(
    State(state): State<ApiState>,
    Json(payload): Json<QuarantineAddRequest>,
) -> (StatusCode, Json<ActionResponse>) {
    let path = std::path::PathBuf::from(payload.path.trim());
    if path.as_os_str().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                status: "error".to_string(),
                message: Some("Path is required".to_string()),
            }),
        );
    }

    match state.response_engine.manual_quarantine(path) {
        Ok(_) => {
            state.telemetry.record_action(ResponseAction::Quarantine).await;
            (
            StatusCode::OK,
            Json(ActionResponse {
                status: "quarantined".to_string(),
                message: None,
            }),
            )
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                status: "error".to_string(),
                message: Some(error),
            }),
        ),
    }
}

async fn quarantine_restore(
    State(state): State<ApiState>,
    Json(payload): Json<QuarantineActionRequest>,
) -> (StatusCode, Json<ActionResponse>) {
    match state.response_engine.restore_quarantine(&payload.id) {
        Ok(()) => (
            StatusCode::OK,
            Json(ActionResponse {
                status: "restored".to_string(),
                message: None,
            }),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                status: "error".to_string(),
                message: Some(error),
            }),
        ),
    }
}

async fn quarantine_delete(
    State(state): State<ApiState>,
    Json(payload): Json<QuarantineActionRequest>,
) -> (StatusCode, Json<ActionResponse>) {
    match state.response_engine.delete_quarantine(&payload.id) {
        Ok(()) => (
            StatusCode::OK,
            Json(ActionResponse {
                status: "deleted".to_string(),
                message: None,
            }),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                status: "error".to_string(),
                message: Some(error),
            }),
        ),
    }
}

fn cors_layer() -> CorsLayer {
    let allowed = std::env::var("AEGIS_CORS_ORIGIN").unwrap_or_else(|_| {
        "http://localhost:5173,http://127.0.0.1:5173".to_string()
    });

    let mut cors = if allowed.trim() == "*" {
        CorsLayer::new().allow_origin(Any)
    } else {
        let origins = allowed
            .split(',')
            .filter_map(|origin| origin.trim().parse::<HeaderValue>().ok())
            .collect::<Vec<_>>();
        CorsLayer::new().allow_origin(AllowOrigin::list(origins))
    };

    cors = cors.allow_methods([Method::GET, Method::POST, Method::PUT]);
    cors.allow_headers([header::CONTENT_TYPE, header::ACCEPT])
}

fn settings_from_config(config: &CoreConfig) -> SettingsResponse {
    SettingsResponse {
        tick_ms: config.tick_ms(),
        log_kernel_events: config.log_kernel_events,
        log_kernel_filter: config.log_kernel_filter.clone(),
        exclude_programs: config.exclude_programs.clone(),
        firewall_enabled: config.firewall_enabled,
        ai_scan_enabled: config.ai_scan_enabled,
        device_scan_enabled: config.device_scan_enabled,
        device_scan_mode: config.device_scan_mode.clone(),
        device_scan_interval_ms: config.device_scan_interval_ms,
        device_scan_removable_only: config.device_scan_removable_only,
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
