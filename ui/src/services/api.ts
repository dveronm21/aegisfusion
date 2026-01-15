export type SystemStatus = 'protected' | 'warning' | 'critical';
export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export type Threat = {
  id: string;
  timestamp: number;
  name: string;
  file: string;
  action: string;
  confidence: number;
  severity: ThreatSeverity;
};

export type Stats = {
  scanned: number;
  blocked: number;
  quarantined: number;
  uptime: string;
};

export type SystemHealth = {
  cpu_percent: number;
  memory_mb: number;
  memory_percent: number;
  disk_used_percent: number;
  network_kbps: number;
};

export type ScanSummary = {
  id: string;
  mode: 'Quick' | 'Full';
  status: 'Queued' | 'Running' | 'Completed' | 'Failed' | 'Cancelled';
  scanned_files: number;
  threats_found: number;
};

export type ScanStartResponse = {
  id: string;
  status: string;
};

export type ScanStopResponse = {
  status: string;
};

export type ApiStatus = {
  system_status: SystemStatus;
  stats: Stats;
  threats: Threat[];
  health: SystemHealth;
  scan?: ScanSummary | null;
};

export type QuarantineItem = {
  id: string;
  threat_id: string;
  file_name: string;
  original_path: string;
  quarantined_path: string;
  quarantined_at: number;
  size_bytes: number;
};

export type Settings = {
  tick_ms: number;
  log_kernel_events: boolean;
  log_kernel_filter: string;
  exclude_programs: string[];
  firewall_enabled: boolean;
  ai_scan_enabled: boolean;
  device_scan_enabled: boolean;
  device_scan_mode: 'quick' | 'full' | string;
  device_scan_interval_ms: number;
  device_scan_removable_only: boolean;
  yara_enabled: boolean;
  yara_rules_path: string;
  yara_max_bytes: number;
  ml_model_path: string;
  ml_score_threshold: number;
  ml_max_bytes: number;
  archive_scan_enabled: boolean;
  archive_max_bytes: number;
  archive_max_entries: number;
  archive_entry_max_bytes: number;
  external_scan_enabled: boolean;
  external_scan_mode: string;
  external_scan_max_bytes: number;
};

type ActionResponse = {
  status: string;
  message?: string;
};

const API_BASE =
  import.meta.env.VITE_API_URL?.toString() || 'http://localhost:8090';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `HTTP ${response.status}`);
  }

  return (await response.json()) as T;
}

export async function getStatus(): Promise<ApiStatus> {
  return request<ApiStatus>('/api/status', { method: 'GET' });
}

export async function startScan(
  mode: 'quick' | 'full'
): Promise<ScanStartResponse> {
  return request<ScanStartResponse>(`/api/scan/${mode}`, { method: 'POST' });
}

export async function stopScan(): Promise<ScanStopResponse> {
  return request<ScanStopResponse>('/api/scan/stop', { method: 'POST' });
}

export async function getQuarantine(): Promise<QuarantineItem[]> {
  return request<QuarantineItem[]>('/api/quarantine', { method: 'GET' });
}

export async function addQuarantine(path: string): Promise<ActionResponse> {
  return request<ActionResponse>('/api/quarantine/add', {
    method: 'POST',
    body: JSON.stringify({ path }),
  });
}

export async function restoreQuarantine(id: string): Promise<ActionResponse> {
  return request<ActionResponse>('/api/quarantine/restore', {
    method: 'POST',
    body: JSON.stringify({ id }),
  });
}

export async function deleteQuarantine(id: string): Promise<ActionResponse> {
  return request<ActionResponse>('/api/quarantine/delete', {
    method: 'POST',
    body: JSON.stringify({ id }),
  });
}

export async function allowThreat(
  target: string,
  threat_id?: string
): Promise<ActionResponse> {
  return request<ActionResponse>('/api/threats/allow', {
    method: 'POST',
    body: JSON.stringify({ target, threat_id }),
  });
}

export async function getSettings(): Promise<Settings> {
  return request<Settings>('/api/settings', { method: 'GET' });
}

export async function updateSettings(update: Partial<Settings>): Promise<Settings> {
  return request<Settings>('/api/settings', {
    method: 'PUT',
    body: JSON.stringify(update),
  });
}
