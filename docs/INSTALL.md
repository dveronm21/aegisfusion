# Aegis Fusion - Installation Guide (Repo-Accurate)

This guide reflects the current repository layout and build steps.

## Prerequisites
- Windows 10/11 (x64) for the core service.
- Rust stable (for `core`).
- Node.js 20+ (for `ui`).
- Go 1.22+ (for `cloud/api`).
- Docker Desktop (optional, for `docker-compose.yml`).

## Build the Core Service
From the repo root:

```powershell
cd core
cargo build --release
```

Output:
```
core\target\release\aegis-fusion-core.exe
```

## Run Core (Console Mode)
```powershell
cd core
.\target\release\aegis-fusion-core.exe
```

Default local API: `http://127.0.0.1:8090/api/status`

## Run Core as Windows Service
The service mode is built into the same binary.

Manual install:
```powershell
# Run PowerShell as Administrator
sc.exe create AegisFusionCore binPath= "\"C:\path\to\aegis-fusion-core.exe\" --service" start= auto
sc.exe start AegisFusionCore
```

Manual uninstall:
```powershell
sc.exe stop AegisFusionCore
sc.exe delete AegisFusionCore
```

Installer (Inno Setup):
1) Build the core in release.
2) Open `installer\windows\setup.iss` with Inno Setup.
3) Build the installer. It registers the service automatically.

## UI (Dashboard)
```powershell
cd ui
$env:VITE_API_URL = "http://localhost:8090"
npm install
npm run dev
```

UI runs at `http://localhost:5173`.

## Cloud API (Go)
Run locally:
```powershell
cd cloud\api
go run .
```

Default API: `http://localhost:8081`

## Sandbox Service (Go)
The sandbox service watches the upload directory and pushes results back to the API.

```powershell
cd cloud\sandbox
$env:SANDBOX_UPLOAD_DIR = "..\api\uploads"
$env:SANDBOX_API_URL = "http://localhost:8081"
$env:SANDBOX_API_KEY = "your_key"
go run .
```

Docker (from repo root):
```powershell
docker compose up --build
```

Docker compose (repo root):
```powershell
docker compose up --build
```

## Environment Variables

### Core
- `AEGIS_API_ADDR` (default `127.0.0.1:8090`)
- `AEGIS_TICK_MS` (default `100`)
- `AEGIS_CLOUD_URL` (optional, enables cloud event push)
- `AEGIS_CLOUD_CLIENT_ID`
- `AEGIS_CLOUD_API_KEY`
- `AEGIS_CLOUD_TIMEOUT_SECS`

### Cloud API
- `PORT` (default `8081`)
- `AEGIS_UPLOAD_DIR` (default `./uploads`)
- `AEGIS_MAX_UPLOAD_MB` (default `50`)
- `AEGIS_ANALYSIS_CONCURRENCY` (default `4`)
- `AEGIS_API_KEYS` (comma-separated API keys)
- `AEGIS_CORS_ORIGIN` (comma-separated origins or `*`)
- `AEGIS_ANALYSIS_MODE` (`internal` or `sandbox`)

### Sandbox
- `SANDBOX_UPLOAD_DIR` (default `./uploads`)
- `SANDBOX_REPORT_DIR` (default `./reports`)
- `SANDBOX_API_URL` (optional, pushes results to API)
- `SANDBOX_API_KEY` (optional)
- `SANDBOX_WORKERS` (default `2`)
- `SANDBOX_POLL_MS` (default `2000`)
- `SANDBOX_MIN_AGE_SEC` (default `2`)
- `SANDBOX_MAX_READ_MB` (default `4`)

## Dev Convenience Script
`start_all.ps1` launches Docker, core, and UI in separate terminals.

```powershell
.\start_all.ps1
```

## Notes
- The kernel driver in `kernel/` is a separate build and install path.
- Running the core service requires Administrator privileges if you connect to the kernel driver.
