# Local Dev Quickstart

Guia rapida para levantar el entorno local de Aegis Fusion.

## Opcion A: docker compose (cloud y servicios)

Desde el root del repo:

```powershell
docker compose up --build
```

Servicios principales:
- Cloud API: http://localhost:8081
- Threat Intel: http://localhost:9090
- Redis: 6379
- Postgres: 5432
- Kafka/Zookeeper

Notas:
- El API usa `AEGIS_API_KEYS` en docker-compose.yml.
- Uploads se guardan en `./data/uploads`.
- Sandbox escribe reportes en `./data/sandbox_reports`.

## Opcion B: start_all.ps1 (local)

Levanta core + UI y opcionalmente cloud local.

```powershell
.\start_all.ps1
```

Para usar cloud local (Go):

```powershell
.\start_all.ps1 -LocalCloud
```

Flags utiles:
- `-SkipDocker` no levanta docker.
- `-SkipCore` no levanta core.
- `-SkipUi` no levanta UI.
- `-Release` usa `cargo run --release`.

## Puertos por defecto

- Core API: http://localhost:8090
- UI: http://localhost:5173
- Cloud API: http://localhost:8081

## Variables clave

- `AEGIS_CLOUD_URL` y `AEGIS_CLOUD_API_KEY` (core -> cloud)
- `VITE_API_URL` (UI -> core API)
- `AEGIS_API_KEYS` (cloud auth)
