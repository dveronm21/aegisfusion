# Aegis Fusion

Next-generation endpoint protection platform built with a security-first, modular architecture.

## Stack

| Layer | Technology |
|---|---|
| Core engine | Rust |
| Cloud API | Go |
| UI Dashboard | React + TypeScript |
| Kernel drivers | Windows (WDM) / Linux (LKM) |
| ML models | LSTM, CNN, Transformer |
| Orchestration | Docker Compose |

## Architecture

`
┌─────────────────────────────────────────┐
│              UI Dashboard               │  React + TypeScript
└─────────────────────┬───────────────────┘
                      │
┌─────────────────────▼───────────────────┐
│              Cloud API                  │  Go · multi-tenant
│   Policies · Threat Intel · Jobs        │
└─────────────────────┬───────────────────┘
                      │ mTLS
┌─────────────────────▼───────────────────┐
│             Core Agent                  │  Rust
│  Rules engine · ML inference · Buffer   │
└─────────────────────┬───────────────────┘
                      │
┌─────────────────────▼───────────────────┐
│           Kernel Driver                 │  Windows WDM / Linux LKM
│  Process · File · Network telemetry     │
└─────────────────────────────────────────┘
`

## Key Features

- **Behavioral detection** — LSTM/CNN models trained on process telemetry
- **Kernel-level visibility** — Windows WDM and Linux LKM drivers for low-level event capture
- **Rules-first approach** — deterministic rules as primary layer, ML as scoring layer
- **mTLS end-to-end** — device identity via TPM-backed keys, certificate per endpoint
- **Offline resilience** — local buffer with retry, graceful degradation without cloud
- **YARA integration** — static signature scanning alongside behavioral analysis
- **Explainable detections** — every alert includes top features, score, and rule ID

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — full technical design, contracts, and threat model
- [Roadmap](docs/ROADMAP.md) — planned milestones
- Install guide and local dev setup available in the private core repository

## Support

Building driver signing infrastructure and cloud scaling.

- [GitHub Sponsors](https://github.com/sponsors/dveronm21)
- [Ko-fi](https://ko-fi.com/douglasveron)

## License

Proprietary — core source available to sponsors and collaborators.