<div align="center">

# 🛡️ Aegis Fusion

### Endpoint security architecture for high-visibility, explainable detection

**Rust core · Go cloud API · React/TypeScript · Windows/Linux telemetry · ML-assisted detection**

[![Security](https://img.shields.io/badge/focus-endpoint%20security-0A66C2?style=for-the-badge)](#)
[![Architecture](https://img.shields.io/badge/architecture-modular-111827?style=for-the-badge)](#architecture)
[![Rust](https://img.shields.io/badge/core-Rust-000000?style=for-the-badge&logo=rust)](#technology-stack)
[![Go](https://img.shields.io/badge/API-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](#technology-stack)
[![React](https://img.shields.io/badge/dashboard-React-61DAFB?style=for-the-badge&logo=react&logoColor=111827)](#technology-stack)

*A public architecture showcase for a broader endpoint-protection platform under active development.*

</div>

---

## Why this project exists

Aegis Fusion explores how an endpoint security platform can combine **deterministic security controls, low-level telemetry and machine-learning scoring** without turning detections into a black box.

The design prioritizes:

- **Explainability** — alerts should expose the rule, score and signals behind the decision.
- **Resilience** — endpoints must keep operating when cloud connectivity is unavailable.
- **Strong device identity** — certificate-based endpoint identity and mTLS between components.
- **Modularity** — endpoint, cloud, UI and analytics layers evolve independently.
- **Security-first engineering** — rules remain the primary decision layer; ML augments rather than replaces them.

## Architecture

```text
┌───────────────────────────────────────────────────────────┐
│                     UI Dashboard                          │
│                  React + TypeScript                       │
└────────────────────────────┬──────────────────────────────┘
                             │
┌────────────────────────────▼──────────────────────────────┐
│                       Cloud API                           │
│                         Go                                │
│        Policies · Threat Intel · Jobs · Multi-tenant      │
└────────────────────────────┬──────────────────────────────┘
                             │ mTLS
┌────────────────────────────▼──────────────────────────────┐
│                       Core Agent                          │
│                         Rust                              │
│        Rules Engine · ML Inference · Local Buffer         │
└────────────────────────────┬──────────────────────────────┘
                             │
┌────────────────────────────▼──────────────────────────────┐
│                    Kernel Telemetry                       │
│              Windows WDM / Linux LKM                      │
│             Process · File · Network Events               │
└───────────────────────────────────────────────────────────┘
```

## Engineering highlights

| Capability | Design direction |
|---|---|
| Behavioral detection | LSTM/CNN/Transformer-assisted scoring over endpoint telemetry |
| Low-level visibility | Windows WDM and Linux LKM telemetry collection |
| Deterministic controls | Rules-first detection pipeline |
| Static inspection | YARA integration |
| Device trust | Per-endpoint certificates and mTLS |
| Offline operation | Local event buffering with retry and graceful degradation |
| Detection transparency | Rule ID, score and contributing signals attached to alerts |
| Cloud management | Policy, jobs and threat-intelligence services |

## Technology stack

```text
Endpoint Core      Rust
Cloud API          Go
Dashboard          React + TypeScript
Windows telemetry  WDM
Linux telemetry    LKM
ML layer           LSTM / CNN / Transformer
Signatures         YARA
Transport          mTLS
Orchestration      Docker Compose
```

## Security philosophy

> **Deterministic when possible. Probabilistic when useful. Explainable always.**

Aegis Fusion intentionally separates collection, deterministic rules, enrichment and ML scoring. The goal is to make every detection traceable instead of relying on an opaque single-model verdict.

## Repository map

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — technical architecture, contracts and threat model.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — implementation roadmap and planned milestones.
- Private core repository — implementation details, local development environment and internal components.

## Current status

This repository is the **public architecture and product showcase** for Aegis Fusion. The implementation is evolving and selected core components remain private while the architecture, roadmap and engineering decisions are documented publicly.

## What this demonstrates

This project is also a portfolio piece focused on:

- endpoint security architecture;
- systems programming;
- secure distributed-system design;
- observability and event pipelines;
- explainable detection engineering;
- cross-platform Windows/Linux integration;
- product-oriented technical documentation.

## Collaboration

Technical feedback, architecture discussions and security engineering collaboration are welcome through GitHub.

Support links:

- [GitHub Sponsors](https://github.com/sponsors/dveronm21)
- [Ko-fi](https://ko-fi.com/douglasveron)

## License

Proprietary. Core source code and selected implementation components are not part of this public repository.

---

<div align="center">

**Built by [Douglas Verón](https://github.com/dveronm21)**

*Infrastructure · Networking · Cybersecurity · Automation · Software Engineering*

</div>
