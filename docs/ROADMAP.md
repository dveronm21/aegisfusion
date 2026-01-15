# Roadmap

## Fase 1 - MVP (telemetria + politicas + alertas)

- Contrato de eventos versionado.
- Telemetria basica desde driver y agente.
- Politicas basicas (ruleset, exclusiones).
- Alertas y timeline en UI.
- Inventario de endpoints en cloud.

## Fase 2 - Enforcement (kill/quarantine/isolate)

- Acciones en agente: kill, quarantine, block network.
- Integracion con políticas en cloud.
- Escaneo bajo demanda (quick/full).
- Jobs distribuidos y tracking de estado.

## Fase 3 - Hardening

- mTLS por endpoint + rotacion de certificados.
- Firma de binarios y driver.
- Rollback y staged rollout.
- Modo degradado sin driver.
- Observabilidad avanzada (latencias, health, SLO).
