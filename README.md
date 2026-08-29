<div align="center">

# 🛡️ Aegis Fusion

### Arquitectura de seguridad para endpoints con detección explicable y alta visibilidad

**Núcleo en Rust · API en Go · React/TypeScript · Telemetría Windows/Linux · Detección asistida por aprendizaje automático**

[![Seguridad](https://img.shields.io/badge/enfoque-seguridad%20de%20endpoints-0A66C2?style=for-the-badge)](#)
[![Arquitectura](https://img.shields.io/badge/arquitectura-modular-111827?style=for-the-badge)](#arquitectura)
[![Rust](https://img.shields.io/badge/n%C3%BAcleo-Rust-000000?style=for-the-badge&logo=rust)](#tecnolog%C3%ADas)
[![Go](https://img.shields.io/badge/API-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](#tecnolog%C3%ADas)
[![React](https://img.shields.io/badge/panel-React-61DAFB?style=for-the-badge&logo=react&logoColor=111827)](#tecnolog%C3%ADas)

*Proyecto público para mostrar la arquitectura y la evolución de una plataforma de protección de endpoints en desarrollo.*

</div>

---

## ¿Por qué existe este proyecto?

Aegis Fusion explora cómo construir una plataforma de seguridad para endpoints que combine **controles determinísticos, telemetría de bajo nivel y puntuación mediante modelos de aprendizaje automático**, sin convertir las detecciones en una caja negra.

El diseño prioriza:

- **Explicabilidad:** cada alerta debe mostrar qué regla, señal o puntaje llevó a tomar una decisión.
- **Resiliencia:** el endpoint debe seguir funcionando aunque pierda conexión con la nube.
- **Identidad fuerte del dispositivo:** certificados por equipo y comunicación mediante mTLS.
- **Modularidad:** endpoint, nube, interfaz y analítica pueden evolucionar de forma independiente.
- **Seguridad primero:** las reglas determinísticas son la base; el aprendizaje automático complementa, no reemplaza, esa lógica.

## Arquitectura

```text
┌───────────────────────────────────────────────────────────┐
│                   Panel de control                        │
│                  React + TypeScript                       │
└────────────────────────────┬──────────────────────────────┘
                             │
┌────────────────────────────▼──────────────────────────────┐
│                    API en la nube                         │
│                         Go                                │
│        Políticas · Inteligencia · Tareas · Clientes       │
└────────────────────────────┬──────────────────────────────┘
                             │ mTLS
┌────────────────────────────▼──────────────────────────────┐
│                    Agente principal                       │
│                         Rust                              │
│       Motor de reglas · Inferencia ML · Búfer local       │
└────────────────────────────┬──────────────────────────────┘
                             │
┌────────────────────────────▼──────────────────────────────┐
│                Telemetría de bajo nivel                   │
│              Windows WDM / Linux LKM                      │
│          Procesos · Archivos · Eventos de red             │
└───────────────────────────────────────────────────────────┘
```

## Puntos fuertes de ingeniería

| Capacidad | Enfoque |
|---|---|
| Detección de comportamiento | Puntuación asistida por LSTM, CNN y Transformer sobre telemetría del endpoint |
| Visibilidad de bajo nivel | Recolección de eventos mediante Windows WDM y Linux LKM |
| Controles determinísticos | Motor de reglas como primera capa de decisión |
| Inspección estática | Integración con YARA |
| Confianza del dispositivo | Certificados por endpoint y mTLS |
| Operación sin conexión | Búfer local, reintentos y degradación controlada |
| Detecciones explicables | Regla, puntaje y señales asociadas a cada alerta |
| Gestión centralizada | Políticas, tareas e inteligencia de amenazas desde la nube |

## Tecnologías

```text
Núcleo del endpoint   Rust
API en la nube        Go
Panel web             React + TypeScript
Telemetría Windows    WDM
Telemetría Linux      LKM
Capa de ML            LSTM / CNN / Transformer
Firmas                 YARA
Transporte seguro      mTLS
Orquestación           Docker Compose
```

## Filosofía de seguridad

> **Determinístico cuando se puede. Probabilístico cuando aporta valor. Explicable siempre.**

Aegis Fusion separa deliberadamente la recolección de eventos, las reglas, el enriquecimiento y la puntuación mediante modelos. La idea es que cada detección pueda rastrearse y entenderse, en vez de depender de un único modelo opaco.

## Documentación del repositorio

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — arquitectura técnica, contratos y modelo de amenazas.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — evolución prevista del proyecto.
- Repositorio privado del núcleo — implementación, entorno local y componentes internos.

## Estado actual

Este repositorio funciona como **presentación pública de arquitectura y producto**. La implementación continúa evolucionando y algunos componentes del núcleo permanecen privados mientras se documentan públicamente las decisiones técnicas principales.

## Qué demuestra este proyecto

Aegis Fusion refleja experiencia práctica en:

- arquitectura de seguridad para endpoints;
- programación de sistemas;
- diseño de sistemas distribuidos seguros;
- observabilidad y procesamiento de eventos;
- detección explicable;
- integración Windows/Linux;
- documentación técnica orientada a producto.

## Colaboración

Son bienvenidos los aportes técnicos, revisiones de arquitectura y conversaciones sobre ingeniería de seguridad a través de GitHub.

Apoyo al proyecto:

- [GitHub Sponsors](https://github.com/sponsors/dveronm21)
- [Ko-fi](https://ko-fi.com/douglasveron)

## Licencia

Propietaria. El código fuente del núcleo y determinados componentes de implementación no forman parte de este repositorio público.

---

<div align="center">

**Desarrollado por [Douglas Verón](https://github.com/dveronm21)**

*Infraestructura · Redes · Ciberseguridad · Automatización · Ingeniería de software*

</div>
