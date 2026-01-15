use crate::config::CoreConfig;

pub struct CoreEngine {
    _config: CoreConfig,
}

impl CoreEngine {
    pub fn new(config: CoreConfig) -> Self {
        Self { _config: config }
    }

    pub async fn run(&self) {
        // TODO: conectar el pipeline real de eventos y respuesta.
    }
}
