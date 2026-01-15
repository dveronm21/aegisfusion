use crate::types::SystemEvent;

pub struct InferenceEngine;

impl InferenceEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn score_event(&self, _event: &SystemEvent) -> Option<f32> {
        // TODO: integrar con runtime ONNX y modelos entrenados.
        None
    }
}
