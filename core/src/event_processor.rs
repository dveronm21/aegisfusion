use crate::types::{SystemEvent, ThreatVerdict, ThreatType, ResponseAction};

pub struct EventProcessor;

impl EventProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process_event(&self, _event: &SystemEvent) -> Option<ThreatVerdict> {
        // TODO: implementar pipeline real de scoring.
        None
    }

    pub fn default_verdict(&self) -> ThreatVerdict {
        ThreatVerdict {
            is_malicious: false,
            confidence: 0.0,
            threat_type: ThreatType::Benign,
            reasons: vec!["No indicators".to_string()],
            recommended_action: ResponseAction::Monitor,
        }
    }
}
