use std::time::Duration;

use reqwest::Client;
use serde::Serialize;

use crate::types::SystemEvent;

pub struct CloudSync {
    config: Option<CloudConfig>,
}

struct CloudConfig {
    client: Client,
    base_url: String,
    client_id: String,
    api_key: Option<String>,
}

#[derive(Serialize)]
struct EventPayload<'a> {
    client_id: &'a str,
    event: &'a SystemEvent,
}

impl CloudSync {
    pub fn new() -> Self {
        let base_url = std::env::var("AEGIS_CLOUD_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let Some(base_url) = base_url else {
            return Self { config: None };
        };

        let timeout_secs = std::env::var("AEGIS_CLOUD_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10);

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .ok();

        let client = match client {
            Some(client) => client,
            None => return Self { config: None },
        };

        let client_id = std::env::var("AEGIS_CLOUD_CLIENT_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "aegis-local".to_string());

        let api_key = std::env::var("AEGIS_CLOUD_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Self {
            config: Some(CloudConfig {
                client,
                base_url,
                client_id,
                api_key,
            }),
        }
    }

    pub async fn push_event(&self, event: &SystemEvent) -> Result<(), String> {
        let Some(config) = &self.config else {
            return Ok(());
        };

        let url = format!("{}/api/v1/events", config.base_url.trim_end_matches('/'));
        let payload = EventPayload {
            client_id: &config.client_id,
            event,
        };

        let mut request = config.client.post(url).json(&payload);
        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await.map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("cloud response {}", response.status()));
        }

        Ok(())
    }
}
