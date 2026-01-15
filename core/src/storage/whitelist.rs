use std::collections::HashSet;

use tokio::sync::RwLock;

pub struct Whitelist {
    entries: RwLock<HashSet<String>>,
}

impl Whitelist {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashSet::new()),
        }
    }

    pub async fn is_allowed(&self, process_name: &str) -> bool {
        let entries = self.entries.read().await;
        entries
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(process_name))
    }

    pub async fn add(&self, process_name: String) {
        let mut entries = self.entries.write().await;
        entries.insert(process_name);
    }
}
