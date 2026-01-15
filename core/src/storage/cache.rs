use std::collections::HashMap;

use tokio::sync::RwLock;

pub struct Cache<T> {
    inner: RwLock<HashMap<String, T>>,
}

impl<T: Clone> Cache<T> {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get(&self, key: &str) -> Option<T> {
        let cache = self.inner.read().await;
        cache.get(key).cloned()
    }

    pub async fn set(&self, key: String, value: T) {
        let mut cache = self.inner.write().await;
        cache.insert(key, value);
    }
}
