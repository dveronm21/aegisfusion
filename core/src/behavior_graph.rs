use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug)]
pub struct GraphNode {
    pub id: String,
    pub node_type: String,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub reputation: f32,
    pub connections: Vec<String>,
}

#[derive(Debug)]
pub struct BehaviorGraph {
    nodes: HashMap<String, GraphNode>,
    edges: Vec<(String, String, String)>,
}

impl BehaviorGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, id: String, node_type: String) {
        if self.nodes.contains_key(&id) {
            return;
        }

        let node = GraphNode {
            id: id.clone(),
            node_type,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            reputation: 0.5,
            connections: Vec::new(),
        };

        self.nodes.insert(id, node);
    }

    pub fn add_edge(&mut self, from: String, to: String, action: String) {
        self.edges.push((from.clone(), to.clone(), action));
        if let Some(node) = self.nodes.get_mut(&from) {
            node.connections.push(to);
        }
    }

    pub fn detect_anomalies(&self) -> Vec<String> {
        let mut anomalies = Vec::new();
        for (id, node) in &self.nodes {
            if node.connections.len() > 50 {
                anomalies.push(format!(
                    "Node {} has {} connections",
                    id,
                    node.connections.len()
                ));
            }
        }
        anomalies
    }
}
