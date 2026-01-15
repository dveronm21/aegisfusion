"""
AEGIS FUSION - Advanced Behavior Graph Analyzer
Analisis de comportamiento mediante grafos y algoritmos de deteccion
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Set

import networkx as nx


# ============================================================================
# ESTRUCTURAS DE DATOS
# ============================================================================


@dataclass
class GraphNode:
    """Nodo en el grafo de comportamiento."""

    id: str
    type: str  # 'process', 'file', 'network', 'registry'
    name: str
    first_seen: datetime
    last_seen: datetime
    attributes: Dict
    reputation: float = 0.5

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class GraphEdge:
    """Arista en el grafo de comportamiento."""

    source: str
    target: str
    action: str  # 'created', 'modified', 'connected', 'read', 'wrote'
    timestamp: datetime
    metadata: Dict
    weight: float = 1.0


@dataclass
class ThreatPattern:
    """Patron de amenaza detectado."""

    pattern_type: str
    confidence: float
    nodes_involved: List[str]
    description: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    indicators: List[str]


# ============================================================================
# BEHAVIOR GRAPH ENGINE
# ============================================================================


class BehaviorGraphEngine:
    """Motor principal de analisis de grafos de comportamiento."""

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.threat_patterns: List[ThreatPattern] = []

        # Estadisticas
        self.stats = {
            "total_nodes": 0,
            "total_edges": 0,
            "processes": 0,
            "files": 0,
            "network_connections": 0,
            "registry_ops": 0,
        }

        print("[BG] Behavior Graph Engine initialized")

    def add_node(self, node: GraphNode) -> None:
        """Agregar nodo al grafo."""
        if node.id not in self.nodes:
            self.nodes[node.id] = node
            self.graph.add_node(
                node.id,
                **{
                    "type": node.type,
                    "name": node.name,
                    "reputation": node.reputation,
                    "attributes": node.attributes,
                },
            )
            self.stats["total_nodes"] += 1
            type_map = {
                "process": "processes",
                "file": "files",
                "network": "network_connections",
                "registry": "registry_ops",
            }
            stat_key = type_map.get(node.type)
            if stat_key:
                self.stats[stat_key] += 1

    def add_edge(self, edge: GraphEdge) -> None:
        """Agregar arista al grafo."""
        self.edges.append(edge)
        self.graph.add_edge(
            edge.source,
            edge.target,
            action=edge.action,
            timestamp=edge.timestamp,
            weight=edge.weight,
            metadata=edge.metadata,
        )
        self.stats["total_edges"] += 1

    # ========================================================================
    # DETECCION DE PATRONES MALICIOSOS
    # ========================================================================

    def detect_process_injection(self) -> List[ThreatPattern]:
        """Detectar inyeccion de codigo en procesos."""
        patterns: List[ThreatPattern] = []

        for node_id in self.graph.nodes():
            node = self.nodes.get(node_id)
            if node and node.type == "process":
                for successor in self.graph.successors(node_id):
                    successor_node = self.nodes.get(successor)
                    if successor_node and successor_node.type == "process":
                        edges = self.graph.get_edge_data(node_id, successor)
                        for _, edge_data in edges.items():
                            if edge_data.get("action") in ["wrote_memory", "injected"]:
                                patterns.append(
                                    ThreatPattern(
                                        pattern_type="process_injection",
                                        confidence=0.85,
                                        nodes_involved=[node_id, successor],
                                        description=(
                                            f"Process {node.name} injected code into "
                                            f"{successor_node.name}"
                                        ),
                                        severity="high",
                                        indicators=[
                                            "WriteProcessMemory detected",
                                            "Cross-process memory access",
                                            f"Source: {node.name}",
                                            f"Target: {successor_node.name}",
                                        ],
                                    )
                                )

        return patterns

    def detect_ransomware_behavior(self) -> List[ThreatPattern]:
        """Detectar comportamiento de ransomware."""
        patterns: List[ThreatPattern] = []
        file_modifications: Dict[str, List[str]] = defaultdict(list)

        for node_id in self.graph.nodes():
            node = self.nodes.get(node_id)
            if node and node.type == "process":
                for successor in self.graph.successors(node_id):
                    successor_node = self.nodes.get(successor)
                    if successor_node and successor_node.type == "file":
                        edges = self.graph.get_edge_data(node_id, successor)
                        for _, edge_data in edges.items():
                            if edge_data.get("action") in ["modified", "encrypted", "deleted"]:
                                file_modifications[node_id].append(successor)

        for process_id, files in file_modifications.items():
            if len(files) > 50:
                process = self.nodes[process_id]

                encrypted_extensions = sum(
                    1
                    for f in files
                    if self.nodes[f].name.endswith(
                        (".encrypted", ".locked", ".crypto")
                    )
                )

                confidence = min(0.95, 0.5 + (len(files) / 200))
                if encrypted_extensions > 10:
                    confidence = 0.98

                patterns.append(
                    ThreatPattern(
                        pattern_type="ransomware",
                        confidence=confidence,
                        nodes_involved=[process_id] + files[:10],
                        description=(
                            f"Process {process.name} modified {len(files)} files rapidly"
                        ),
                        severity="critical",
                        indicators=[
                            f"Mass file modification: {len(files)} files",
                            f"Encrypted files: {encrypted_extensions}",
                            "Rapid execution pattern",
                            f"Process: {process.name}",
                        ],
                    )
                )

        return patterns

    def detect_data_exfiltration(self) -> List[ThreatPattern]:
        """Detectar exfiltracion de datos."""
        patterns: List[ThreatPattern] = []

        for node_id in self.graph.nodes():
            node = self.nodes.get(node_id)
            if node and node.type == "process":
                files_read: List[str] = []
                network_conns: List[str] = []

                for successor in self.graph.successors(node_id):
                    successor_node = self.nodes.get(successor)
                    if not successor_node:
                        continue

                    if successor_node.type == "file":
                        edges = self.graph.get_edge_data(node_id, successor)
                        for _, edge_data in edges.items():
                            if edge_data.get("action") == "read":
                                files_read.append(successor)

                    elif successor_node.type == "network":
                        network_conns.append(successor)

                if files_read and network_conns:
                    sensitive_files = [
                        f
                        for f in files_read
                        if any(
                            keyword in self.nodes[f].name.lower()
                            for keyword in [
                                "password",
                                "credential",
                                "secret",
                                "key",
                                "token",
                                "config",
                            ]
                        )
                    ]

                    if sensitive_files or len(files_read) > 20:
                        confidence = 0.7
                        if sensitive_files:
                            confidence = 0.9

                        patterns.append(
                            ThreatPattern(
                                pattern_type="data_exfiltration",
                                confidence=confidence,
                                nodes_involved=[node_id]
                                + files_read[:5]
                                + network_conns[:3],
                                description=(
                                    f"Process {node.name} read {len(files_read)} files and "
                                    "established network connections"
                                ),
                                severity="high" if sensitive_files else "medium",
                                indicators=[
                                    f"Files accessed: {len(files_read)}",
                                    f"Sensitive files: {len(sensitive_files)}",
                                    f"Network connections: {len(network_conns)}",
                                    f"Process: {node.name}",
                                ],
                            )
                        )

        return patterns

    def detect_persistence_mechanisms(self) -> List[ThreatPattern]:
        """Detectar mecanismos de persistencia."""
        patterns: List[ThreatPattern] = []
        persistence_locations = [
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "startup",
            "scheduled_task",
            "service",
        ]

        for node_id in self.graph.nodes():
            node = self.nodes.get(node_id)
            if node and node.type == "process":
                persistence_mods: List[str] = []

                for successor in self.graph.successors(node_id):
                    successor_node = self.nodes.get(successor)
                    if successor_node and successor_node.type == "registry":
                        if any(loc in successor_node.name for loc in persistence_locations):
                            persistence_mods.append(successor)

                if persistence_mods:
                    patterns.append(
                        ThreatPattern(
                            pattern_type="persistence",
                            confidence=0.85,
                            nodes_involved=[node_id] + persistence_mods,
                            description=(
                                f"Process {node.name} modified persistence locations"
                            ),
                            severity="high",
                            indicators=[
                                f"Persistence mechanisms: {len(persistence_mods)}",
                                "Registry Run keys modified",
                                f"Process: {node.name}",
                            ],
                        )
                    )

        return patterns

    def detect_lateral_movement(self) -> List[ThreatPattern]:
        """Detectar movimiento lateral."""
        patterns: List[ThreatPattern] = []

        for node_id in self.graph.nodes():
            node = self.nodes.get(node_id)
            if node and node.type == "process":
                internal_connections: List[str] = []

                for successor in self.graph.successors(node_id):
                    successor_node = self.nodes.get(successor)
                    if successor_node and successor_node.type == "network":
                        ip = successor_node.attributes.get("ip", "")
                        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith(
                            "172."
                        ):
                            internal_connections.append(successor)

                if len(internal_connections) >= 3:
                    patterns.append(
                        ThreatPattern(
                            pattern_type="lateral_movement",
                            confidence=0.75,
                            nodes_involved=[node_id] + internal_connections,
                            description=(
                                f"Process {node.name} connected to "
                                f"{len(internal_connections)} internal hosts"
                            ),
                            severity="high",
                            indicators=[
                                f"Internal connections: {len(internal_connections)}",
                                "Potential lateral movement",
                                f"Process: {node.name}",
                            ],
                        )
                    )

        return patterns

    # ========================================================================
    # ALGORITMOS DE ANALISIS
    # ========================================================================

    def calculate_node_centrality(self) -> Dict[str, float]:
        """Calcular centralidad de nodos usando PageRank."""
        try:
            pagerank = nx.pagerank(self.graph, alpha=0.85)
            return pagerank
        except Exception:
            return {}

    def detect_communities(self) -> List[Set[str]]:
        """Detectar comunidades (clusters) en el grafo."""
        undirected = self.graph.to_undirected()

        try:
            from networkx.algorithms import community

            communities = community.louvain_communities(undirected)
            return communities
        except Exception:
            return []

    def find_shortest_attack_path(self, source: str, target: str) -> List[str]:
        """Encontrar el camino mas corto entre dos nodos."""
        try:
            path = nx.shortest_path(self.graph, source, target)
            return path
        except Exception:
            return []

    def calculate_threat_score(self, node_id: str) -> float:
        """Calcular score de amenaza para un nodo especifico."""
        if node_id not in self.nodes:
            return 0.0

        node = self.nodes[node_id]
        score = 0.0

        score += (1.0 - node.reputation) * 0.3

        centrality = self.calculate_node_centrality()
        if node_id in centrality:
            score += centrality[node_id] * 0.2

        suspicious_connections = 0
        for successor in self.graph.successors(node_id):
            successor_node = self.nodes.get(successor)
            if successor_node and successor_node.reputation < 0.3:
                suspicious_connections += 1

        score += min(suspicious_connections / 10, 0.3)

        involved_patterns = [
            p for p in self.threat_patterns if node_id in p.nodes_involved
        ]
        if involved_patterns:
            max_confidence = max(p.confidence for p in involved_patterns)
            score += max_confidence * 0.2

        return min(score, 1.0)

    def analyze(self) -> Dict:
        """Ejecutar analisis completo del grafo."""
        print("\n[BG] Running behavior graph analysis...")

        print("  -> Detecting process injection...")
        injection_patterns = self.detect_process_injection()

        print("  -> Detecting ransomware behavior...")
        ransomware_patterns = self.detect_ransomware_behavior()

        print("  -> Detecting data exfiltration...")
        exfiltration_patterns = self.detect_data_exfiltration()

        print("  -> Detecting persistence mechanisms...")
        persistence_patterns = self.detect_persistence_mechanisms()

        print("  -> Detecting lateral movement...")
        lateral_patterns = self.detect_lateral_movement()

        self.threat_patterns = (
            injection_patterns
            + ransomware_patterns
            + exfiltration_patterns
            + persistence_patterns
            + lateral_patterns
        )

        centrality = self.calculate_node_centrality()
        top_central_nodes = sorted(
            centrality.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        communities = self.detect_communities()

        return {
            "threat_patterns": self.threat_patterns,
            "stats": self.stats,
            "top_central_nodes": [
                {
                    "id": node_id,
                    "name": self.nodes[node_id].name,
                    "centrality": score,
                }
                for node_id, score in top_central_nodes
                if node_id in self.nodes
            ],
            "communities": [
                {"size": len(comm), "nodes": list(comm)[:5]}
                for comm in communities
            ],
            "high_risk_nodes": [
                {
                    "id": node_id,
                    "name": node.name,
                    "threat_score": self.calculate_threat_score(node_id),
                }
                for node_id, node in self.nodes.items()
                if self.calculate_threat_score(node_id) > 0.7
            ],
        }

    def visualize_summary(self) -> None:
        """Mostrar resumen visual del analisis."""
        print("\n" + "=" * 70)
        print("BEHAVIOR GRAPH ANALYSIS SUMMARY")
        print("=" * 70)
        print("\nGraph Statistics:")
        print(f"   Nodes: {self.stats['total_nodes']}")
        print(f"   Edges: {self.stats['total_edges']}")
        print(f"   Processes: {self.stats['processes']}")
        print(f"   Files: {self.stats['files']}")
        print(f"   Network Connections: {self.stats['network_connections']}")

        print(f"\nThreats Detected: {len(self.threat_patterns)}")

        severity_counts: Dict[str, int] = defaultdict(int)
        for pattern in self.threat_patterns:
            severity_counts[pattern.severity] += 1

        if severity_counts:
            print(f"   Critical: {severity_counts['critical']}")
            print(f"   High: {severity_counts['high']}")
            print(f"   Medium: {severity_counts['medium']}")
            print(f"   Low: {severity_counts['low']}")

        print("\n" + "=" * 70)


# ============================================================================
# DEMO Y SIMULACION
# ============================================================================


def simulate_ransomware_attack() -> BehaviorGraphEngine:
    """Simular un ataque de ransomware para testing."""
    engine = BehaviorGraphEngine()

    malware = GraphNode(
        id="proc_1234",
        type="process",
        name="cryptolocker.exe",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        attributes={"pid": 1234, "path": "C:\\Temp\\cryptolocker.exe"},
        reputation=0.1,
    )
    engine.add_node(malware)

    for i in range(100):
        file_node = GraphNode(
            id=f"file_{i}",
            type="file",
            name=f"document_{i}.docx.encrypted",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            attributes={"path": f"C:\\Users\\Documents\\document_{i}.docx.encrypted"},
            reputation=0.8,
        )
        engine.add_node(file_node)

        edge = GraphEdge(
            source="proc_1234",
            target=f"file_{i}",
            action="encrypted",
            timestamp=datetime.now(),
            metadata={"operation": "encrypt"},
            weight=1.0,
        )
        engine.add_edge(edge)

    c2_node = GraphNode(
        id="net_c2",
        type="network",
        name="c2.malware.com",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        attributes={"ip": "45.33.32.156", "port": 443},
        reputation=0.0,
    )
    engine.add_node(c2_node)

    c2_edge = GraphEdge(
        source="proc_1234",
        target="net_c2",
        action="connected",
        timestamp=datetime.now(),
        metadata={"protocol": "HTTPS"},
        weight=1.0,
    )
    engine.add_edge(c2_edge)

    return engine


if __name__ == "__main__":
    print("[BG] AEGIS FUSION - Behavior Graph Analyzer Demo")
    print("=" * 70)

    engine = simulate_ransomware_attack()

    results = engine.analyze()

    engine.visualize_summary()

    print("\nDetected Threat Patterns:")
    for i, pattern in enumerate(results["threat_patterns"], 1):
        print(f"\n   {i}. {pattern.pattern_type.upper()}")
        print(f"      Confidence: {pattern.confidence:.1%}")
        print(f"      Severity: {pattern.severity}")
        print(f"      Description: {pattern.description}")
        print("      Indicators:")
        for indicator in pattern.indicators:
            print(f"         - {indicator}")

    print("\n" + "=" * 70)
    print("Analysis complete. System protected by Aegis Fusion.")
    print("=" * 70)
