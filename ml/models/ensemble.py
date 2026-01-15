"""AEGIS FUSION - Machine Learning Models
Orquestador y ensemble de modelos
"""

from typing import Dict, List, Tuple

try:
    from .behavior_lstm import BehaviorLSTM
    from .network_transformer import NetworkTransformer
    from .static_cnn import StaticAnalysisCNN
except ImportError:
    from behavior_lstm import BehaviorLSTM
    from network_transformer import NetworkTransformer
    from static_cnn import StaticAnalysisCNN


class EnsembleClassifier:
    """Combina outputs de todos los modelos para decision final."""

    def __init__(self):
        self.weights = {
            "static": 0.25,
            "behavior": 0.35,
            "network": 0.25,
            "heuristic": 0.15,
        }

        self.thresholds = {
            "allow": 0.3,
            "monitor": 0.6,
            "quarantine": 0.8,
            "terminate": 0.9,
        }

    def predict(self, features: Dict[str, float]) -> Tuple[str, float, List[str]]:
        """Combina scores y genera decision final."""
        static_score = features.get("static_score", 0.0)

        behavior_scores = features.get("behavior_scores", {})
        behavior_score = max(
            [
                behavior_scores.get("Ransomware", 0),
                behavior_scores.get("Trojan", 0),
                behavior_scores.get("Spyware", 0),
                behavior_scores.get("Rootkit", 0),
            ]
        )

        network_scores = features.get("network_scores", {})
        network_score = max(
            [
                network_scores.get("C2_Communication", 0),
                network_scores.get("Data_Exfiltration", 0),
                network_scores.get("Botnet_Activity", 0),
            ]
        )

        heuristic_score = features.get("heuristic_score", 0.0)

        final_score = (
            static_score * self.weights["static"]
            + behavior_score * self.weights["behavior"]
            + network_score * self.weights["network"]
            + heuristic_score * self.weights["heuristic"]
        )

        context = features.get("context", {})
        if context.get("signed", False):
            final_score *= 0.7
        if context.get("prevalence", 0) > 100000:
            final_score *= 0.5

        action = "allow"
        if final_score >= self.thresholds["terminate"]:
            action = "terminate"
        elif final_score >= self.thresholds["quarantine"]:
            action = "quarantine"
        elif final_score >= self.thresholds["monitor"]:
            action = "monitor"

        reasons = []
        if static_score > 0.7:
            reasons.append(f"Static analysis: {static_score:.2f}")
        if behavior_score > 0.7:
            reasons.append(f"Suspicious behavior: {behavior_score:.2f}")
        if network_score > 0.7:
            reasons.append(f"Malicious network activity: {network_score:.2f}")
        if heuristic_score > 0.5:
            reasons.append(f"Heuristic detection: {heuristic_score:.2f}")

        confidence = final_score

        return action, confidence, reasons


class AegisMLEngine:
    """Motor principal de ML que orquesta todos los modelos."""

    def __init__(self):
        print("[ML] Initializing Aegis ML Engine...")

        self.static_model = StaticAnalysisCNN()
        self.behavior_model = BehaviorLSTM()
        self.network_model = NetworkTransformer()
        self.ensemble = EnsembleClassifier()

        print("  - Static Analysis CNN loaded")
        print("  - Behavior LSTM loaded")
        print("  - Network Transformer loaded")
        print("  - Ensemble Classifier ready")
        print("[ML] Engine: READY\n")

    def analyze_complete(
        self,
        file_bytes: bytes | None = None,
        syscalls: List[str] | None = None,
        network_conns: List[Dict] | None = None,
        heuristic_score: float = 0.0,
        context: Dict | None = None,
    ) -> Dict:
        """Analisis completo usando todos los modelos."""
        features: Dict = {}

        if file_bytes is not None:
            features["static_score"] = self.static_model.analyze_file(file_bytes)
            print(f"  Static analysis: {features['static_score']:.3f}")

        if syscalls is not None:
            features["behavior_scores"] = self.behavior_model.analyze_behavior(syscalls)
            print(f"  Behavior analysis: {features['behavior_scores']}")

        if network_conns is not None:
            features["network_scores"] = self.network_model.analyze_traffic(network_conns)
            print(f"  Network analysis: {features['network_scores']}")

        features["heuristic_score"] = heuristic_score
        features["context"] = context or {}

        action, confidence, reasons = self.ensemble.predict(features)

        return {
            "action": action,
            "confidence": confidence,
            "reasons": reasons,
            "details": features,
        }


def demo():
    line = "=" * 60
    print(line)
    print("AEGIS FUSION - ML Models Demo")
    print(line + "\n")

    engine = AegisMLEngine()

    print("\nAnalyzing suspicious executable...\n")

    fake_malware = b"MZ\x90\x00" + b"\x00" * 1000 + b"This program cannot be run"

    suspicious_calls = [
        "CreateFile",
        "WriteFile",
        "CreateProcess",
        "VirtualAlloc",
        "VirtualProtect",
        "connect",
        "send",
        "RegSetValue",
        "DeleteFile",
        "WriteFile",
        "CreateProcess",
    ] * 10

    suspicious_network = [
        {
            "dst_ip": "45.33.32.156",
            "dst_port": 4444,
            "protocol": "TCP",
            "bytes_sent": 1024,
            "bytes_recv": 50000,
            "duration": 300,
            "packet_count": 150,
            "encrypted": False,
            "frequency": 10,
            "entropy": 7.2,
        }
    ] * 5

    result = engine.analyze_complete(
        file_bytes=fake_malware,
        syscalls=suspicious_calls,
        network_conns=suspicious_network,
        heuristic_score=0.75,
        context={
            "signed": False,
            "prevalence": 10,
            "age_days": 0,
        },
    )

    print("\n" + line)
    print("ANALYSIS RESULTS")
    print(line)
    print(f"Action: {result['action'].upper()}")
    print(f"Confidence: {result['confidence']:.1%}")
    print("\nReasons:")
    for reason in result["reasons"]:
        print(f"  - {reason}")

    print("\n" + line)
    print("Aegis Fusion ML Engine - Demo Complete")
    print(line)


if __name__ == "__main__":
    demo()
