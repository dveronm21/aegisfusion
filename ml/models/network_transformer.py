"""AEGIS FUSION - Machine Learning Models
Modelo Transformer para analisis de red
"""

from typing import Dict, List

import torch
import torch.nn as nn
import torch.nn.functional as F


class NetworkTransformer(nn.Module):
    """Transformer para analisis de patrones de trafico de red.
    Detecta: C2, exfiltracion, botnet activity.
    """

    def __init__(self, d_model: int = 128, nhead: int = 8, num_layers: int = 4, num_classes: int = 4):
        super().__init__()

        # Embedding para features de red
        self.feature_embedding = nn.Linear(10, d_model)

        # Positional encoding
        self.pos_encoder = nn.Parameter(torch.randn(1, 100, d_model))

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=512,
            dropout=0.1,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Clasificador
        self.classifier = nn.Sequential(
            nn.Linear(d_model, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes),
        )

    def forward(self, x):
        # x shape: (batch, seq_len, features)
        x = self.feature_embedding(x)
        x = x + self.pos_encoder[:, : x.size(1), :]

        # Transformer espera (seq_len, batch, features)
        x = x.permute(1, 0, 2)
        x = self.transformer(x)

        # Global average pooling
        x = x.mean(dim=0)

        # Clasificacion
        out = self.classifier(x)
        return out

    def analyze_traffic(self, connections: List[Dict]) -> Dict[str, float]:
        """Analiza patrones de trafico de red."""
        # Extraer features
        features = []
        for conn in connections[:100]:
            feat = [
                (hash(conn.get("dst_ip", "")) % 1000) / 1000,
                conn.get("dst_port", 0) / 65535,
                1.0 if conn.get("protocol") == "TCP" else 0.0,
                min(conn.get("bytes_sent", 0) / 1e6, 1.0),
                min(conn.get("bytes_recv", 0) / 1e6, 1.0),
                min(conn.get("duration", 0) / 3600, 1.0),
                conn.get("packet_count", 0) / 1000,
                1.0 if conn.get("encrypted", False) else 0.0,
                conn.get("frequency", 0) / 100,
                conn.get("entropy", 0) / 8,
            ]
            features.append(feat)

        # Padding si es necesario
        while len(features) < 100:
            features.append([0.0] * 10)

        tensor = torch.FloatTensor([features])

        # Inferencia
        self.eval()
        with torch.no_grad():
            logits = self(tensor)
            probs = F.softmax(logits, dim=1)[0]

        # Tipos de actividad
        activities = [
            "Normal",
            "C2_Communication",
            "Data_Exfiltration",
            "Botnet_Activity",
        ]
        results = {activity: prob.item() for activity, prob in zip(activities, probs)}

        return results
