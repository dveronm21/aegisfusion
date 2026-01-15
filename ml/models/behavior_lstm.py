"""AEGIS FUSION - Machine Learning Models
Modelo LSTM para analisis de comportamiento
"""

from typing import Dict, List

import torch
import torch.nn as nn
import torch.nn.functional as F


class BehaviorLSTM(nn.Module):
    """LSTM bidireccional para analisis de secuencias de comportamiento.
    Entrada: secuencia de syscalls o API calls.
    Salida: clasificacion de familia de malware.
    """

    def __init__(
        self,
        vocab_size: int = 5000,
        embedding_dim: int = 128,
        hidden_dim: int = 256,
        num_classes: int = 10,
    ):
        super().__init__()

        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(
            embedding_dim,
            hidden_dim,
            num_layers=2,
            bidirectional=True,
            batch_first=True,
            dropout=0.3,
        )

        self.attention = nn.Linear(hidden_dim * 2, 1)
        self.fc1 = nn.Linear(hidden_dim * 2, 128)
        self.fc2 = nn.Linear(128, num_classes)
        self.dropout = nn.Dropout(0.5)

    def forward(self, x):
        # x shape: (batch, seq_len)
        embedded = self.embedding(x)

        # LSTM
        lstm_out, _ = self.lstm(embedded)

        # Attention mechanism
        attention_weights = F.softmax(self.attention(lstm_out), dim=1)
        context = torch.sum(attention_weights * lstm_out, dim=1)

        # Clasificacion
        out = F.relu(self.fc1(context))
        out = self.dropout(out)
        out = self.fc2(out)

        return out

    def analyze_behavior(self, syscall_sequence: List[str]) -> Dict[str, float]:
        """Analiza una secuencia de syscalls y retorna probabilidades por familia."""
        # Vocabulario simulado (en produccion vendria de training)
        vocab = {
            "CreateFile": 1,
            "WriteFile": 2,
            "ReadFile": 3,
            "DeleteFile": 4,
            "CreateProcess": 5,
            "TerminateProcess": 6,
            "connect": 7,
            "send": 8,
            "recv": 9,
            "RegOpenKey": 10,
            "RegSetValue": 11,
            "VirtualAlloc": 12,
            "VirtualProtect": 13,
            "LoadLibrary": 14,
            "GetProcAddress": 15,
        }

        # Convertir secuencia a indices
        indices = [vocab.get(call, 0) for call in syscall_sequence[:1000]]

        # Padding
        if len(indices) < 1000:
            indices += [0] * (1000 - len(indices))

        tensor = torch.LongTensor([indices])

        # Inferencia
        self.eval()
        with torch.no_grad():
            logits = self(tensor)
            probs = F.softmax(logits, dim=1)[0]

        # Mapear a familias
        families = [
            "Benign",
            "Ransomware",
            "Trojan",
            "Spyware",
            "Rootkit",
            "Worm",
            "Adware",
            "Backdoor",
            "Downloader",
            "Unknown",
        ]

        results = {family: prob.item() for family, prob in zip(families, probs)}
        return results
