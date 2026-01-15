"""AEGIS FUSION - Machine Learning Models
Modelos de deteccion basados en IA
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


class StaticAnalysisCNN(nn.Module):
    """CNN para analisis estatico de ejecutables.
    Entrada: primeros 2MB del archivo como bytes.
    Salida: probabilidad de malware [0-1].
    """

    def __init__(self):
        super().__init__()

        # Convoluciones 1D sobre bytes
        self.conv1 = nn.Conv1d(1, 128, kernel_size=500, stride=500)
        self.conv2 = nn.Conv1d(128, 128, kernel_size=500, stride=500)
        self.conv3 = nn.Conv1d(128, 256, kernel_size=500, stride=500)

        self.pool = nn.MaxPool1d(2)
        self.dropout = nn.Dropout(0.5)

        # Capas fully connected
        self.fc1 = nn.Linear(256, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 1)

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # x shape: (batch, 1, bytes)
        x = F.relu(self.conv1(x))
        x = self.pool(x)

        x = F.relu(self.conv2(x))
        x = self.pool(x)

        x = F.relu(self.conv3(x))
        x = F.adaptive_max_pool1d(x, 1)  # Global max pooling

        x = x.view(x.size(0), -1)  # Flatten

        x = F.relu(self.fc1(x))
        x = self.dropout(x)

        x = F.relu(self.fc2(x))
        x = self.dropout(x)

        x = self.fc3(x)
        x = self.sigmoid(x)

        return x

    def analyze_file(self, file_bytes: bytes) -> float:
        """Analiza un archivo y retorna score de malware."""
        # Preparar entrada (primeros 2MB)
        max_len = 2 * 1024 * 1024
        if len(file_bytes) > max_len:
            file_bytes = file_bytes[:max_len]

        # Padding si es necesario
        if len(file_bytes) < max_len:
            file_bytes = file_bytes + b"\x00" * (max_len - len(file_bytes))

        # Convertir a tensor
        byte_array = np.frombuffer(file_bytes, dtype=np.uint8)
        byte_array = byte_array.astype(np.float32) / 255.0

        tensor = torch.FloatTensor(byte_array).unsqueeze(0).unsqueeze(0)

        # Inferencia
        self.eval()
        with torch.no_grad():
            score = self(tensor).item()

        return score
