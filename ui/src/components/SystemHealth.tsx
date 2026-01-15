import React, { useEffect, useState } from 'react';
import { Activity, Cpu, HardDrive, Network, Shield } from 'lucide-react';

import { getStatus, SystemHealth as Health } from '../services/api';

const SystemHealth: React.FC = () => {
  const [health, setHealth] = useState<Health>({
    cpu_percent: 0,
    memory_mb: 0,
    memory_percent: 0,
    disk_used_percent: 0,
    network_kbps: 0,
  });
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const loadHealth = async () => {
      try {
        const payload = await getStatus();
        if (!cancelled) {
          setHealth(payload.health);
          setMessage(null);
        }
      } catch (error) {
        if (!cancelled) {
          setMessage('No se pudo cargar la salud del sistema');
        }
      }
    };

    loadHealth();
    const interval = window.setInterval(loadHealth, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  return (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 rounded-lg bg-slate-700 text-cyan-300">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-xl font-bold">Salud del sistema</h2>
          <p className="text-sm text-slate-400">
            Impacto de recursos en tiempo real del agente.
          </p>
        </div>
      </div>

      {message ? <div className="text-sm text-orange-300 mb-4">{message}</div> : null}

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-slate-900/70 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Cpu className="w-4 h-4 text-blue-400" />
              Uso de CPU
            </div>
            <span className="text-sm font-semibold text-blue-300">
              {health.cpu_percent.toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full"
              style={{ width: `${Math.min(100, health.cpu_percent)}%` }}
            />
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Activity className="w-4 h-4 text-green-400" />
              Uso de memoria
            </div>
            <span className="text-sm font-semibold text-green-300">
              {health.memory_mb.toLocaleString()} MB
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-green-500 h-2 rounded-full"
              style={{ width: `${Math.min(100, health.memory_percent)}%` }}
            />
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <HardDrive className="w-4 h-4 text-purple-400" />
              Uso de disco
            </div>
            <span className="text-sm font-semibold text-purple-300">
              {health.disk_used_percent.toFixed(1)}%
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-purple-500 h-2 rounded-full"
              style={{ width: `${Math.min(100, health.disk_used_percent)}%` }}
            />
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Network className="w-4 h-4 text-cyan-400" />
              Rendimiento de red
            </div>
            <span className="text-sm font-semibold text-cyan-300">
              {health.network_kbps.toFixed(1)} KB/s
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-cyan-500 h-2 rounded-full"
              style={{ width: `${Math.min(100, health.network_kbps / 10)}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default SystemHealth;
