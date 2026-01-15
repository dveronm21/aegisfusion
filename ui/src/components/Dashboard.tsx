import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Archive,
  CheckCircle,
  Clock,
  Cpu,
  FileText,
  HardDrive,
  Network,
  Settings as SettingsIcon,
  Shield,
  XCircle,
} from 'lucide-react';

import Quarantine from './Quarantine';
import SettingsPanel from './Settings';
import SystemHealthPanel from './SystemHealth';
import ThreatExplorer from './ThreatExplorer';
import {
  ScanSummary,
  Stats,
  SystemHealth,
  SystemStatus,
  Threat,
  getStatus,
  startScan,
  stopScan,
} from '../services/api';

type View = 'overview' | 'threats' | 'quarantine' | 'system' | 'settings';

const statusConfig: Record<
  SystemStatus,
  { label: string; badge: string; dot: string }
> = {
  protected: {
    label: 'PROTEGIDO',
    badge: 'bg-green-500/20 border-green-500 text-green-400',
    dot: 'bg-green-500',
  },
  warning: {
    label: 'EN RIESGO',
    badge: 'bg-orange-500/20 border-orange-500 text-orange-400',
    dot: 'bg-orange-500',
  },
  critical: {
    label: 'COMPROMETIDO',
    badge: 'bg-red-500/20 border-red-500 text-red-400',
    dot: 'bg-red-500',
  },
};

const navItems: Array<{
  key: View;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { key: 'overview', label: 'Resumen', icon: Shield },
  { key: 'threats', label: 'Amenazas', icon: AlertTriangle },
  { key: 'quarantine', label: 'Cuarentena', icon: Archive },
  { key: 'system', label: 'Sistema', icon: Activity },
  { key: 'settings', label: 'Configuracion', icon: SettingsIcon },
];

const scanModeLabel = (mode?: string) => {
  if (!mode) {
    return '';
  }
  const normalized = mode.toLowerCase();
  if (normalized === 'quick') {
    return 'rapido';
  }
  if (normalized === 'full') {
    return 'completo';
  }
  return mode;
};

const actionLabel = (action: string) => {
  const normalized = action.trim().toLowerCase();
  switch (normalized) {
    case 'allow':
      return 'Permitir';
    case 'allowed':
      return 'Permitido';
    case 'monitor':
      return 'Monitorear';
    case 'monitored':
      return 'Monitoreado';
    case 'suspended':
      return 'Suspendido';
    case 'quarantine':
      return 'Cuarentena';
    case 'quarantined':
      return 'En cuarentena';
    case 'terminate':
      return 'Terminar';
    case 'terminated':
      return 'Terminado';
    case 'block':
      return 'Bloquear';
    case 'blocked':
      return 'Bloqueado';
    case 'network blocked':
      return 'Red bloqueada';
    case 'remediated':
      return 'Remediado';
    case 'rolled back':
      return 'Revertido';
    case 'delete':
      return 'Eliminar';
    case 'restore':
      return 'Restaurar';
    default:
      return action;
  }
};

const scanErrorLabel = (status: string) => {
  const normalized = status.trim().toLowerCase();
  if (normalized === 'scan already running') {
    return 'Ya hay un escaneo en curso';
  }
  if (normalized === 'no scan roots configured') {
    return 'No hay rutas de escaneo configuradas';
  }
  return status;
};

const AegisFusionDashboard: React.FC = () => {
  const [view, setView] = useState<View>('overview');
  const [systemStatus, setSystemStatus] = useState<SystemStatus>('protected');
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Stats>({
    scanned: 0,
    blocked: 0,
    quarantined: 0,
    uptime: '0d 0h 0m',
  });
  const [health, setHealth] = useState<SystemHealth>({
    cpu_percent: 0,
    memory_mb: 0,
    memory_percent: 0,
    disk_used_percent: 0,
    network_kbps: 0,
  });
  const [scanStatus, setScanStatus] = useState<ScanSummary | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const scanActive =
    scanStatus?.status === 'Running' || scanStatus?.status === 'Queued';

  useEffect(() => {
    let cancelled = false;

    const fetchStatus = async () => {
      try {
        const payload = await getStatus();
        if (cancelled) {
          return;
        }

        setSystemStatus(payload.system_status || 'protected');
        setStats(payload.stats);
        setThreats(
          (payload.threats || []).map((threat) => ({
            ...threat,
            confidence: Number(threat.confidence),
          }))
        );
        setHealth(payload.health);
        setScanStatus(payload.scan ?? null);
        setStatusMessage(null);
      } catch (error) {
        if (cancelled) {
          return;
        }
        setStatusMessage('Backend sin conexion');
        setSystemStatus('warning');
      }
    };

    fetchStatus();
    const interval = window.setInterval(fetchStatus, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const status = statusConfig[systemStatus];

  const StatCard: React.FC<{
    icon: React.ComponentType<{ className?: string }>;
    label: string;
    value: number | string;
    color: string;
  }> = ({ icon: Icon, label, value, color }) => (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-lg ${color}`}>
          <Icon className="w-6 h-6" />
        </div>
        <span className="text-sm text-slate-400">{label}</span>
      </div>
      <div className="text-3xl font-bold text-white">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  );

  const ThreatItem: React.FC<{ threat: Threat }> = ({ threat }) => {
    const timeLabel = threat.timestamp
      ? new Date(threat.timestamp * 1000).toLocaleTimeString()
      : '--:--:--';
    const severityBorder =
      threat.severity === 'critical'
        ? 'border-red-500'
        : threat.severity === 'high'
          ? 'border-orange-500'
          : threat.severity === 'medium'
            ? 'border-yellow-500'
            : 'border-slate-600';
    const severityIcon =
      threat.severity === 'critical'
        ? 'text-red-400'
        : threat.severity === 'high'
          ? 'text-orange-400'
          : threat.severity === 'medium'
            ? 'text-yellow-400'
            : 'text-slate-400';

    return (
      <div
        className={`bg-slate-800 rounded-lg p-4 border-l-4 ${severityBorder}`}
      >
        <div className="flex items-start justify-between mb-2">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className={`w-4 h-4 ${severityIcon}`} />
              <span className="font-semibold text-white">{threat.name}</span>
            </div>
            <div className="text-sm text-slate-400">
              <span className="font-mono">{threat.file}</span>
            </div>
          </div>
          <div className="text-xs text-slate-500">{timeLabel}</div>
        </div>
        <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-700">
          <div className="flex items-center gap-4 text-sm">
            <span className="text-green-400">
              Accion: {actionLabel(threat.action)}
            </span>
            <span className="text-blue-400">
              Confianza: {(threat.confidence * 100).toFixed(0)}%
            </span>
          </div>
        </div>
      </div>
    );
  };

  const startScanAction = async (mode: 'quick' | 'full') => {
    setStatusMessage(
      `Iniciando escaneo ${mode === 'quick' ? 'rapido' : 'completo'}...`
    );

    try {
      const payload = await startScan(mode);
      if (payload.status !== 'started') {
        const label = mode === 'quick' ? 'rapido' : 'completo';
        const errorLabel = scanErrorLabel(payload.status);
        setStatusMessage(
          payload.status
            ? `No se pudo iniciar el escaneo ${label}: ${errorLabel}`
            : `No se pudo iniciar el escaneo ${label}`
        );
        return;
      }
      setStatusMessage(`Escaneo ${payload.id} iniciado`);
    } catch (error) {
      setStatusMessage(
        `No se pudo iniciar el escaneo ${mode === 'quick' ? 'rapido' : 'completo'}`
      );
    }
  };

  const stopScanAction = async () => {
    setStatusMessage('Deteniendo escaneo...');

    try {
      const payload = await stopScan();
      if (payload.status === 'stopping') {
        setStatusMessage('Solicitud de detencion enviada');
      } else {
        setStatusMessage('No hay un escaneo en curso');
      }
    } catch (error) {
      setStatusMessage('No se pudo detener el escaneo');
    }
  };

  const renderOverview = () => (
    <>
      <div className="grid grid-cols-4 gap-6 mb-8">
        <StatCard
          icon={FileText}
          label="Archivos escaneados"
          value={stats.scanned}
          color="bg-blue-500/20 text-blue-400"
        />
        <StatCard
          icon={XCircle}
          label="Amenazas bloqueadas"
          value={stats.blocked}
          color="bg-red-500/20 text-red-400"
        />
        <StatCard
          icon={AlertTriangle}
          label="En cuarentena"
          value={stats.quarantined}
          color="bg-orange-500/20 text-orange-400"
        />
        <StatCard
          icon={Clock}
          label="Tiempo activo"
          value={stats.uptime}
          color="bg-green-500/20 text-green-400"
        />
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 bg-slate-800 rounded-xl p-6 border border-slate-700">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold">Amenazas recientes detectadas</h2>
            <span className="text-sm text-slate-400">
              Monitoreo en tiempo real
            </span>
          </div>
          <div className="space-y-4">
            {threats.length === 0 ? (
              <div className="text-center py-12">
                <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                <p className="text-slate-400">
                  No se detectaron amenazas. El sistema esta seguro.
                </p>
              </div>
            ) : (
              threats.map((threat) => (
                <ThreatItem key={threat.id} threat={threat} />
              ))
            )}
          </div>
        </div>

        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-bold mb-6">Salud del sistema</h2>

          <div className="mb-6">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-blue-400" />
                <span className="text-sm">Impacto de CPU</span>
              </div>
              <span className="text-sm font-semibold text-blue-400">
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

          <div className="mb-6">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-green-400" />
                <span className="text-sm">Memoria</span>
              </div>
              <span className="text-sm font-semibold text-green-400">
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

          <div className="mb-6">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-purple-400" />
                <span className="text-sm">Uso de disco</span>
              </div>
              <span className="text-sm font-semibold text-purple-400">
                {health.disk_used_percent < 30
                  ? 'Bajo'
                  : health.disk_used_percent < 70
                    ? 'Medio'
                    : 'Alto'}
              </span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2">
              <div
                className="bg-purple-500 h-2 rounded-full"
                style={{ width: `${Math.min(100, health.disk_used_percent)}%` }}
              />
            </div>
          </div>

          <div className="mb-6">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <span className="text-sm">Monitoreo de red</span>
              </div>
              <span className="text-sm font-semibold text-cyan-400">
                {health.network_kbps > 1 ? 'Activo' : 'En espera'}
              </span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2">
              <div
                className="bg-cyan-500 h-2 rounded-full"
                style={{
                  width: `${Math.min(100, health.network_kbps / 10)}%`,
                }}
              />
            </div>
          </div>

          <div className="mt-8 pt-6 border-t border-slate-700">
            <h3 className="text-sm font-semibold mb-4 text-slate-300">
              Capas de proteccion
            </h3>
            <div className="space-y-3">
              {[
                { name: 'Monitor del kernel', status: 'active' },
                { name: 'Motor ML', status: 'active' },
                { name: 'Analisis de comportamiento', status: 'active' },
                { name: 'Escudo de red', status: 'active' },
                { name: 'Sincronizacion en la nube', status: 'active' },
              ].map((layer, idx) => (
                <div key={idx} className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">{layer.name}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full" />
                    <span className="text-xs text-green-400">Activo</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mt-6">
        <button
          className="bg-blue-600 hover:bg-blue-700 px-4 py-3 rounded-lg font-semibold transition-colors"
          onClick={() => startScanAction('quick')}
          disabled={scanActive}
        >
          Escaneo rapido
        </button>
        <button
          className="bg-slate-700 hover:bg-slate-600 px-4 py-3 rounded-lg font-semibold transition-colors"
          onClick={() => startScanAction('full')}
          disabled={scanActive}
        >
          Escaneo completo
        </button>
        <button
          className="bg-slate-700 hover:bg-slate-600 px-4 py-3 rounded-lg font-semibold transition-colors"
          onClick={() => setView('quarantine')}
        >
          Cuarentena
        </button>
        <button
          className="bg-slate-700 hover:bg-slate-600 px-4 py-3 rounded-lg font-semibold transition-colors"
          onClick={() => setView('settings')}
        >
          Configuracion
        </button>
      </div>
    </>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl">
              <Shield className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                AEGIS FUSION
              </h1>
              <p className="text-slate-400 text-sm">
                Proteccion avanzada contra amenazas
              </p>
            </div>
          </div>
          <div
            className={`flex items-center gap-3 px-6 py-3 rounded-lg border ${status.badge}`}
          >
            <div className={`w-3 h-3 rounded-full animate-pulse ${status.dot}`} />
            <span className="font-semibold">{status.label}</span>
          </div>
        </div>
        {statusMessage ? (
          <p className="mt-3 text-sm text-orange-300">{statusMessage}</p>
        ) : null}
        {scanStatus?.status === 'Running' ? (
          <p className="mt-2 text-xs text-slate-400">
            Escaneo en curso ({scanModeLabel(scanStatus.mode)}) -{' '}
            {scanStatus.scanned_files} archivos - {scanStatus.threats_found}{' '}
            amenazas
          </p>
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-8">
        {navItems.map((item) => {
          const isActive = item.key === view;
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              onClick={() => setView(item.key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-semibold transition-colors ${
                isActive
                  ? 'bg-slate-700 border-slate-500 text-white'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-white'
              }`}
            >
              <Icon className="w-4 h-4" />
              {item.label}
            </button>
          );
        })}
        {scanActive ? (
          <button
            className="ml-auto bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg font-semibold transition-colors"
            onClick={stopScanAction}
          >
            Detener escaneo
          </button>
        ) : null}
      </div>

      {view === 'overview' && renderOverview()}
      {view === 'threats' && <ThreatExplorer />}
      {view === 'quarantine' && <Quarantine />}
      {view === 'system' && <SystemHealthPanel />}
      {view === 'settings' && <SettingsPanel />}
    </div>
  );
};

export default AegisFusionDashboard;
