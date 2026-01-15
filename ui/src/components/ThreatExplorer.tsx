import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Filter, Search } from 'lucide-react';

import { allowThreat, getStatus, Threat, ThreatSeverity } from '../services/api';

const ThreatExplorer: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [filter, setFilter] = useState<'all' | ThreatSeverity>('all');
  const [query, setQuery] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [allowingId, setAllowingId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const loadThreats = async () => {
      try {
        const payload = await getStatus();
        if (!cancelled) {
          setThreats(payload.threats || []);
          setMessage(null);
        }
      } catch (error) {
        if (!cancelled) {
          setMessage('No se pudo cargar el registro de amenazas');
        }
      }
    };

    loadThreats();
    const interval = window.setInterval(loadThreats, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const filteredThreats = useMemo(() => {
    const lowered = query.trim().toLowerCase();
    return threats.filter((threat) => {
      if (filter !== 'all' && threat.severity !== filter) {
        return false;
      }
      if (!lowered) {
        return true;
      }
      return (
        threat.name.toLowerCase().includes(lowered) ||
        threat.file.toLowerCase().includes(lowered) ||
        threat.action.toLowerCase().includes(lowered)
      );
    });
  }, [threats, filter, query]);

  const severityBadge = (severity: ThreatSeverity) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'high':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      default:
        return 'bg-slate-700 text-slate-300 border-slate-600';
    }
  };

  const severityLabel = (severity: ThreatSeverity) => {
    switch (severity) {
      case 'critical':
        return 'CRITICA';
      case 'high':
        return 'ALTA';
      case 'medium':
        return 'MEDIA';
      case 'low':
      default:
        return 'BAJA';
    }
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

  const handleAllow = async (threat: Threat) => {
    const target = threat.file?.trim();
    if (!target) {
      setMessage('No se encontro la ruta para permitir');
      return;
    }

    setAllowingId(threat.id);
    try {
      const response = await allowThreat(target, threat.id);
      if (response.status !== 'allowed') {
        setMessage(response.message || 'No se pudo permitir la amenaza');
        return;
      }
      setThreats((prev) =>
        prev.map((item) =>
          item.id === threat.id ? { ...item, action: 'Allowed' } : item
        )
      );
      setMessage('Amenaza permitida y agregada a exclusiones');
    } catch (error) {
      setMessage('No se pudo permitir la amenaza');
    } finally {
      setAllowingId(null);
    }
  };

  return (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-700 text-cyan-300">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xl font-bold">Explorador de amenazas</h2>
            <p className="text-sm text-slate-400">
              Investigue detecciones en la linea de tiempo del endpoint.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Buscar amenazas"
              className="pl-9 pr-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200"
            />
          </div>
          <div className="relative">
            <Filter className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <select
              value={filter}
              onChange={(event) =>
                setFilter(event.target.value as 'all' | ThreatSeverity)
              }
              className="pl-9 pr-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200"
            >
              <option value="all">Todas las severidades</option>
              <option value="critical">Critica</option>
              <option value="high">Alta</option>
              <option value="medium">Media</option>
              <option value="low">Baja</option>
            </select>
          </div>
        </div>
      </div>

      {message ? <div className="text-sm text-orange-300 mb-4">{message}</div> : null}

      {filteredThreats.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          No hay amenazas que coincidan con los filtros actuales.
        </div>
      ) : (
        <div className="space-y-3">
          {filteredThreats.map((threat) => {
            const normalizedAction = threat.action.trim().toLowerCase();
            const isAllowed =
              normalizedAction === 'allowed' || normalizedAction === 'allow';
            return (
            <div
              key={threat.id}
              className="bg-slate-900/60 border border-slate-700 rounded-lg p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-semibold text-white">{threat.name}</p>
                  <p className="text-xs text-slate-400">{threat.file}</p>
                </div>
                <span
                  className={`text-xs border px-2 py-1 rounded-full ${severityBadge(
                    threat.severity
                  )}`}
                >
                  {severityLabel(threat.severity)}
                </span>
              </div>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
                <span>
                  Confianza: {(threat.confidence * 100).toFixed(0)}%
                </span>
                <span>Accion: {actionLabel(threat.action)}</span>
                <span>
                  {threat.timestamp
                    ? new Date(threat.timestamp * 1000).toLocaleString()
                    : '--'}
                </span>
                <button
                  onClick={() => handleAllow(threat)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold border ${
                    isAllowed
                      ? 'bg-green-500/20 text-green-300 border-green-500/40'
                      : 'bg-slate-800 text-slate-200 border-slate-600 hover:bg-slate-700'
                  }`}
                  disabled={allowingId === threat.id || isAllowed}
                >
                  {allowingId === threat.id
                    ? 'Permitiendo...'
                    : isAllowed
                      ? 'Permitido'
                      : 'Permitir'}
                </button>
              </div>
            </div>
          );
          })}
        </div>
      )}
    </div>
  );
};

export default ThreatExplorer;
