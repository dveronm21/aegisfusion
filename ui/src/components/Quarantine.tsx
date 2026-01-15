import React, { useEffect, useState } from 'react';
import { Archive, RefreshCw, RotateCcw, Trash2 } from 'lucide-react';

import {
  addQuarantine,
  deleteQuarantine,
  getQuarantine,
  QuarantineItem,
  restoreQuarantine,
} from '../services/api';

const formatBytes = (value: number) => {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  if (value < 1024 * 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  }
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

const formatTime = (timestamp: number) => {
  if (!timestamp) {
    return '--';
  }
  return new Date(timestamp * 1000).toLocaleString();
};

const Quarantine: React.FC = () => {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [manualPath, setManualPath] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadItems = async () => {
    setLoading(true);
    try {
      const payload = await getQuarantine();
      setItems(payload);
      setMessage(null);
    } catch (error) {
      setMessage('No se pudo cargar la lista de cuarentena');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadItems();
  }, []);

  const handleAdd = async () => {
    if (!manualPath.trim()) {
      setMessage('Indique la ruta del archivo para poner en cuarentena');
      return;
    }

    setLoading(true);
    try {
      const response = await addQuarantine(manualPath.trim());
      if (response.status !== 'quarantined') {
        setMessage(response.message || 'No se pudo poner en cuarentena el archivo');
        return;
      }
      setManualPath('');
      await loadItems();
    } catch (error) {
      setMessage('No se pudo poner en cuarentena el archivo');
    } finally {
      setLoading(false);
    }
  };

  const handleRestore = async (id: string) => {
    setBusyId(id);
    try {
      const response = await restoreQuarantine(id);
      if (response.status !== 'restored') {
        setMessage(response.message || 'Error al restaurar');
      }
      await loadItems();
    } catch (error) {
      setMessage('Error al restaurar');
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (id: string) => {
    setBusyId(id);
    try {
      const response = await deleteQuarantine(id);
      if (response.status !== 'deleted') {
        setMessage(response.message || 'Error al eliminar');
      }
      await loadItems();
    } catch (error) {
      setMessage('Error al eliminar');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-700 text-cyan-300">
            <Archive className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xl font-bold">Cuarentena</h2>
            <p className="text-sm text-slate-400">
              Inspeccione, restaure o elimine archivos aislados.
            </p>
          </div>
        </div>
        <button
          onClick={loadItems}
          className="flex items-center gap-2 text-sm text-slate-300 hover:text-white"
          disabled={loading}
        >
          <RefreshCw className="w-4 h-4" />
          Actualizar
        </button>
      </div>

      <div className="mb-6">
        <label className="text-sm text-slate-300">Cuarentena manual</label>
        <div className="mt-2 flex flex-wrap gap-3">
          <input
            value={manualPath}
            onChange={(event) => setManualPath(event.target.value)}
            placeholder="C:\\ruta\\al\\archivo.exe"
            className="flex-1 min-w-[240px] bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm text-slate-200"
          />
          <button
            onClick={handleAdd}
            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm font-semibold"
            disabled={loading}
          >
            Poner en cuarentena
          </button>
        </div>
      </div>

      {message ? (
        <div className="mb-4 text-sm text-orange-300">{message}</div>
      ) : null}

      {items.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          No hay archivos en cuarentena.
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item) => (
            <div
              key={item.id}
              className="bg-slate-900/60 border border-slate-700 rounded-lg p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="font-semibold text-white">{item.file_name}</p>
                  <p className="text-xs text-slate-400">{item.original_path}</p>
                </div>
                <div className="text-right text-xs text-slate-400">
                  <div>{formatTime(item.quarantined_at)}</div>
                  <div>{formatBytes(item.size_bytes)}</div>
                </div>
              </div>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-4">
                <div className="text-xs text-slate-500">
                  ID de amenaza: {item.threat_id}
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => handleRestore(item.id)}
                    className="flex items-center gap-2 text-sm text-green-300 hover:text-green-200"
                    disabled={busyId === item.id}
                  >
                    <RotateCcw className="w-4 h-4" />
                    Restaurar
                  </button>
                  <button
                    onClick={() => handleDelete(item.id)}
                    className="flex items-center gap-2 text-sm text-red-300 hover:text-red-200"
                    disabled={busyId === item.id}
                  >
                    <Trash2 className="w-4 h-4" />
                    Eliminar
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Quarantine;
