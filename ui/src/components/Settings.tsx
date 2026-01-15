import React, { useEffect, useState } from 'react';
import { Save, SlidersHorizontal } from 'lucide-react';

import { getSettings, Settings, updateSettings } from '../services/api';

const SettingsPanel: React.FC = () => {
  const [current, setCurrent] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [exclusionInput, setExclusionInput] = useState('');

  const loadSettings = async () => {
    try {
      const payload = await getSettings();
      const normalized: Settings = {
        ...payload,
        exclude_programs: Array.isArray(payload.exclude_programs)
          ? payload.exclude_programs
          : [],
        firewall_enabled: payload.firewall_enabled ?? true,
        ai_scan_enabled: payload.ai_scan_enabled ?? true,
        device_scan_enabled: payload.device_scan_enabled ?? true,
        device_scan_mode: payload.device_scan_mode || 'quick',
        device_scan_interval_ms: payload.device_scan_interval_ms ?? 3000,
        device_scan_removable_only: payload.device_scan_removable_only ?? false,
        yara_enabled: payload.yara_enabled ?? true,
        yara_rules_path: payload.yara_rules_path || '',
        yara_max_bytes: payload.yara_max_bytes ?? 20 * 1024 * 1024,
        ml_model_path: payload.ml_model_path || '',
        ml_score_threshold: payload.ml_score_threshold ?? 0.75,
        ml_max_bytes: payload.ml_max_bytes ?? 4 * 1024 * 1024,
        archive_scan_enabled: payload.archive_scan_enabled ?? true,
        archive_max_bytes: payload.archive_max_bytes ?? 200 * 1024 * 1024,
        archive_max_entries: payload.archive_max_entries ?? 2000,
        archive_entry_max_bytes:
          payload.archive_entry_max_bytes ?? 20 * 1024 * 1024,
        external_scan_enabled: payload.external_scan_enabled ?? true,
        external_scan_mode: payload.external_scan_mode || 'auto',
        external_scan_max_bytes: payload.external_scan_max_bytes ?? 50 * 1024 * 1024,
      };
      setCurrent(normalized);
      setDraft(normalized);
      setMessage(null);
    } catch (error) {
      setMessage('No se pudo cargar la configuracion');
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const updateDraft = (update: Partial<Settings>) => {
    setDraft((prev) => (prev ? { ...prev, ...update } : prev));
  };

  const handleAddExclusion = () => {
    if (!draft) {
      return;
    }
    const value = exclusionInput.trim();
    if (!value) {
      setMessage('Ingrese un nombre o ruta para excluir');
      return;
    }

    const exists = draft.exclude_programs.some(
      (entry) => entry.toLowerCase() === value.toLowerCase()
    );
    if (exists) {
      setMessage('La exclusion ya existe');
      return;
    }

    updateDraft({ exclude_programs: [...draft.exclude_programs, value] });
    setExclusionInput('');
    setMessage(null);
  };

  const handleRemoveExclusion = (entry: string) => {
    if (!draft) {
      return;
    }
    updateDraft({
      exclude_programs: draft.exclude_programs.filter(
        (item) => item.toLowerCase() !== entry.toLowerCase()
      ),
    });
  };

  const handleSave = async () => {
    if (!draft) {
      return;
    }

    setSaving(true);
    try {
      const payload = await updateSettings(draft);
      setCurrent(payload);
      setDraft(payload);
      setMessage('Configuracion actualizada');
    } catch (error) {
      setMessage('No se pudo actualizar la configuracion');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 rounded-lg bg-slate-700 text-cyan-300">
          <SlidersHorizontal className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-xl font-bold">Configuracion</h2>
          <p className="text-sm text-slate-400">
            Ajuste la configuracion del motor sin reiniciar.
          </p>
        </div>
      </div>

      {message ? <div className="mb-4 text-sm text-orange-300">{message}</div> : null}

      {draft ? (
        <div className="grid gap-6">
          <div>
            <label className="text-sm text-slate-300">Firewall</label>
            <div className="mt-2 flex items-center gap-3">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                  draft.firewall_enabled
                    ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-700'
                }`}
                onClick={() =>
                  updateDraft({ firewall_enabled: !draft.firewall_enabled })
                }
              >
                {draft.firewall_enabled ? 'Activado' : 'Desactivado'}
              </button>
              <span className="text-xs text-slate-500">
                Bloqueo de red para amenazas detectadas.
              </span>
            </div>
          </div>

          <div>
            <label className="text-sm text-slate-300">IA en escaneos</label>
            <div className="mt-2 flex items-center gap-3">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                  draft.ai_scan_enabled
                    ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-700'
                }`}
                onClick={() =>
                  updateDraft({ ai_scan_enabled: !draft.ai_scan_enabled })
                }
              >
                {draft.ai_scan_enabled ? 'Activado' : 'Desactivado'}
              </button>
              <span className="text-xs text-slate-500">
                Modelo ML local para complementar YARA.
              </span>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-3">
              <div>
                <label className="text-xs text-slate-500">Modelo IA (ruta)</label>
                <input
                  value={draft.ml_model_path}
                  onChange={(event) =>
                    updateDraft({ ml_model_path: event.target.value })
                  }
                  placeholder="C:\\ruta\\aegis_ml_weights.json"
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.ai_scan_enabled}
                />
              </div>
              <div>
                <label className="text-xs text-slate-500">
                  Umbral ML (0-1)
                </label>
                <input
                  type="number"
                  min={0.1}
                  max={0.99}
                  step={0.01}
                  value={draft.ml_score_threshold}
                  onChange={(event) =>
                    updateDraft({
                      ml_score_threshold: Number(event.target.value),
                    })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.ai_scan_enabled}
                />
              </div>
              <div>
                <label className="text-xs text-slate-500">Maximo bytes IA</label>
                <input
                  type="number"
                  min={65536}
                  value={draft.ml_max_bytes}
                  onChange={(event) =>
                    updateDraft({ ml_max_bytes: Number(event.target.value) })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.ai_scan_enabled}
                />
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm text-slate-300">Motor YARA</label>
            <div className="mt-2 flex items-center gap-3">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                  draft.yara_enabled
                    ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-700'
                }`}
                onClick={() => updateDraft({ yara_enabled: !draft.yara_enabled })}
              >
                {draft.yara_enabled ? 'Activado' : 'Desactivado'}
              </button>
              <span className="text-xs text-slate-500">
                Reglas locales para deteccion avanzada.
              </span>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div>
                <label className="text-xs text-slate-500">Ruta de reglas</label>
                <input
                  value={draft.yara_rules_path}
                  onChange={(event) =>
                    updateDraft({ yara_rules_path: event.target.value })
                  }
                  placeholder="C:\\ruta\\rules"
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.yara_enabled}
                />
              </div>
              <div>
                <label className="text-xs text-slate-500">Maximo bytes</label>
                <input
                  type="number"
                  min={65536}
                  value={draft.yara_max_bytes}
                  onChange={(event) =>
                    updateDraft({ yara_max_bytes: Number(event.target.value) })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.yara_enabled}
                />
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm text-slate-300">
              Escaneo de archivos comprimidos
            </label>
            <div className="mt-2 flex items-center gap-3">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                  draft.archive_scan_enabled
                    ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-700'
                }`}
                onClick={() =>
                  updateDraft({ archive_scan_enabled: !draft.archive_scan_enabled })
                }
              >
                {draft.archive_scan_enabled ? 'Activado' : 'Desactivado'}
              </button>
              <span className="text-xs text-slate-500">
                Analiza ZIP, DOCX, JAR, APK y similares.
              </span>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-3">
              <div>
                <label className="text-xs text-slate-500">Maximo bytes</label>
                <input
                  type="number"
                  min={1048576}
                  value={draft.archive_max_bytes}
                  onChange={(event) =>
                    updateDraft({
                      archive_max_bytes: Number(event.target.value),
                    })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.archive_scan_enabled}
                />
              </div>
              <div>
                <label className="text-xs text-slate-500">Maximo entradas</label>
                <input
                  type="number"
                  min={10}
                  value={draft.archive_max_entries}
                  onChange={(event) =>
                    updateDraft({
                      archive_max_entries: Number(event.target.value),
                    })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.archive_scan_enabled}
                />
              </div>
              <div>
                <label className="text-xs text-slate-500">Bytes por entrada</label>
                <input
                  type="number"
                  min={65536}
                  value={draft.archive_entry_max_bytes}
                  onChange={(event) =>
                    updateDraft({
                      archive_entry_max_bytes: Number(event.target.value),
                    })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.archive_scan_enabled}
                />
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm text-slate-300">
              Escaneo externo (Defender/ClamAV)
            </label>
            <div className="mt-2 flex items-center gap-3">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                  draft.external_scan_enabled
                    ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-700'
                }`}
                onClick={() =>
                  updateDraft({ external_scan_enabled: !draft.external_scan_enabled })
                }
              >
                {draft.external_scan_enabled ? 'Activado' : 'Desactivado'}
              </button>
              <span className="text-xs text-slate-500">
                Usa motores del sistema para confirmar amenazas.
              </span>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div>
                <label className="text-xs text-slate-500">Modo</label>
                <select
                  value={draft.external_scan_mode}
                  onChange={(event) =>
                    updateDraft({ external_scan_mode: event.target.value })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.external_scan_enabled}
                >
                  <option value="auto">Auto</option>
                  <option value="defender">Defender</option>
                  <option value="clamav">ClamAV</option>
                  <option value="off">Desactivado</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500">Maximo bytes</label>
                <input
                  type="number"
                  min={65536}
                  value={draft.external_scan_max_bytes}
                  onChange={(event) =>
                    updateDraft({
                      external_scan_max_bytes: Number(event.target.value),
                    })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.external_scan_enabled}
                />
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm text-slate-300">
              Analisis automatico de dispositivos
            </label>
            <div className="mt-2 flex items-center gap-3">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                  draft.device_scan_enabled
                    ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-700'
                }`}
                onClick={() =>
                  updateDraft({ device_scan_enabled: !draft.device_scan_enabled })
                }
              >
                {draft.device_scan_enabled ? 'Activado' : 'Desactivado'}
              </button>
              <span className="text-xs text-slate-500">
                Escanea automaticamente USB y dispositivos conectados.
              </span>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-3">
              <div>
                <label className="text-xs text-slate-500">Modo</label>
                <select
                  value={draft.device_scan_mode}
                  onChange={(event) =>
                    updateDraft({ device_scan_mode: event.target.value })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.device_scan_enabled}
                >
                  <option value="quick">Rapido</option>
                  <option value="full">Completo</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500">Intervalo (ms)</label>
                <input
                  type="number"
                  min={500}
                  value={draft.device_scan_interval_ms}
                  onChange={(event) =>
                    updateDraft({
                      device_scan_interval_ms: Number(event.target.value),
                    })
                  }
                  className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200"
                  disabled={!draft.device_scan_enabled}
                />
              </div>
              <div>
                <label className="text-xs text-slate-500">Solo removibles</label>
                <div className="mt-2">
                  <button
                    className={`px-3 py-2 rounded-lg text-sm font-semibold ${
                      draft.device_scan_removable_only
                        ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                        : 'bg-slate-900 text-slate-400 border border-slate-700'
                    }`}
                    onClick={() =>
                      updateDraft({
                        device_scan_removable_only: !draft.device_scan_removable_only,
                      })
                    }
                    disabled={!draft.device_scan_enabled}
                  >
                    {draft.device_scan_removable_only ? 'Si' : 'No'}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm text-slate-300">Excepciones de programas</label>
            <p className="mt-1 text-xs text-slate-500">
              Nombre del ejecutable o ruta completa.
            </p>
            <div className="mt-2 flex flex-wrap gap-3">
              <input
                value={exclusionInput}
                onChange={(event) => setExclusionInput(event.target.value)}
                placeholder="chrome.exe o C:\\ruta\\programa.exe"
                className="flex-1 min-w-[240px] bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm text-slate-200"
              />
              <button
                onClick={handleAddExclusion}
                className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm font-semibold"
              >
                Agregar
              </button>
            </div>
            {draft.exclude_programs.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {draft.exclude_programs.map((entry) => (
                  <div
                    key={entry}
                    className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-full px-3 py-1 text-xs"
                  >
                    <span className="text-slate-300">{entry}</span>
                    <button
                      onClick={() => handleRemoveExclusion(entry)}
                      className="text-red-300 hover:text-red-200"
                    >
                      Quitar
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-2 text-xs text-slate-500">
                Sin exclusiones configuradas.
              </div>
            )}
          </div>

          <div>
            <label className="text-sm text-slate-300">Registro del kernel</label>
            <div className="mt-2 flex items-center gap-3">
              <button
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                  draft.log_kernel_events
                    ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                    : 'bg-slate-900 text-slate-400 border border-slate-700'
                }`}
                onClick={() => updateDraft({ log_kernel_events: !draft.log_kernel_events })}
              >
                {draft.log_kernel_events ? 'Activado' : 'Desactivado'}
              </button>
              <span className="text-xs text-slate-500">
                Controla el registro de eventos del kernel en el servicio.
              </span>
            </div>
          </div>

          <div>
            <label className="text-sm text-slate-300">
              Filtro de registro del kernel
            </label>
            <select
              value={draft.log_kernel_filter}
              onChange={(event) => updateDraft({ log_kernel_filter: event.target.value })}
              className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm text-slate-200"
            >
              <option value="all">Todos</option>
              <option value="process">Proceso</option>
              <option value="file">Archivo</option>
              <option value="registry">Registro</option>
            </select>
          </div>

          <div>
            <label className="text-sm text-slate-300">
              Intervalo de tick del motor (ms)
            </label>
            <input
              type="number"
              min={1}
              value={draft.tick_ms}
              onChange={(event) =>
                updateDraft({ tick_ms: Number(event.target.value) })
              }
              className="mt-2 w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm text-slate-200"
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="text-xs text-slate-500">
              Intervalo activo: {current?.tick_ms ?? '--'} ms
            </div>
            <button
              onClick={handleSave}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm font-semibold"
              disabled={saving}
            >
              <Save className="w-4 h-4" />
              Guardar cambios
            </button>
          </div>
        </div>
      ) : (
        <div className="text-sm text-slate-400">Cargando configuracion...</div>
      )}
    </div>
  );
};

export default SettingsPanel;
