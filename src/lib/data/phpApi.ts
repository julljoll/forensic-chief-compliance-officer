/**
 * SHA256.US — Cliente de API REST PHP con Respaldo Offline (IndexedDB).
 * Se conecta a los endpoints en /api/*.php y almacena en caché local.
 */

import { idbGet, idbPut, idbGetAll } from './idb';
import type { CasoCMS } from '../domain/types';
import type { EntradaAuditoria } from '../crypto/hashChain';

const API_BASE = '/api';

export interface ApiResponse<T> {
  ok: boolean;
  data?: T;
  error?: string;
  offline?: boolean;
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      credentials: 'same-origin',
    });

    const json = await res.json().catch(() => null);
    if (!res.ok) {
      return { ok: false, error: json?.error || `HTTP ${res.status}`, data: json };
    }
    return { ok: true, data: json };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'Error de red', offline: true };
  }
}

export type ModalidadFirmaPlanilla = 'adobe_electronica' | 'manual_autografa' | 'hibrida';
export type EstadoFirmaPlanilla =
  | 'PENDIENTE_FIRMA'
  | 'FIRMADA_ADOBE'
  | 'FIRMADA_MANUAL'
  | 'FIRMADA_HIBRIDA'
  | 'REVOCADA';

export interface PeritoDirectorioDTO {
  id: string;
  nombre: string;
  ci: string;
  civ: string;
  inpre: string;
  cargo: string;
  organismo: string;
}

export interface PlanillaEmitidaDTO {
  id?: number;
  codigoPlanilla: string;
  planillaSlug: string;
  codigoDoc: string;
  tituloPlanilla: string;
  faseIso: string;
  casoId: string | null;
  numeroCaso: string | null;
  numeroPRCC: string | null;
  perito: {
    usuarioId: string;
    nombre: string;
    ci: string;
    civ: string;
    inpre: string;
    cargo: string;
    organismo: string;
  };
  coPerito: {
    nombre: string;
    civ: string;
  } | null;
  modalidadFirma: ModalidadFirmaPlanilla;
  estadoFirma: EstadoFirmaPlanilla;
  firmadaEn: string | null;
  hashEmisionSha256: string;
  hashPdfSha256: string | null;
  hashPdfFirmadoSha256: string | null;
  auditoriaSeq: number | null;
  auditoriaHash: string | null;
  emitidoEnUtc: string;
  offlineDraft?: boolean;
}

export interface EmitirPlanillaPayload {
  planillaSlug: string;
  codigoDoc: string;
  tituloPlanilla: string;
  faseIso: string;
  casoId?: string | null;
  numeroCaso?: string | null;
  numeroPRCC?: string | null;
  coPeritoNombre?: string | null;
  coPeritoCiv?: string | null;
  modalidadFirma: ModalidadFirmaPlanilla;
}

let cachedCsrfToken: string | null = null;

function readStoredCsrf(): string | null {
  if (cachedCsrfToken) return cachedCsrfToken;
  if (typeof window !== 'undefined') {
    const stored = sessionStorage.getItem('fcco_csrf_token');
    if (stored) {
      cachedCsrfToken = stored;
      return stored;
    }
  }
  return null;
}

function storeCsrf(token?: string | null): void {
  if (!token) return;
  cachedCsrfToken = token;
  if (typeof window !== 'undefined') {
    sessionStorage.setItem('fcco_csrf_token', token);
  }
}

async function ensureCsrfToken(): Promise<string | null> {
  const current = readStoredCsrf();
  if (current) return current;
  const authRes = await request<{ csrf_token?: string }>('/auth.php', { method: 'GET' });
  if (authRes.data?.csrf_token) {
    storeCsrf(authRes.data.csrf_token);
    return authRes.data.csrf_token;
  }
  return null;
}

export const phpApi = {
  // ── Casos ──
  async listarCasos(): Promise<CasoCMS[]> {
    const res = await request<{ casos: CasoCMS[] }>('/casos.php');
    if (res.ok && res.data?.casos) {
      // Actualizar caché IndexedDB
      for (const c of res.data.casos) {
        await idbPut('casos', c);
      }
      return res.data.casos;
    }
    // Fallback offline
    return idbGetAll<CasoCMS>('casos');
  },

  async obtenerCaso(id: string): Promise<CasoCMS | undefined> {
    const res = await request<{ caso: CasoCMS }>(`/casos.php?id=${encodeURIComponent(id)}`);
    if (res.ok && res.data?.caso) {
      await idbPut('casos', res.data.caso);
      return res.data.caso;
    }
    return idbGet<CasoCMS>('casos', id);
  },

  async guardarCaso(caso: CasoCMS): Promise<{ ok: boolean; version?: number; error?: string }> {
    const method = caso.version ? 'PUT' : 'POST';
    const res = await request<{ success: boolean; version?: number }>(`/casos.php`, {
      method,
      body: JSON.stringify(caso),
    });

    if (res.ok) {
      const nuevo = { ...caso, version: res.data?.version ?? (caso.version || 1) + 1 };
      await idbPut('casos', nuevo);
      return { ok: true, version: nuevo.version };
    }

    // Si falló por offline, guardar localmente con bandera de sincronización pendiente
    if (res.offline) {
      await idbPut('casos', caso);
      return { ok: true, version: caso.version, error: 'Guardado en modo offline' };
    }

    return { ok: false, error: res.error };
  },

  // ── Avance de Fase ISO ──
  async avanzarFase(casoId: string, fase: string, controles: Record<string, any>): Promise<ApiResponse<any>> {
    return request('/avanzar-etapa.php', {
      method: 'POST',
      body: JSON.stringify({ casoId, fase, controles }),
    });
  },

  async avanzarEtapa(opts: { casoId: string; fase?: string; faseOrigen?: string; etapa?: string; peritoActor?: string; controles?: Record<string, any> }): Promise<ApiResponse<any> & { hash?: string }> {
    const res = await request<any>('/avanzar-etapa.php', {
      method: 'POST',
      body: JSON.stringify({
        casoId: opts.casoId,
        fase: opts.fase || opts.faseOrigen || opts.etapa,
        peritoActor: opts.peritoActor,
        controles: opts.controles || {},
      }),
    });
    return { ...res, hash: (res.data as any)?.hash };
  },

  // ── Auditoría ──
  async listarAuditoria(casoId?: string): Promise<EntradaAuditoria[]> {
    const url = casoId ? `/auditoria.php?caso_id=${encodeURIComponent(casoId)}` : '/auditoria.php';
    const res = await request<{ logs: EntradaAuditoria[] }>(url);
    if (res.ok && res.data?.logs) {
      return res.data.logs;
    }
    return idbGetAll<EntradaAuditoria>('auditoria');
  },

  async obtenerAuditoria(casoId?: string): Promise<EntradaAuditoria[]> {
    return this.listarAuditoria(casoId);
  },

  async verificarCadenaAuditoria(): Promise<{ valida: boolean; total: number; motivo?: string; integra?: boolean; totalEntradas?: number; error?: string }> {
    const res = await request<any>('/auditoria.php?verificar=1');
    if (res.ok && res.data) {
      return {
        valida: res.data.valida ?? res.data.integra ?? false,
        total: res.data.total ?? res.data.totalEntradas ?? 0,
        motivo: res.data.motivo ?? res.data.error,
        integra: res.data.integra ?? res.data.valida ?? false,
        totalEntradas: res.data.totalEntradas ?? res.data.total ?? 0,
        error: res.data.error ?? res.data.motivo,
      };
    }
    return { valida: false, total: 0, motivo: res.error || 'No se pudo conectar con el servidor', integra: false, totalEntradas: 0, error: res.error };
  },

  async verificarAuditoria(): Promise<{ valida: boolean; total: number; motivo?: string; integra?: boolean; totalEntradas?: number; error?: string }> {
    return this.verificarCadenaAuditoria();
  },

  // ── Planillas Emitidas (QR Rojo + Code-128 + SHA-256 en cPanel) ──
  async emitirPlanilla(
    payload: EmitirPlanillaPayload
  ): Promise<ApiResponse<{ ok: boolean; qrUrl: string; planilla: PlanillaEmitidaDTO }>> {
    const csrf = await ensureCsrfToken();
    return request('/planillas-emitidas.php', {
      method: 'POST',
      headers: csrf ? { 'X-CSRF-Token': csrf } : {},
      body: JSON.stringify(payload),
    });
  },

  async fijarHashPdfPlanilla(
    codigoPlanilla: string,
    hashPdfSha256: string
  ): Promise<ApiResponse<{ ok: boolean; codigoPlanilla: string; hashPdfSha256: string; actualizado: boolean }>> {
    const csrf = await ensureCsrfToken();
    return request('/planillas-emitidas.php', {
      method: 'PUT',
      headers: csrf ? { 'X-CSRF-Token': csrf } : {},
      body: JSON.stringify({
        action: 'fijar_hash_pdf',
        codigoPlanilla,
        hashPdfSha256,
      }),
    });
  },

  async certificarFirmaPlanilla(
    codigoPlanilla: string,
    estadoFirma: EstadoFirmaPlanilla,
    hashPdfFirmadoSha256?: string | null
  ): Promise<ApiResponse<{ ok: boolean; codigoPlanilla: string; estadoFirma: EstadoFirmaPlanilla; auditoriaSeq?: number }>> {
    const csrf = await ensureCsrfToken();
    return request('/planillas-emitidas.php', {
      method: 'PUT',
      headers: csrf ? { 'X-CSRF-Token': csrf } : {},
      body: JSON.stringify({
        action: 'certificar_firma',
        codigoPlanilla,
        estadoFirma,
        hashPdfFirmadoSha256: hashPdfFirmadoSha256 || null,
      }),
    });
  },

  async verificarPlanillaPorCodigo(
    codigo: string
  ): Promise<ApiResponse<{ ok: boolean; verificada: boolean; planilla?: PlanillaEmitidaDTO; error?: string }>> {
    return request(`/planillas-emitidas.php?codigo=${encodeURIComponent(codigo.trim().toUpperCase())}`, {
      method: 'GET',
    });
  },

  async listarPlanillasEmitidas(casoId?: string): Promise<PlanillaEmitidaDTO[]> {
    const qs = casoId ? `?caso_id=${encodeURIComponent(casoId)}` : '?listar=1';
    const res = await request<{ ok: boolean; planillas: PlanillaEmitidaDTO[] }>(`/planillas-emitidas.php${qs}`);
    if (res.ok && Array.isArray(res.data?.planillas)) {
      return res.data.planillas;
    }
    return [];
  },

  async listarPeritosActivos(): Promise<PeritoDirectorioDTO[]> {
    const res = await request<{ ok: boolean; peritos: PeritoDirectorioDTO[] }>('/planillas-emitidas.php?peritos=1');
    if (res.ok && Array.isArray(res.data?.peritos)) {
      return res.data.peritos;
    }
    return [];
  },

  // ── Autenticación ──
  async login(email: string, pass: string = '', totpCode: string = ''): Promise<ApiResponse<any>> {
    const res = await request<any>('/auth.php', {
      method: 'POST',
      body: JSON.stringify({ action: 'login', email, password: pass, totp_code: totpCode }),
    });
    if (res.ok && res.data?.csrf_token) {
      storeCsrf(res.data.csrf_token);
    }
    return res;
  },

  async logout(): Promise<void> {
    cachedCsrfToken = null;
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem('fcco_csrf_token');
    }
    await request('/auth.php', {
      method: 'POST',
      body: JSON.stringify({ action: 'logout' }),
    });
  },

  async checkAuth(): Promise<ApiResponse<any>> {
    const res = await request<any>('/auth.php', { method: 'GET' });
    if (res.data?.csrf_token) {
      storeCsrf(res.data.csrf_token);
    }
    return res;
  },
};
