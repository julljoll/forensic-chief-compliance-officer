/**
 * SHA256.US — Store de Autenticación Forense (Opción C — Grado Forense)
 * Solo Google OIDC (Authorization Code + PKCE S256 + RS256 JWKS) + Google Authenticator (RFC 6238).
 * Inicio de sesión con contraseña local deshabilitado permanentemente.
 */

import { phpApi, type UsuarioPerfilDTO } from '../lib/data/phpApi';

export interface User {
  id: string;
  email: string;
  nombre: string;
  apellido?: string;
  ci?: string;
  cargo?: string;
  rol: 'admin' | 'perito_lider' | 'perito_asistente' | 'fiscal' | 'compliance_officer' | 'coordinador';
  organismo?: string;
  despacho?: string;
  google_linked?: boolean;
  google_sub_masked?: string | null;
  totp_enabled?: number;
  totp_enrolled_at?: string | null;
  last_login_at?: string | null;
  last_login_ip?: string | null;
  recovery_codes_remaining?: number;
  profileImage?: string;
}

export type MfaStep = 'verify' | 'enroll' | null;

export interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
  csrfToken: string | null;
  error: string | null;
  isLoading: boolean;
  pendingMfa: boolean;
  mfaStep: MfaStep;
  pendingEmail: string | null;

  hydrateSession: () => Promise<boolean>;
  verifyMfa: (code: string, useRecovery?: boolean) => Promise<boolean>;
  enrollMfaConfirm: (code: string) => Promise<{ ok: boolean; recoveryCodes?: string[] }>;
  cancelPendingMfa: () => Promise<void>;
  logout: () => void;
  updateProfileImage: (b64: string) => void;
  setPendingMfa: (pending: boolean, step?: MfaStep, email?: string | null) => void;
}

function toStoreUser(dto: UsuarioPerfilDTO): User {
  return {
    id: dto.id,
    email: dto.email,
    nombre: dto.nombre,
    apellido: dto.apellido,
    ci: dto.ci,
    cargo: dto.cargo,
    rol: (dto.rol as User['rol']) || 'perito_lider',
    organismo: dto.organismo,
    despacho: dto.despacho,
    google_linked: dto.google_linked,
    google_sub_masked: dto.google_sub_masked,
    totp_enabled: dto.totp_enabled,
    totp_enrolled_at: dto.totp_enrolled_at,
    last_login_at: dto.last_login_at,
    last_login_ip: dto.last_login_ip,
    recovery_codes_remaining: dto.recovery_codes_remaining,
  };
}

let state: AuthState = {
  isAuthenticated: false,
  user: null,
  csrfToken: null,
  error: null,
  isLoading: false,
  pendingMfa: false,
  mfaStep: null,
  pendingEmail: null,

  hydrateSession: async () => {
    state.isLoading = true;
    state.error = null;
    notify();

    try {
      const res = await phpApi.checkAuth();

      if (res.status === 200 && res.ok && res.data?.authenticated === true && res.data?.user) {
        state.isAuthenticated = true;
        state.user = toStoreUser(res.data.user);
        state.csrfToken = res.data.csrf_token || null;
        state.pendingMfa = false;
        state.mfaStep = null;
        state.pendingEmail = null;
        state.error = null;
        state.isLoading = false;
        notify();
        return true;
      }

      if (res.data?.pending_mfa === true) {
        state.isAuthenticated = false;
        state.user = null;
        state.csrfToken = res.data.csrf_token || null;
        state.pendingMfa = true;
        state.mfaStep = res.data.mfa_step || 'verify';
        state.pendingEmail = res.data.pending_email || null;
        state.error = null;
        state.isLoading = false;
        notify();
        return false;
      }

      state.isAuthenticated = false;
      state.user = null;
      state.csrfToken = res.data?.csrf_token || null;
      state.pendingMfa = false;
      state.mfaStep = null;
      state.pendingEmail = null;
      state.error = null;
      state.isLoading = false;
      notify();
      return false;
    } catch (err: any) {
      state.isAuthenticated = false;
      state.user = null;
      state.pendingMfa = false;
      state.mfaStep = null;
      state.pendingEmail = null;
      state.error = err?.message || 'Error al verificar la sesión pericial';
      state.isLoading = false;
      notify();
      return false;
    }
  },

  verifyMfa: async (code: string, useRecovery: boolean = false) => {
    const clean = (code || '').trim();
    if (!useRecovery && !/^\d{6}$/.test(clean)) {
      state.error = 'Ingrese un código válido de 6 dígitos de Google Authenticator';
      notify();
      return false;
    }
    if (useRecovery && clean.replace(/[^a-zA-Z0-9]/g, '').length !== 8) {
      state.error = 'Ingrese un código de recuperación válido de 8 caracteres';
      notify();
      return false;
    }

    state.isLoading = true;
    state.error = null;
    notify();

    try {
      const res = await phpApi.verifyMfa(clean, useRecovery);
      if (res.status === 200 && res.ok && res.data?.authenticated === true && res.data?.user) {
        state.isAuthenticated = true;
        state.user = toStoreUser(res.data.user);
        state.csrfToken = res.data.csrf_token || state.csrfToken;
        state.pendingMfa = false;
        state.mfaStep = null;
        state.pendingEmail = null;
        state.error = null;
        state.isLoading = false;
        notify();
        return true;
      }

      if (res.data?.pending_mfa_expired) {
        state.pendingMfa = false;
        state.mfaStep = null;
        state.pendingEmail = null;
      }
      state.isAuthenticated = false;
      state.user = null;
      state.error = res.error || 'Código de verificación inválido o expirado';
      state.isLoading = false;
      notify();
      return false;
    } catch (err: any) {
      state.isAuthenticated = false;
      state.user = null;
      state.error = err?.message || 'Error de conexión al validar Google Authenticator';
      state.isLoading = false;
      notify();
      return false;
    }
  },

  enrollMfaConfirm: async (code: string) => {
    const clean = (code || '').trim();
    if (!/^\d{6}$/.test(clean)) {
      state.error = 'Ingrese el código de 6 dígitos generado por Google Authenticator';
      notify();
      return { ok: false };
    }

    state.isLoading = true;
    state.error = null;
    notify();

    try {
      const res = await phpApi.enrollMfaConfirm(clean);
      if (res.status === 200 && res.ok && res.data?.user) {
        state.isAuthenticated = true;
        state.user = toStoreUser(res.data.user);
        state.csrfToken = res.data.csrf_token || state.csrfToken;
        state.pendingMfa = false;
        state.mfaStep = null;
        state.pendingEmail = null;
        state.error = null;
        state.isLoading = false;
        notify();
        return { ok: true, recoveryCodes: res.data.recovery_codes || [] };
      }

      state.error = res.error || 'No se pudo confirmar el enrolamiento TOTP';
      state.isLoading = false;
      notify();
      return { ok: false };
    } catch (err: any) {
      state.error = err?.message || 'Error de conexión durante enrolamiento TOTP';
      state.isLoading = false;
      notify();
      return { ok: false };
    }
  },

  cancelPendingMfa: async () => {
    state.pendingMfa = false;
    state.mfaStep = null;
    state.pendingEmail = null;
    state.error = null;
    try {
      await phpApi.cancelPendingMfa();
    } catch {
      // continuar limpiando estado local
    }
    notify();
  },

  logout: () => {
    state.isAuthenticated = false;
    state.user = null;
    state.csrfToken = null;
    state.error = null;
    state.pendingMfa = false;
    state.mfaStep = null;
    state.pendingEmail = null;
    phpApi.logout().catch(() => {});
    notify();
  },

  updateProfileImage: (b64: string) => {
    if (state.user) {
      state.user = { ...state.user, profileImage: b64 };
      notify();
    }
  },

  setPendingMfa: (pending: boolean, step: MfaStep = null, email: string | null = null) => {
    state.pendingMfa = pending;
    state.mfaStep = pending ? (step || 'verify') : null;
    state.pendingEmail = pending ? email : null;
    notify();
  },
};

const listeners = new Set<() => void>();
function notify() {
  listeners.forEach((l) => l());
}

export const useAuthStore = {
  getState: () => state,
  setState: (partial: Partial<AuthState>) => {
    state = { ...state, ...partial };
    notify();
  },
  subscribe: (listener: () => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};
