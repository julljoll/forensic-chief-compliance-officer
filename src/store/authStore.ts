/**
 * SHA256.US — Store de Autenticación de Peritos y Compliance Officers.
 * Cumplimiento: NIST SP 800-63B (AAL2) · RFC 6238 TOTP · OWASP ASVS
 * Toda autenticación es delegada determinísticamente al backend PHP PDO (/api/auth.php).
 */

import { phpApi } from '../lib/data/phpApi';

export interface User {
  id: string;
  email: string;
  nombre: string;
  apellido?: string;
  ci?: string;
  cargo?: string;
  rol: 'admin' | 'perito_lider' | 'perito_asistente' | 'fiscal' | 'compliance_officer';
  organismo?: string;
  despacho?: string;
  profileImage?: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
  csrfToken: string | null;
  error: string | null;
  isLoading: boolean;
  needsMfa: boolean;
  pendingEmail: string | null;

  login: (email: string, pass?: string, totpCode?: string) => Promise<boolean>;
  logout: () => void;
  updateProfileImage: (b64: string) => void;
  setNeedsMfa: (needed: boolean, email?: string) => void;
}

let state: AuthState = {
  isAuthenticated: false,
  user: null,
  csrfToken: null,
  error: null,
  isLoading: false,
  needsMfa: false,
  pendingEmail: null,

  login: async (email: string, pass: string = '', totpCode: string = '') => {
    const trimmedEmail = (email || '').trim().toLowerCase();
    const trimmedPass = (pass || '').trim();
    const trimmedTotp = (totpCode || '').trim();

    if (!trimmedEmail || !trimmedEmail.includes('@')) {
      state.error = 'Ingrese un correo electrónico válido';
      state.isAuthenticated = false;
      state.user = null;
      notify();
      return false;
    }

    if (!trimmedPass && !trimmedTotp) {
      state.error = 'Ingrese la contraseña o el código de Google Authenticator';
      state.isAuthenticated = false;
      state.user = null;
      notify();
      return false;
    }

    state.isLoading = true;
    state.error = null;
    notify();

    try {
      const res = await phpApi.login(trimmedEmail, trimmedPass, trimmedTotp);

      if (res.ok && res.data?.user) {
        state.isAuthenticated = true;
        state.user = res.data.user;
        state.csrfToken = res.data.csrf_token || null;
        state.error = null;
        state.needsMfa = false;
        state.pendingEmail = null;
        state.isLoading = false;
        notify();
        return true;
      }

      if (res.data?.needs_mfa || res.data?.requires_totp) {
        state.needsMfa = true;
        state.pendingEmail = trimmedEmail;
        state.error = null;
        state.isLoading = false;
        notify();
        return false;
      }

      state.error = res.error || 'Credenciales no autorizadas o código 2FA erróneo';
      state.isAuthenticated = false;
      state.user = null;
      state.isLoading = false;
      notify();
      return false;
    } catch (err: any) {
      state.error = err?.message || 'Error al conectar con el servidor de autenticación';
      state.isAuthenticated = false;
      state.user = null;
      state.isLoading = false;
      notify();
      return false;
    }
  },

  logout: () => {
    state.isAuthenticated = false;
    state.user = null;
    state.csrfToken = null;
    state.error = null;
    state.needsMfa = false;
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

  setNeedsMfa: (needed: boolean, email?: string) => {
    state.needsMfa = needed;
    state.pendingEmail = email || null;
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
