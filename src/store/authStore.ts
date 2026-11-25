/**
 * SHA256.US — Store de Autenticación sin Contraseña (Código OTP 6 Dígitos + Enlace Mágico por Correo)
 * Toda validación es ejecutada por el backend PHP PDO (/api/auth.php) en modo fail-closed.
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
  auth_method?: string;
  last_login_at?: string | null;
  last_login_ip?: string | null;
  profileImage?: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
  csrfToken: string | null;
  error: string | null;
  isLoading: boolean;
  otpSent: boolean;
  pendingEmail: string | null;

  hydrateSession: () => Promise<boolean>;
  requestOtp: (email: string) => Promise<boolean>;
  verifyOtp: (email: string, code: string) => Promise<boolean>;
  verifyMagicLink: (token: string) => Promise<boolean>;
  logout: () => void;
  updateProfileImage: (b64: string) => void;
  resetOtpStep: () => void;
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
    auth_method: dto.auth_method,
    last_login_at: dto.last_login_at,
    last_login_ip: dto.last_login_ip,
  };
}

let state: AuthState = {
  isAuthenticated: false,
  user: null,
  csrfToken: null,
  error: null,
  isLoading: false,
  otpSent: false,
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
        state.otpSent = false;
        state.pendingEmail = null;
        state.error = null;
        state.isLoading = false;
        notify();
        return true;
      }

      state.isAuthenticated = false;
      state.user = null;
      state.csrfToken = res.data?.csrf_token || null;
      state.error = null;
      state.isLoading = false;
      notify();
      return false;
    } catch (err: any) {
      state.isAuthenticated = false;
      state.user = null;
      state.error = err?.message || 'Error al verificar la sesión pericial';
      state.isLoading = false;
      notify();
      return false;
    }
  },

  requestOtp: async (email: string) => {
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      state.error = 'Ingrese un correo electrónico válido';
      notify();
      return false;
    }

    state.isLoading = true;
    state.error = null;
    notify();

    try {
      const res = await phpApi.requestOtp(cleanEmail);
      if (res.status === 200 && res.ok) {
        state.otpSent = true;
        state.pendingEmail = cleanEmail;
        state.error = null;
        state.isLoading = false;
        notify();
        return true;
      }

      state.otpSent = false;
      state.error = res.error || 'No se pudo enviar el código de acceso';
      state.isLoading = false;
      notify();
      return false;
    } catch (err: any) {
      state.otpSent = false;
      state.error = err?.message || 'Error de conexión al solicitar código';
      state.isLoading = false;
      notify();
      return false;
    }
  },

  verifyOtp: async (email: string, code: string) => {
    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanCode = (code || '').replace(/\s+/g, '');

    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      state.error = 'Correo electrónico inválido';
      notify();
      return false;
    }
    if (!/^\d{6}$/.test(cleanCode)) {
      state.error = 'Ingrese el código de 6 dígitos enviado a su correo';
      notify();
      return false;
    }

    state.isLoading = true;
    state.error = null;
    notify();

    try {
      const res = await phpApi.verifyOtp(cleanEmail, cleanCode);
      if (res.status === 200 && res.ok && res.data?.authenticated === true && res.data?.user) {
        state.isAuthenticated = true;
        state.user = toStoreUser(res.data.user);
        state.csrfToken = res.data.csrf_token || state.csrfToken;
        state.otpSent = false;
        state.pendingEmail = null;
        state.error = null;
        state.isLoading = false;
        notify();
        return true;
      }

      state.isAuthenticated = false;
      state.user = null;
      state.error = res.error || 'Código de 6 dígitos incorrecto o expirado';
      state.isLoading = false;
      notify();
      return false;
    } catch (err: any) {
      state.isAuthenticated = false;
      state.user = null;
      state.error = err?.message || 'Error de conexión al verificar el código';
      state.isLoading = false;
      notify();
      return false;
    }
  },

  verifyMagicLink: async (token: string) => {
    const cleanToken = (token || '').trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(cleanToken)) {
      state.error = 'El enlace mágico es inválido o está incompleto';
      notify();
      return false;
    }

    state.isLoading = true;
    state.error = null;
    notify();

    try {
      const res = await phpApi.verifyMagicLink(cleanToken);
      if (res.status === 200 && res.ok && res.data?.authenticated === true && res.data?.user) {
        state.isAuthenticated = true;
        state.user = toStoreUser(res.data.user);
        state.csrfToken = res.data.csrf_token || state.csrfToken;
        state.otpSent = false;
        state.pendingEmail = null;
        state.error = null;
        state.isLoading = false;
        notify();
        return true;
      }

      state.isAuthenticated = false;
      state.user = null;
      state.error = res.error || 'El enlace mágico expiró o ya fue utilizado';
      state.isLoading = false;
      notify();
      return false;
    } catch (err: any) {
      state.isAuthenticated = false;
      state.user = null;
      state.error = err?.message || 'Error de conexión al validar el enlace mágico';
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
    state.otpSent = false;
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

  resetOtpStep: () => {
    state.otpSent = false;
    state.pendingEmail = null;
    state.error = null;
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
