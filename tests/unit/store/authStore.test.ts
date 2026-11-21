import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from '@/store/authStore';
import { phpApi } from '@/lib/data/phpApi';

describe('useAuthStore', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.getState().logout();
  });

  it('debe iniciar sesión exitosamente cuando el backend valida credenciales', async () => {
    const mockUser = {
      id: 'usr-jull-01',
      email: 'julljoll@gmail.com',
      nombre: 'Jull Joll',
      cargo: 'Perito Analizador de Datos Forenses',
      rol: 'admin' as const,
    };

    vi.spyOn(phpApi, 'login').mockResolvedValueOnce({
      ok: true,
      data: { user: mockUser, csrf_token: 'fake-csrf-token' },
    });

    const success = await useAuthStore.getState().login('julljoll@gmail.com', 'test-pass');
    expect(success).toBe(true);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.user).not.toBeNull();
    expect(state.user?.email).toBe('julljoll@gmail.com');
    expect(state.user?.nombre).toBe('Jull Joll');
    expect(state.csrfToken).toBe('fake-csrf-token');
    expect(state.error).toBeNull();
  });

  it('debe manejar solicitud de segundo factor MFA (needs_mfa) correctamente', async () => {
    vi.spyOn(phpApi, 'login').mockResolvedValueOnce({
      ok: true,
      data: { needs_mfa: true, email: 'julljoll@gmail.com' },
    });

    const success = await useAuthStore.getState().login('julljoll@gmail.com', 'test-pass');
    expect(success).toBe(false);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.needsMfa).toBe(true);
    expect(state.pendingEmail).toBe('julljoll@gmail.com');
  });

  it('debe iniciar sesión con código Google Authenticator (TOTP)', async () => {
    const mockUser = {
      id: 'usr-jull-01',
      email: 'julljoll@gmail.com',
      nombre: 'Jull Joll',
      rol: 'admin' as const,
    };

    vi.spyOn(phpApi, 'login').mockResolvedValueOnce({
      ok: true,
      data: { user: mockUser },
    });

    const success = await useAuthStore.getState().login('julljoll@gmail.com', '', '123456');
    expect(success).toBe(true);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.user?.email).toBe('julljoll@gmail.com');
  });

  it('debe rechazar correo electrónico inválido antes de llamar a la red', async () => {
    const apiSpy = vi.spyOn(phpApi, 'login');
    const success = await useAuthStore.getState().login('correo-invalido', 'pass');
    expect(success).toBe(false);
    expect(apiSpy).not.toHaveBeenCalled();

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.user).toBeNull();
    expect(state.error).toBe('Ingrese un correo electrónico válido');
  });

  it('debe rechazar contraseña y código totp vacíos sin llamar a la red', async () => {
    const apiSpy = vi.spyOn(phpApi, 'login');
    const success = await useAuthStore.getState().login('julljoll@gmail.com', '   ', '');
    expect(success).toBe(false);
    expect(apiSpy).not.toHaveBeenCalled();

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.error).toBe('Ingrese la contraseña o el código de Google Authenticator');
  });

  it('debe cerrar sesión correctamente y limpiar el estado y tokens', async () => {
    vi.spyOn(phpApi, 'logout').mockResolvedValueOnce();
    useAuthStore.setState({
      isAuthenticated: true,
      user: { id: '1', email: 'j@g.com', nombre: 'J', rol: 'admin' },
      csrfToken: 'tok',
    });

    useAuthStore.getState().logout();
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.user).toBeNull();
    expect(state.csrfToken).toBeNull();
    expect(state.error).toBeNull();
  });

  it('debe actualizar la imagen de perfil del usuario activo', () => {
    useAuthStore.setState({
      isAuthenticated: true,
      user: { id: '1', email: 'j@g.com', nombre: 'J', rol: 'admin' },
    });
    const fakeImageBase64 = 'data:image/png;base64,fake';

    useAuthStore.getState().updateProfileImage(fakeImageBase64);
    expect(useAuthStore.getState().user?.profileImage).toBe(fakeImageBase64);
  });
});
