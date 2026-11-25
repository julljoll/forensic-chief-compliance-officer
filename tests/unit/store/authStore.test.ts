import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from '@/store/authStore';
import { phpApi, type UsuarioPerfilDTO } from '@/lib/data/phpApi';

const mockUserDto: UsuarioPerfilDTO = {
  id: 'usr-jull-01',
  email: 'julljoll@gmail.com',
  nombre: 'Jull',
  apellido: 'Joll',
  ci: 'V-18.999.001',
  cargo: 'Perito Analizador de Datos Forenses',
  rol: 'admin',
  organismo: 'Laboratorio Privado SHA256.US',
  despacho: 'Área de Análisis e Interpretación (F3/F4)',
  telefono: '+58 412-0000000',
  direccion: '',
  especialidad: 'Informática Forense',
  civ: 'CIV-299410',
  inpre: 'INPRE-184920',
  auth_method: 'email_otp',
};

describe('useAuthStore (Código OTP 6 Dígitos + Enlace Mágico por Correo — Fail-Closed)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(phpApi, 'logout').mockResolvedValue();
    useAuthStore.getState().logout();
  });

  it('debe hidratar sesión autenticada exclusivamente cuando /api/auth.php devuelve HTTP 200 y authenticated=true', async () => {
    vi.spyOn(phpApi, 'checkAuth').mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        ok: true,
        authenticated: true,
        auth_method: 'email_otp',
        password_login_enabled: false,
        user: mockUserDto,
        csrf_token: 'csrf-token-256bit',
      },
    });

    const isAuth = await useAuthStore.getState().hydrateSession();
    expect(isAuth).toBe(true);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.user?.email).toBe('julljoll@gmail.com');
    expect(state.csrfToken).toBe('csrf-token-256bit');
  });

  it('debe solicitar código OTP de 6 dígitos para correo válido y marcar otpSent=true', async () => {
    vi.spyOn(phpApi, 'requestOtp').mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        ok: true,
        email: 'julljoll@gmail.com',
        expires_in: 300,
        cooldown: 45,
      },
    });

    const ok = await useAuthStore.getState().requestOtp('JullJoll@gmail.com');
    expect(ok).toBe(true);

    const state = useAuthStore.getState();
    expect(state.otpSent).toBe(true);
    expect(state.pendingEmail).toBe('julljoll@gmail.com');
    expect(state.isAuthenticated).toBe(false);
  });

  it('debe autenticar al verificar un código OTP de 6 dígitos válido', async () => {
    vi.spyOn(phpApi, 'verifyOtp').mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        ok: true,
        authenticated: true,
        auth_method: 'email_otp',
        user: mockUserDto,
        csrf_token: 'csrf-after-otp',
      },
    });

    const ok = await useAuthStore.getState().verifyOtp('julljoll@gmail.com', '482 917');
    expect(ok).toBe(true);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.user?.email).toBe('julljoll@gmail.com');
    expect(state.csrfToken).toBe('csrf-after-otp');
  });

  it('debe autenticar con un enlace mágico válido de 64 caracteres hex', async () => {
    const validToken = 'a'.repeat(64);
    vi.spyOn(phpApi, 'verifyMagicLink').mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        ok: true,
        authenticated: true,
        auth_method: 'magic_link',
        user: mockUserDto,
        csrf_token: 'csrf-after-magic',
      },
    });

    const ok = await useAuthStore.getState().verifyMagicLink(validToken);
    expect(ok).toBe(true);
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
    expect(useAuthStore.getState().csrfToken).toBe('csrf-after-magic');
  });

  it('debe rechazar correo, código OTP y token mágico malformados antes de llamar a la red', async () => {
    const reqSpy = vi.spyOn(phpApi, 'requestOtp');
    const otpSpy = vi.spyOn(phpApi, 'verifyOtp');
    const magSpy = vi.spyOn(phpApi, 'verifyMagicLink');

    expect(await useAuthStore.getState().requestOtp('correo-invalido')).toBe(false);
    expect(await useAuthStore.getState().verifyOtp('julljoll@gmail.com', '123')).toBe(false);
    expect(await useAuthStore.getState().verifyMagicLink('token-corto')).toBe(false);

    expect(reqSpy).not.toHaveBeenCalled();
    expect(otpSpy).not.toHaveBeenCalled();
    expect(magSpy).not.toHaveBeenCalled();
  });

  it('debe cerrar sesión correctamente y limpiar estado', () => {
    useAuthStore.setState({
      isAuthenticated: true,
      user: { id: '1', email: 'j@g.com', nombre: 'J', rol: 'admin' },
      csrfToken: 'tok',
      otpSent: true,
      pendingEmail: 'j@g.com',
    });

    useAuthStore.getState().logout();
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.user).toBeNull();
    expect(state.csrfToken).toBeNull();
    expect(state.otpSent).toBe(false);
    expect(state.pendingEmail).toBeNull();
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
