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
  google_linked: true,
  google_sub_masked: '108••••••••0987',
  totp_enabled: 1,
  totp_enrolled_at: '2026-11-25 10:00:00',
  recovery_codes_remaining: 8,
};

describe('useAuthStore (Google OIDC + Google Authenticator TOTP — Fail-Closed)', () => {
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
    expect(state.user?.google_linked).toBe(true);
    expect(state.csrfToken).toBe('csrf-token-256bit');
    expect(state.pendingMfa).toBe(false);
  });

  it('debe mantener isAuthenticated=false y activar pendingMfa cuando el servidor devuelve 401 con pending_mfa=true', async () => {
    vi.spyOn(phpApi, 'checkAuth').mockResolvedValueOnce({
      ok: false,
      status: 401,
      data: {
        ok: false,
        authenticated: false,
        password_login_enabled: false,
        pending_mfa: true,
        mfa_step: 'verify',
        pending_email: 'julljoll@gmail.com',
        user: null,
        csrf_token: 'csrf-pending',
      },
    });

    const isAuth = await useAuthStore.getState().hydrateSession();
    expect(isAuth).toBe(false);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.user).toBeNull();
    expect(state.pendingMfa).toBe(true);
    expect(state.mfaStep).toBe('verify');
    expect(state.pendingEmail).toBe('julljoll@gmail.com');
  });

  it('debe promover sesión tras verificar código de 6 dígitos de Google Authenticator', async () => {
    vi.spyOn(phpApi, 'verifyMfa').mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        ok: true,
        authenticated: true,
        user: mockUserDto,
        csrf_token: 'csrf-after-mfa',
      },
    });

    const ok = await useAuthStore.getState().verifyMfa('123456', false);
    expect(ok).toBe(true);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.user?.email).toBe('julljoll@gmail.com');
    expect(state.csrfToken).toBe('csrf-after-mfa');
    expect(state.pendingMfa).toBe(false);
  });

  it('debe validar formato de 6 dígitos TOTP y 8 caracteres de recuperación antes de llamar a la red', async () => {
    const spy = vi.spyOn(phpApi, 'verifyMfa');

    expect(await useAuthStore.getState().verifyMfa('12345', false)).toBe(false);
    expect(useAuthStore.getState().error).toContain('6 dígitos');
    expect(await useAuthStore.getState().verifyMfa('ABC', true)).toBe(false);
    expect(useAuthStore.getState().error).toContain('8 caracteres');
    expect(spy).not.toHaveBeenCalled();
  });

  it('debe confirmar enrolamiento TOTP inicial y devolver los 8 códigos de respaldo', async () => {
    const codes = ['AAAA-BBBB', 'CCCC-DDDD', 'EEEE-FFFF', 'GGGG-HHHH', 'JJJJ-KKKK', 'LLLL-MMMM', 'NNNN-PPPP', 'QQQQ-RRRR'];
    vi.spyOn(phpApi, 'enrollMfaConfirm').mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        ok: true,
        authenticated: true,
        user: mockUserDto,
        recovery_codes: codes,
        csrf_token: 'csrf-enrolled',
      },
    });

    const res = await useAuthStore.getState().enrollMfaConfirm('654321');
    expect(res.ok).toBe(true);
    expect(res.recoveryCodes).toEqual(codes);
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('debe cerrar sesión correctamente y limpiar el estado y tokens', () => {
    useAuthStore.setState({
      isAuthenticated: true,
      user: { id: '1', email: 'j@g.com', nombre: 'J', rol: 'admin' },
      csrfToken: 'tok',
      pendingMfa: true,
      mfaStep: 'verify',
      pendingEmail: 'j@g.com',
    });

    useAuthStore.getState().logout();
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.user).toBeNull();
    expect(state.csrfToken).toBeNull();
    expect(state.pendingMfa).toBe(false);
    expect(state.mfaStep).toBeNull();
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
