import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('Seguridad y Gating Estricto de Autenticación (Anti-Bypass Fail-Closed)', () => {
  const rootDir = path.resolve(__dirname, '../../..');

  it('public/gatekeeper.php debe existir y proteger el acceso del lado del servidor con no-store', () => {
    const gatekeeperPath = path.resolve(rootDir, 'public/gatekeeper.php');
    expect(fs.existsSync(gatekeeperPath)).toBe(true);

    const content = fs.readFileSync(gatekeeperPath, 'utf-8');
    expect(content).toContain('Session::getUser()');
    expect(content).toContain("header('Location: /?msg=sesion_requerida'");
    expect(content).toContain('Cache-Control: no-store');
    expect(content).toContain('readfile($targetFile)');
  });

  it('public/.htaccess debe interceptar rutas protegidas, bloquear config/api/lib y mantener CSP script-src self sin SDK externos', () => {
    const htaccessPath = path.resolve(rootDir, 'public/.htaccess');
    expect(fs.existsSync(htaccessPath)).toBe(true);

    const htaccess = fs.readFileSync(htaccessPath, 'utf-8');
    expect(htaccess).toContain('RewriteRule ^(dashboard|casos|flujo|custodia|normativa|auditoria|exportar|seguridad|planillas)(.*)$ gatekeeper.php [QSA,L]');
    expect(htaccess).toContain('RewriteRule ^perfil(.*)$ gatekeeper.php [QSA,L]');
    expect(htaccess).toContain('RewriteRule ^api/lib/ - [F,L]');
    expect(htaccess).toContain('RewriteRule ^api/ - [L]');
    expect(htaccess).toContain("script-src 'self'");
    expect(htaccess).not.toContain('accounts.google.com');
    expect(htaccess).not.toContain('apis.google.com');
    expect(htaccess).not.toContain('gstatic.com');
  });

  it('public/api/auth.php debe devolver HTTP 401 sin usuario autenticado y bloquear login por contraseña (HTTP 403)', () => {
    const authPhpPath = path.resolve(rootDir, 'public/api/auth.php');
    expect(fs.existsSync(authPhpPath)).toBe(true);

    const authPhp = fs.readFileSync(authPhpPath, 'utf-8');
    expect(authPhp).toContain('http_response_code(401);');
    expect(authPhp).toContain("'authenticated'          => false");
    expect(authPhp).toContain("'error'                  => 'Sesión no autorizada o expirada. Debe iniciar sesión.'");
    expect(authPhp).toContain('Session::requireCsrf();');
    expect(authPhp).toContain("if (\$action === 'login')");
    expect(authPhp).toContain('http_response_code(403);');
    expect(authPhp).toContain("'password_login_enabled' => false");
  });

  it('AppLayout.astro debe contener guardia sincrónico en <head> y capa anti-flash', () => {
    const appLayoutPath = path.resolve(rootDir, 'src/layouts/AppLayout.astro');
    expect(fs.existsSync(appLayoutPath)).toBe(true);

    const content = fs.readFileSync(appLayoutPath, 'utf-8');
    expect(content).toContain("sessionStorage.getItem('fcco_auth_active') !== '1'");
    expect(content).toContain("window.location.replace('/?msg=sesion_requerida')");
    expect(content).toContain('html.fcco-auth-loading body');
    expect(content).toContain('<AuthGuard />');
  });

  it('PrintLayout.astro debe proteger las 13 planillas con guardia sincrónico y AuthGuard', () => {
    const printLayoutPath = path.resolve(rootDir, 'src/layouts/PrintLayout.astro');
    expect(fs.existsSync(printLayoutPath)).toBe(true);

    const content = fs.readFileSync(printLayoutPath, 'utf-8');
    expect(content).toContain("sessionStorage.getItem('fcco_auth_active') !== '1'");
    expect(content).toContain("window.location.replace('/?msg=sesion_requerida')");
    expect(content).toContain('html.fcco-auth-loading body');
    expect(content).toContain('<AuthGuard />');
  });

  it('AuthGuard.astro debe operar en modo fail-closed absoluto sin ningún fallback offline que revele contenido', () => {
    const guardPath = path.resolve(rootDir, 'src/components/layout/AuthGuard.astro');
    expect(fs.existsSync(guardPath)).toBe(true);

    const content = fs.readFileSync(guardPath, 'utf-8');
    expect(content).toContain('authRes.status === 200');
    expect(content).toContain('authRes.data?.authenticated === true');
    expect(content).toContain('!!authRes.data?.user');
    expect(content).toContain("sessionStorage.removeItem('fcco_auth_active')");
    expect(content).toContain("window.location.replace('/?msg=sesion_requerida')");

    // Verificar estrictamente que solo exista una llamada a revealContent() (jamás dentro del bloque catch)
    const revealCalls = content.match(/\brevealContent\s*\(/g) ?? [];
    expect(revealCalls.length).toBe(2); // 1 definición de función + 1 única invocación tras HTTP 200 authenticated=true
    expect(content).not.toContain('Verificación de sesión offline');
  });

  it('LoginView.astro debe implementar los 3 estados limpios (Google OIDC, TOTP/Respaldo, QR local) sin contraseñas locales', () => {
    const loginPath = path.resolve(rootDir, 'src/components/views/LoginView.astro');
    expect(fs.existsSync(loginPath)).toBe(true);

    const content = fs.readFileSync(loginPath, 'utf-8');
    expect(content).toContain('id="state-google-login"');
    expect(content).toContain('id="state-mfa-verify"');
    expect(content).toContain('id="state-mfa-enroll"');
    expect(content).toContain('Continuar con Cuenta Google Autorizada');
    expect(content).toContain('/api/auth-google-start.php');
    expect(content).toContain("import QRCode from 'qrcode'");
    expect(content).toContain("sessionStorage.setItem('fcco_auth_active', '1')");
    expect(content).toContain("msg === 'sesion_requerida'");
    expect(content).toContain("msg === 'correo_no_autorizado'");
    expect(content).toContain("msg === 'google_sub_mismatch'");
    // Prohibición estricta de inputs de contraseña local o SDK externo de Google
    expect(content).not.toContain('type="password"');
    expect(content).not.toContain('accounts.google.com/gsi/client');
  });

  it('SeguridadTotpView.astro debe mostrar estado Google vinculado, TOTP activo y regeneración de códigos sin localStorage', () => {
    const segPath = path.resolve(rootDir, 'src/components/views/SeguridadTotpView.astro');
    expect(fs.existsSync(segPath)).toBe(true);

    const content = fs.readFileSync(segPath, 'utf-8');
    expect(content).toContain('id="badge-google-linked"');
    expect(content).toContain('id="seg-google-sub"');
    expect(content).toContain('id="form-regenerar-codigos"');
    expect(content).toContain('phpApi.regenerateRecoveryCodes');
    expect(content).toContain("import QRCode from 'qrcode'");
    expect(content).not.toContain('fcco_totp_secret');
    expect(content).not.toContain('fcco_totp_backup_codes');
  });
});
