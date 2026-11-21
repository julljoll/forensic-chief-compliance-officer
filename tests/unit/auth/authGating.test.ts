import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('Seguridad y Gating Estricto de Autenticación (Anti-Bypass de URL)', () => {
  const rootDir = path.resolve(__dirname, '../../..');

  it('public/gatekeeper.php debe existir y proteger el acceso del lado del servidor', () => {
    const gatekeeperPath = path.resolve(rootDir, 'public/gatekeeper.php');
    expect(fs.existsSync(gatekeeperPath)).toBe(true);

    const content = fs.readFileSync(gatekeeperPath, 'utf-8');
    expect(content).toContain('Session::getUser()');
    expect(content).toContain("header('Location: /?msg=sesion_requerida'");
    expect(content).toContain('readfile($targetFile)');
  });

  it('public/.htaccess debe interceptar todas las rutas protegidas y enviarlas al gatekeeper', () => {
    const htaccessPath = path.resolve(rootDir, 'public/.htaccess');
    expect(fs.existsSync(htaccessPath)).toBe(true);

    const htaccess = fs.readFileSync(htaccessPath, 'utf-8');
    expect(htaccess).toContain('RewriteRule ^(dashboard|casos|flujo|custodia|normativa|auditoria|exportar|seguridad|planillas)(.*)$ gatekeeper.php [QSA,L]');
    expect(htaccess).toContain('RewriteRule ^api/lib/ - [F,L]');
    expect(htaccess).toContain('RewriteRule ^api/ - [L]');
  });

  it('public/api/auth.php debe devolver HTTP 401 si no hay usuario autenticado', () => {
    const authPhpPath = path.resolve(rootDir, 'public/api/auth.php');
    expect(fs.existsSync(authPhpPath)).toBe(true);

    const authPhp = fs.readFileSync(authPhpPath, 'utf-8');
    expect(authPhp).toContain('http_response_code(401);');
    expect(authPhp).toContain("'authenticated' => false");
    expect(authPhp).toContain("'error'         => 'Sesión no autorizada o expirada. Debe iniciar sesión.'");
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

  it('AuthGuard.astro debe validar rigurosamente la sesión y destruir credenciales locales no autorizadas', () => {
    const guardPath = path.resolve(rootDir, 'src/components/layout/AuthGuard.astro');
    expect(fs.existsSync(guardPath)).toBe(true);

    const content = fs.readFileSync(guardPath, 'utf-8');
    expect(content).toContain("authRes.ok && authRes.data?.authenticated === true && !!authRes.data?.user");
    expect(content).toContain("sessionStorage.removeItem('fcco_auth_active')");
    expect(content).toContain("window.location.replace('/?msg=sesion_requerida')");
  });

  it('LoginView.astro debe registrar la sesión activa en sessionStorage al iniciar sesión', () => {
    const loginPath = path.resolve(rootDir, 'src/components/views/LoginView.astro');
    expect(fs.existsSync(loginPath)).toBe(true);

    const content = fs.readFileSync(loginPath, 'utf-8');
    expect(content).toContain("sessionStorage.setItem('fcco_auth_active', '1')");
    expect(content).toContain("msg === 'sesion_requerida'");
  });
});
