import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

describe('Plan de Seguridad Opción C — Grado Forense (Google OIDC + PKCE S256 + RS256 JWKS + TOTP AES-256-GCM)', () => {
  const rootDir = path.resolve(__dirname, '../../..');

  it('PHP CLI: suite criptográfica OIDC/JWKS/PKCE/Whitelist/TOTP AES-256-GCM/Sesiones/Auditoría debe aprobar al 100 %', () => {
    const phpScript = path.resolve(rootDir, 'tests/php/test_google_oidc_and_totp.php');
    expect(fs.existsSync(phpScript)).toBe(true);

    const output = execFileSync('php', ['-d', 'error_reporting=E_ALL', phpScript], {
      cwd: rootDir,
      encoding: 'utf-8',
    });

    expect(output).toContain('0 fallaron.');
    expect(output).not.toContain('[FAIL]');
    expect(output).not.toContain('PHP Warning:');
  });

  it('config.php y config.example.php deben deshabilitar password_login_enabled y definir SameSite=Lax, 30m/8h y whitelist de 2 correos', () => {
    const configPhp = fs.readFileSync(path.resolve(rootDir, 'public/api/config.php'), 'utf-8');
    const examplePhp = fs.readFileSync(path.resolve(rootDir, 'public/api/config.example.php'), 'utf-8');

    expect(configPhp).toContain("'password_login_enabled' => false");
    expect(configPhp).toContain("\$defaultConfig['security']['password_login_enabled'] = false;");
    expect(configPhp).toContain("'samesite'         => 'Lax'");
    expect(configPhp).toContain("'httponly'         => true");
    expect(configPhp).toContain("'idle_timeout'     => 1800");
    expect(configPhp).toContain("'absolute_timeout' => 28800");
    expect(configPhp).toContain("'pending_mfa_ttl'  => 300");
    expect(configPhp).toContain("'totp_encryption_key'");

    expect(examplePhp).toContain("'password_login_enabled' => false");
    expect(examplePhp).toContain("'samesite'         => 'Lax'");
    expect(examplePhp).toContain("'allowed_emails'");
    expect(examplePhp).toContain('perito.principal@example.com');
    expect(examplePhp).toContain('perito.adquisicion@example.com');
    expect(examplePhp).toContain("'totp_encryption_key'");
    expect(examplePhp).toContain("'google_oidc'");
  });

  it('todos los endpoints protegidos /api/*.php deben exigir Session::requireUser() y Session::requireCsrf() en mutaciones', () => {
    const protectedEndpoints = [
      'public/api/casos.php',
      'public/api/avanzar-etapa.php',
      'public/api/auditoria.php',
      'public/api/perfil.php',
      'public/api/planillas-emitidas.php',
    ];

    for (const relPath of protectedEndpoints) {
      const src = fs.readFileSync(path.resolve(rootDir, relPath), 'utf-8');
      expect(src, `${relPath} debe exigir Session::requireUser()`).toContain('Session::requireUser()');
      expect(src, `${relPath} debe exigir Session::requireCsrf()`).toContain('Session::requireCsrf()');
    }
  });

  it('auth-google-callback.php y auth.php deben auditar en cadena SHA-256 todos los eventos críticos de seguridad', () => {
    const callbackPhp = fs.readFileSync(path.resolve(rootDir, 'public/api/auth-google-callback.php'), 'utf-8');
    const authPhp = fs.readFileSync(path.resolve(rootDir, 'public/api/auth.php'), 'utf-8');

    expect(callbackPhp).toContain('LOGIN_CORREO_NO_AUTORIZADO');
    expect(callbackPhp).toContain('LOGIN_GOOGLE_SUB_MISMATCH');
    expect(callbackPhp).toContain('GOOGLE_SUB_VINCULADO');
    expect(callbackPhp).toContain('Session::setPendingMfa');
    // Callback jamás debe asignar $_SESSION['usuario'] directamente sin TOTP
    expect(callbackPhp).not.toContain("\$_SESSION['usuario']");

    expect(authPhp).toContain('LOGIN_AUTORIZADO');
    expect(authPhp).toContain('MFA_TOTP_FALLIDO');
    expect(authPhp).toContain('MFA_RECOVERY_CODE_USADO');
    expect(authPhp).toContain('MFA_TOTP_ENROLADO');
    expect(authPhp).toContain('MFA_RECOVERY_CODES_REGENERADOS');
    expect(authPhp).toContain('LOGIN_PASSWORD_BLOQUEADO');
    expect(authPhp).toContain('Totp::encryptSecret');
    expect(authPhp).toContain('Totp::decryptSecret');
    expect(authPhp).toContain('totp_last_step');
  });

  it('database.sql y migrations/002_google_oidc_mfa.sql deben incluir google_sub, totp_enrolled_at, totp_last_step, last_login_at y last_login_ip', () => {
    const dbSql = fs.readFileSync(path.resolve(rootDir, 'database.sql'), 'utf-8');
    const migSql = fs.readFileSync(path.resolve(rootDir, 'migrations/002_google_oidc_mfa.sql'), 'utf-8');

    for (const col of ['google_sub', 'totp_enrolled_at', 'totp_last_step', 'last_login_at', 'last_login_ip', 'uk_usuarios_google_sub']) {
      expect(dbSql, `database.sql debe contener ${col}`).toContain(col);
      expect(migSql, `migrations/002_google_oidc_mfa.sql debe contener ${col}`).toContain(col);
    }
    expect(dbSql).toContain('!DISABLED_GOOGLE_OIDC_ONLY!');
    expect(migSql).toContain('!DISABLED_GOOGLE_OIDC_ONLY!');
  });
});
