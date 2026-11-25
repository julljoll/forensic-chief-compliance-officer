import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

describe('Acceso Seguro Sin Contraseña — Código OTP 6 Dígitos + Enlace Mágico por Correo', () => {
  const rootDir = path.resolve(__dirname, '../../..');

  it('PHP CLI: suite completa de Email OTP, Enlace Mágico, Mailer, Sesiones 30m/8h y Auditoría SHA-256 debe aprobar al 100 %', () => {
    const phpScript = path.resolve(rootDir, 'tests/php/test_email_otp_auth.php');
    expect(fs.existsSync(phpScript)).toBe(true);

    const output = execFileSync('php', ['-d', 'error_reporting=E_ALL', phpScript], {
      cwd: rootDir,
      encoding: 'utf-8',
    });

    expect(output).toContain('0 fallaron.');
    expect(output).not.toContain('[FAIL]');
    expect(output).not.toContain('PHP Warning:');
  });

  it('config.php y config.example.php deben deshabilitar contraseñas locales y definir OTP 5m, 30m/8h, SameSite=Lax y correo cPanel/SMTP', () => {
    const configPhp = fs.readFileSync(path.resolve(rootDir, 'public/api/config.php'), 'utf-8');
    const examplePhp = fs.readFileSync(path.resolve(rootDir, 'public/api/config.example.php'), 'utf-8');

    expect(configPhp).toContain("'password_login_enabled' => false");
    expect(configPhp).toContain("\$defaultConfig['security']['password_login_enabled'] = false;");
    expect(configPhp).toContain("'samesite'         => 'Lax'");
    expect(configPhp).toContain("'httponly'         => true");
    expect(configPhp).toContain("'idle_timeout'     => 1800");
    expect(configPhp).toContain("'absolute_timeout' => 28800");
    expect(configPhp).toContain("'otp_ttl_seconds'        => 300");
    expect(configPhp).toContain("'allowed_emails'");
    expect(configPhp).toContain("'mail'");

    expect(examplePhp).toContain("'password_login_enabled' => false");
    expect(examplePhp).toContain("'samesite' => 'Lax'");
    expect(examplePhp).toContain("'allowed_emails'");
    expect(examplePhp).toContain("'smtp_host'");
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

  it('public/api/auth.php debe auditar en cadena SHA-256 los eventos de OTP, enlace mágico, rechazos y bloqueos', () => {
    const authPhp = fs.readFileSync(path.resolve(rootDir, 'public/api/auth.php'), 'utf-8');

    expect(authPhp).toContain('OTP_SOLICITADO');
    expect(authPhp).toContain('LOGIN_AUTORIZADO');
    expect(authPhp).toContain('LOGIN_CORREO_NO_AUTORIZADO');
    expect(authPhp).toContain('OTP_VERIFICACION_FALLIDA');
    expect(authPhp).toContain('LOGIN_PASSWORD_BLOQUEADO');
    expect(authPhp).toContain('LOGOUT_PERITO');
    expect(authPhp).toContain('EmailOtp::createChallenge');
    expect(authPhp).toContain('EmailOtp::verifyOtp');
    expect(authPhp).toContain('EmailOtp::verifyMagicToken');
  });

  it('database.sql y migrations/002_email_otp_auth.sql deben definir email_otp_tokens y deshabilitar contraseñas locales', () => {
    const dbSql = fs.readFileSync(path.resolve(rootDir, 'database.sql'), 'utf-8');
    const migSql = fs.readFileSync(path.resolve(rootDir, 'migrations/002_email_otp_auth.sql'), 'utf-8');

    for (const token of ['email_otp_tokens', 'otp_hash', 'magic_token_hash', 'last_login_at', 'last_login_ip', '!DISABLED_EMAIL_OTP_ONLY!']) {
      expect(dbSql, `database.sql debe contener ${token}`).toContain(token);
      expect(migSql, `migrations/002_email_otp_auth.sql debe contener ${token}`).toContain(token);
    }
  });
});
