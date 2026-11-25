import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

describe('Verificación de Despliegue cPanel y Estructura en dist/', () => {
  const rootDir = path.resolve(__dirname, '../../..');
  const distDir = path.resolve(rootDir, 'dist');

  beforeAll(() => {
    execSync('npm run build', { cwd: rootDir, stdio: 'inherit' });
  }, 90000);

  it('debe existir database.sql y migrations/002_email_otp_auth.sql con email_otp_tokens e inmutabilidad', () => {
    const sqlPath = path.resolve(rootDir, 'database.sql');
    expect(fs.existsSync(sqlPath)).toBe(true);
    const sql = fs.readFileSync(sqlPath, 'utf-8');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS `casos`');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS `fases_caso`');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS `auditoria`');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS `login_attempts`');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS `email_otp_tokens`');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS `planillas_emitidas`');
    expect(sql).toContain('`direccion`');
    expect(sql).toContain('`especialidad`');
    expect(sql).toContain('`last_login_at`');
    expect(sql).toContain('`last_login_ip`');
    expect(sql).toContain('trg_auditoria_no_update');
    expect(sql).toContain('trg_auditoria_no_delete');
    expect(sql).toContain('trg_planillas_emitidas_no_delete');
    expect(sql).toContain('trg_planillas_emitidas_inmutable');

    const migPath = path.resolve(rootDir, 'migrations/002_email_otp_auth.sql');
    expect(fs.existsSync(migPath)).toBe(true);
    const migSql = fs.readFileSync(migPath, 'utf-8');
    expect(migSql).toContain('email_otp_tokens');
    expect(migSql).toContain('otp_hash');
    expect(migSql).toContain('magic_token_hash');
    expect(migSql).toContain('last_login_at');
    expect(migSql).toContain('last_login_ip');
  });

  it('dist/ debe contener .htaccess con reglas de Apache para URLs limpias y CSP sin SDK externos', () => {
    const htaccessPath = path.resolve(distDir, '.htaccess');
    expect(fs.existsSync(htaccessPath)).toBe(true);
    const htaccess = fs.readFileSync(htaccessPath, 'utf-8');
    expect(htaccess).toContain('RewriteEngine On');
    expect(htaccess).toContain('RewriteRule ^api/lib/ - [F,L]');
    expect(htaccess).toContain('RewriteRule ^api/ - [L]');
    expect(htaccess).toContain('RewriteRule ^verificar/?$ verificar.html [QSA,L]');
    expect(htaccess).toContain('RewriteRule ^perfil(.*)$ gatekeeper.php [QSA,L]');
    expect(htaccess).toContain('X-Frame-Options');
    expect(htaccess).toContain('X-Content-Type-Options');
    expect(htaccess).toContain('Content-Security-Policy');
    expect(htaccess).toContain("script-src 'self'");
    expect(htaccess).not.toContain('accounts.google.com');
  });

  it('dist/api/ debe contener todos los controladores y bibliotecas de PHP PDO, Email OTP, Mailer y Auditoría', () => {
    const expectedPhp = [
      'casos.php',
      'avanzar-etapa.php',
      'auditoria.php',
      'auth.php',
      'perfil.php',
      'planillas-emitidas.php',
      'config.php',
      'config.example.php',
      'lib/canonical.php',
      'lib/db.php',
      'lib/auth.php',
      'lib/email_otp.php',
      'lib/mailer.php',
      'lib/audit.php',
      'lib/totp.php',
    ];
    for (const file of expectedPhp) {
      const p = path.resolve(distDir, 'api', file);
      expect(fs.existsSync(p), `Debe existir dist/api/${file}`).toBe(true);
    }
  });

  it('dist/index.html debe mostrar acceso por Código OTP / Enlace Mágico sin campos de contraseña local', () => {
    const indexHtml = fs.readFileSync(path.resolve(distDir, 'index.html'), 'utf-8');
    expect(indexHtml).toContain('Enviar Código de Acceso al Correo');
    expect(indexHtml).toContain('state-email-request');
    expect(indexHtml).toContain('state-otp-verify');
    expect(indexHtml).toContain('state-magic-verifying');
    expect(indexHtml).not.toContain('type="password"');
    expect(indexHtml).not.toContain('accounts.google.com');
  });

  it('dist/ debe contener todas las páginas principales compiladas en HTML estático', () => {
    const expectedPages = [
      'index.html',
      'dashboard.html',
      'casos.html',
      'flujo.html',
      'custodia.html',
      'normativa.html',
      'auditoria.html',
      'exportar.html',
      'perfil.html',
      'seguridad.html',
      'planillas.html',
      'planillas/index.html',
      'verificar.html',
    ];
    for (const page of expectedPages) {
      const p = path.resolve(distDir, page);
      expect(fs.existsSync(p), `Debe existir dist/${page}`).toBe(true);
    }
  });

  it('dist/planillas/ debe contener las 13 planillas oficiales en Folio (216x330mm)', () => {
    const expectedPlanillas = [
      'acta-consentimiento.html',
      'acta-entrevista.html',
      'acta-obtencion.html',
      'planilla-prcc.html',
      'acta-desprecintado.html',
      'acta-dictamen.html',
      'acta-entrega-resultados.html',
      'acta-sanitizacion.html',
      'acta-auditoria-timeline.html',
      'planilla-evaluacion-ux.html',
      'planilla-audio-sonic.html',
      'dictamen-imagenes.html',
      'dictamen-audios.html',
    ];
    for (const pl of expectedPlanillas) {
      const p = path.resolve(distDir, 'planillas', pl);
      expect(fs.existsSync(p), `Debe existir dist/planillas/${pl}`).toBe(true);

      const html = fs.readFileSync(p, 'utf-8');
      expect(html).toContain('folio-forense-aislado');
    }
  });

  it('dist/assets/uswds/ debe contener CSS compilado, JS y fuentes', () => {
    expect(fs.existsSync(path.resolve(distDir, 'assets/uswds/css/uswds.min.css'))).toBe(true);
    expect(fs.existsSync(path.resolve(distDir, 'assets/uswds/js/uswds.min.js'))).toBe(true);
    expect(fs.existsSync(path.resolve(distDir, 'assets/uswds/fonts'))).toBe(true);
  });
});
