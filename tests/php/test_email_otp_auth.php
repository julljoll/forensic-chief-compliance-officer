<?php
/**
 * SHA256.US — Suite de Pruebas Unitarias PHP CLI: Acceso por Código OTP (6 Dígitos) + Enlace Mágico por Correo
 */

declare(strict_types=1);

require_once __DIR__ . '/../../public/api/lib/canonical.php';
require_once __DIR__ . '/../../public/api/lib/email_otp.php';
require_once __DIR__ . '/../../public/api/lib/mailer.php';
require_once __DIR__ . '/../../public/api/lib/audit.php';
require_once __DIR__ . '/../../public/api/lib/db.php';
require_once __DIR__ . '/../../public/api/lib/auth.php';

use Sha256\Audit\AuditLog;
use Sha256\Auth\EmailOtp;
use Sha256\Auth\EmailOtpException;
use Sha256\Auth\Session;
use Sha256\Crypto\Canonical;
use Sha256\Db\Database;
use Sha256\Mail\Mailer;

$passed = 0;
$failed = 0;

function assertTrue(bool $cond, string $label): void
{
    global $passed, $failed;
    if ($cond) {
        $passed++;
        echo "  [OK] {$label}\n";
    } else {
        $failed++;
        fwrite(STDERR, "  [FAIL] {$label}\n");
    }
}

function assertSame(mixed $expected, mixed $actual, string $label): void
{
    assertTrue(
        $expected === $actual,
        $label . ($expected === $actual ? '' : ' (esperado=' . var_export($expected, true) . ', actual=' . var_export($actual, true) . ')')
    );
}

function assertThrows(callable $fn, string $expectedClass, ?string $expectedCode, string $label): void
{
    try {
        $fn();
        assertTrue(false, "{$label} (no lanzó excepción)");
    } catch (\Throwable $e) {
        $okClass = $e instanceof $expectedClass;
        $okCode = true;
        if ($expectedCode !== null && $e instanceof EmailOtpException) {
            $okCode = $e->getErrorCode() === $expectedCode;
        }
        assertTrue($okClass && $okCode, "{$label} [" . get_class($e) . ($e instanceof EmailOtpException ? ':' . $e->getErrorCode() : '') . ']');
    }
}

echo "=== SHA256.US — Suite PHP CLI (Email OTP 6 Dígitos + Magic Link + Mailer + Session + Audit) ===\n";

// ----------------------------------------------------------------------------
// 1. Lista blanca estricta de exactamente 2 correos de peritos
// ----------------------------------------------------------------------------
$wl = ['JullJoll@gmail.com', 'sha256.us@gmail.com'];
assertSame(['julljoll@gmail.com', 'sha256.us@gmail.com'], EmailOtp::validateAllowedEmails($wl), 'validateAllowedEmails normaliza exactamente 2 correos');
assertTrue(EmailOtp::isEmailWhitelisted('JULLJOLL@GMAIL.COM', $wl), 'isEmailWhitelisted acepta correo #1 (case-insensitive)');
assertTrue(EmailOtp::isEmailWhitelisted('sha256.us@gmail.com', $wl), 'isEmailWhitelisted acepta correo #2');
assertTrue(!EmailOtp::isEmailWhitelisted('intruso@gmail.com', $wl), 'isEmailWhitelisted rechaza correo no autorizado');
assertThrows(fn() => EmailOtp::validateAllowedEmails([]), EmailOtpException::class, 'WHITELIST_COUNT_INVALID', 'Lista blanca vacía rechazada');
assertThrows(fn() => EmailOtp::validateAllowedEmails(['uno@example.com']), EmailOtpException::class, 'WHITELIST_COUNT_INVALID', 'Lista blanca de 1 correo rechazada');
assertThrows(fn() => EmailOtp::validateAllowedEmails(['a@x.com', 'b@x.com', 'c@x.com']), EmailOtpException::class, 'WHITELIST_COUNT_INVALID', 'Lista blanca de 3 correos rechazada');

// ----------------------------------------------------------------------------
// 2. Generación OTP 6 dígitos + Enlace Mágico 256-bit + Hashes SHA-256
// ----------------------------------------------------------------------------
$otp = EmailOtp::generateOtpCode();
$magic = EmailOtp::generateMagicToken();
assertTrue(strlen($otp) === 6 && ctype_digit($otp), 'OTP generado tiene exactamente 6 dígitos numéricos');
assertTrue(strlen($magic) === 64 && ctype_xdigit($magic), 'Token mágico tiene 64 hex (256 bits)');
assertTrue(
    EmailOtp::hashOtp('julljoll@gmail.com', $otp) !== EmailOtp::hashOtp('sha256.us@gmail.com', $otp),
    'Hash OTP queda vinculado criptográficamente al correo destinatario'
);

// ----------------------------------------------------------------------------
// 3. Flujo Completo en SQLite PDO: creación, cooldown, expiración, consumo único y bloqueo 5 intentos
// ----------------------------------------------------------------------------
$sqlite = new PDO('sqlite::memory:');
$sqlite->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$sqlite->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$sqlite->exec('
    CREATE TABLE email_otp_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id TEXT NOT NULL,
        email TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        magic_token_hash TEXT NOT NULL UNIQUE,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 5,
        ip_solicitud TEXT NOT NULL DEFAULT "",
        expires_at TEXT NOT NULL,
        consumed_at TEXT NULL,
        creado_en TEXT NOT NULL
    );
    CREATE TABLE login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        usuario TEXT NOT NULL,
        intentado_en TEXT NOT NULL,
        exitoso INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE auditoria (
        seq INTEGER PRIMARY KEY,
        caso_id TEXT NULL,
        usuario TEXT NOT NULL,
        accion TEXT NOT NULL,
        detalle TEXT NOT NULL,
        nivel TEXT NOT NULL,
        ts_utc TEXT NOT NULL,
        hash_anterior TEXT NOT NULL,
        hash_actual TEXT NOT NULL
    );
');
Database::setConnectionForTesting($sqlite);

$secCfg = [
    'otp_ttl_seconds'      => 300,
    'otp_max_attempts'     => 5,
    'otp_resend_cooldown'  => 45,
    'otp_max_requests_15m' => 5,
    'rate_limit_max'       => 5,
    'rate_limit_minutes'   => 15,
    'allowed_emails'       => $wl,
];

$t0 = 1770000000;
$ch1 = EmailOtp::createChallenge($sqlite, 'usr-jull-01', 'julljoll@gmail.com', '198.51.100.10', $secCfg, $t0);
assertSame(300, $ch1['ttl_seconds'], 'Reto OTP tiene TTL de 5 minutos (300s)');

// En BD no debe existir el código ni el token en texto plano
$storedRow = $sqlite->query('SELECT * FROM email_otp_tokens WHERE id = ' . $ch1['id'])->fetch();
assertTrue($storedRow['otp_hash'] !== $ch1['otp_code'], 'El código OTP NO se almacena en texto plano en BD');
assertTrue($storedRow['magic_token_hash'] !== $ch1['magic_token'], 'El token mágico NO se almacena en texto plano en BD');

// Cooldown de 45 segundos
assertThrows(
    fn() => EmailOtp::createChallenge($sqlite, 'usr-jull-01', 'julljoll@gmail.com', '198.51.100.10', $secCfg, $t0 + 20),
    EmailOtpException::class,
    'OTP_COOLDOWN',
    'Enfriamiento de 45s bloquea reenvío inmediato'
);

// Verificar OTP válido y comprobar consumo atómico de un solo uso (anti-replay)
$okRes = EmailOtp::verifyOtp($sqlite, 'julljoll@gmail.com', $ch1['otp_code'], $t0 + 60);
assertSame(true, $okRes['ok'], 'Código OTP de 6 dígitos válido es aceptado');
assertSame('usr-jull-01', $okRes['usuario_id'], 'verifyOtp devuelve usuario_id correcto');

$replayRes = EmailOtp::verifyOtp($sqlite, 'julljoll@gmail.com', $ch1['otp_code'], $t0 + 61);
assertSame(false, $replayRes['ok'], 'Reutilizar el mismo código OTP falla (anti-replay uso único)');

// El enlace mágico del mismo reto ya consumido también debe fallar
$magicAfterOtp = EmailOtp::verifyMagicToken($sqlite, $ch1['magic_token'], $t0 + 62);
assertSame(false, $magicAfterOtp['ok'], 'El enlace mágico queda invalidado una vez consumido el código OTP');
assertSame('ALREADY_USED', $magicAfterOtp['reason'], 'Motivo exacto ALREADY_USED en enlace mágico');

// Reto #2: probar expiración estricta tras 5 minutos (301s)
$ch2 = EmailOtp::createChallenge($sqlite, 'usr-jull-01', 'julljoll@gmail.com', '198.51.100.10', $secCfg, $t0 + 100);
$expRes = EmailOtp::verifyOtp($sqlite, 'julljoll@gmail.com', $ch2['otp_code'], $t0 + 401);
assertSame(false, $expRes['ok'], 'Código OTP expirado (>5 min) es rechazado');
assertSame('EXPIRED', $expRes['reason'], 'Motivo exacto EXPIRED');

// Reto #3: probar bloqueo tras 5 intentos fallidos sobre el mismo código
$ch3 = EmailOtp::createChallenge($sqlite, 'usr-jull-01', 'julljoll@gmail.com', '198.51.100.10', $secCfg, $t0 + 200);
$wrongCode = ($ch3['otp_code'] === '000000') ? '111111' : '000000';
for ($a = 1; $a <= 4; $a++) {
    $r = EmailOtp::verifyOtp($sqlite, 'julljoll@gmail.com', $wrongCode, $t0 + 210 + $a);
    assertSame('CODE_MISMATCH', $r['reason'], "Intento erróneo #{$a} retorna CODE_MISMATCH");
}
$r5 = EmailOtp::verifyOtp($sqlite, 'julljoll@gmail.com', $wrongCode, $t0 + 220);
assertSame('MAX_ATTEMPTS_EXCEEDED', $r5['reason'], '5.º fallo invalida el código con MAX_ATTEMPTS_EXCEEDED');
$rAfterLock = EmailOtp::verifyOtp($sqlite, 'julljoll@gmail.com', $ch3['otp_code'], $t0 + 221);
assertSame(false, $rAfterLock['ok'], 'Incluso el código correcto falla tras agotarse los 5 intentos');

// Reto #4: probar Enlace Mágico válido de 1 clic + anti-replay
$ch4 = EmailOtp::createChallenge($sqlite, 'usr-sha256-02', 'sha256.us@gmail.com', '198.51.100.20', $secCfg, $t0 + 300);
$mOk = EmailOtp::verifyMagicToken($sqlite, $ch4['magic_token'], $t0 + 310);
assertSame(true, $mOk['ok'], 'Enlace mágico válido de 256 bits es aceptado');
assertSame('usr-sha256-02', $mOk['usuario_id'], 'verifyMagicToken devuelve usuario_id correcto');
assertSame('sha256.us@gmail.com', $mOk['email'], 'verifyMagicToken devuelve correo correcto');
$mReplay = EmailOtp::verifyMagicToken($sqlite, $ch4['magic_token'], $t0 + 311);
assertSame('ALREADY_USED', $mReplay['reason'], 'Reutilizar enlace mágico es bloqueado (ALREADY_USED)');

// ----------------------------------------------------------------------------
// 4. Mailer: resolución automática php_mail / smtp y formato HTML+Texto
// ----------------------------------------------------------------------------
assertSame('php_mail', Mailer::resolveDriver(['driver' => 'auto', 'smtp_host' => '']), 'Mailer auto elige php_mail sin credenciales SMTP');
assertSame('smtp', Mailer::resolveDriver(['driver' => 'auto', 'smtp_host' => 'mail.sha256.us', 'smtp_user' => 'no-reply@sha256.us', 'smtp_pass' => 'secreto-real']), 'Mailer auto elige smtp cuando hay credenciales reales');
assertSame('php_mail', Mailer::resolveDriver(['driver' => 'auto', 'smtp_host' => 'mail.sha256.us', 'smtp_user' => 'no-reply@sha256.us', 'smtp_pass' => 'CLAVE_DE_LA_CUENTA_NO_REPLY_EN_CPANEL']), 'Mailer ignora contraseña placeholder de config.example.php');

$capturedMail = null;
Mailer::setTransportForTesting(function (array $msg) use (&$capturedMail): bool {
    $capturedMail = $msg;
    return true;
});
$sent = Mailer::sendLoginOtp(
    ['driver' => 'auto', 'from_email' => 'no-reply@sha256.us', 'from_name' => 'SHA256.US'],
    'julljoll@gmail.com',
    'Jull Joll',
    '482917',
    'https://sha256.us/?magic=' . $ch4['magic_token'],
    300,
    '198.51.100.10'
);
assertSame(true, $sent, 'Mailer::sendLoginOtp despacha mensaje multipart correctamente');
assertTrue(is_array($capturedMail) && str_contains($capturedMail['subject'], '482 917'), 'Asunto incluye código OTP formateado');
assertTrue(is_array($capturedMail) && str_contains($capturedMail['html'], 'https://sha256.us/?magic='), 'Cuerpo HTML incluye botón de Enlace Mágico');
assertTrue(is_array($capturedMail) && str_contains($capturedMail['text'], '482 917'), 'Cuerpo texto plano incluye código OTP');
Mailer::setTransportForTesting(null);

// ----------------------------------------------------------------------------
// 5. Sesiones (30m idle / 8h absolutas / CSRF / password_login_enabled=false / Rate-limit)
// ----------------------------------------------------------------------------
$realConfig = require __DIR__ . '/../../public/api/config.php';
assertSame(false, $realConfig['security']['password_login_enabled'], 'config.php fuerza password_login_enabled === false');
assertSame('Lax', $realConfig['session']['samesite'], 'config.php configura cookie SameSite=Lax');
assertSame(true, $realConfig['session']['httponly'], 'config.php configura cookie HttpOnly=true');
assertSame(1800, $realConfig['session']['idle_timeout'], 'config.php configura 30 min de inactividad');
assertSame(28800, $realConfig['session']['absolute_timeout'], 'config.php configura 8 h absolutas');

Session::setConfigForTesting($realConfig);
$fakeRow = [
    'id'            => 'usr-jull-01',
    'email'         => 'julljoll@gmail.com',
    'password_hash' => '!DISABLED_EMAIL_OTP_ONLY!',
    'nombre'        => 'Jull',
    'apellido'      => 'Joll',
    'rol'           => 'admin',
    'activo'        => 1,
    'last_login_at' => '2026-11-25 12:00:00',
    'last_login_ip' => '198.51.100.10',
];
$cleanUser = Session::createAuthenticatedSession($fakeRow, 'email_otp', $t0);
assertTrue(!isset($cleanUser['password_hash']), 'Usuario saneado no expone password_hash');
assertTrue(Session::getUser($t0 + 1799) !== null, 'Sesión activa dentro de 30 min de inactividad');
assertSame(null, Session::getUser($t0 + 1799 + 1801), 'Sesión expira tras superar 30 min de inactividad');

Session::createAuthenticatedSession($fakeRow, 'magic_link', $t0);
for ($step = 1; $step <= 16; $step++) {
    Session::getUser($t0 + ($step * 1700));
}
assertTrue(Session::getUser($t0 + 28799) !== null, 'Sesión activa justo antes de 8 h absolutas');
assertSame(null, Session::getUser($t0 + 28801), 'Sesión expira al superar 8 h absolutas');

Session::createAuthenticatedSession($fakeRow, 'email_otp', $t0);
$csrf = Session::getCsrfToken();
assertTrue(strlen($csrf) === 64 && Session::verifyCsrf($csrf) && !Session::verifyCsrf('bad'), 'Token CSRF 256-bit validado en tiempo constante');

// Rate-limit 5 intentos / 15 min
$rlIp = '203.0.113.77';
for ($i = 1; $i <= 4; $i++) {
    Session::recordAttempt($rlIp, 'julljoll@gmail.com', false, $t0 + $i);
    assertSame(false, Session::isRateLimited($rlIp, 'julljoll@gmail.com', $t0 + $i), "Intento fallido #{$i} debajo del límite");
}
Session::recordAttempt($rlIp, 'julljoll@gmail.com', false, $t0 + 5);
assertSame(true, Session::isRateLimited($rlIp, 'julljoll@gmail.com', $t0 + 5), '5.º fallo activa bloqueo rate-limit 15 min');
Session::recordAttempt($rlIp, 'julljoll@gmail.com', true, $t0 + 6);
assertSame(false, Session::isRateLimited($rlIp, 'julljoll@gmail.com', $t0 + 6), 'Acceso exitoso limpia bloqueos previos');

// ----------------------------------------------------------------------------
// 6. Auditoría Inmutable SHA-256 (AuditLog)
// ----------------------------------------------------------------------------
$events = [
    ['intruso@evil.com', 'LOGIN_CORREO_NO_AUTORIZADO', 'Correo fuera de lista blanca', 'error'],
    ['julljoll@gmail.com', 'OTP_SOLICITADO', 'Código OTP y enlace mágico enviados', 'info'],
    ['julljoll@gmail.com', 'OTP_VERIFICACION_FALLIDA', 'Código incorrecto', 'warning'],
    ['julljoll@gmail.com', 'LOGIN_AUTORIZADO', 'Ingreso verificado por OTP 6 dígitos', 'success'],
];
foreach ($events as [$u, $acc, $det, $lvl]) {
    AuditLog::append($sqlite, $u, $acc, $det, $lvl);
}
$auditRows = $sqlite->query('SELECT * FROM auditoria ORDER BY seq ASC')->fetchAll();
assertSame(4, count($auditRows), 'AuditLog asentó los 4 eventos de seguridad OTP');
$prev = Canonical::GENESIS_HASH;
$chainValid = true;
foreach ($auditRows as $idx => $r) {
    $expected = Canonical::hash([
        'accion'       => $r['accion'],
        'casoId'       => $r['caso_id'],
        'detalle'      => $r['detalle'],
        'hashAnterior' => $r['hash_anterior'],
        'nivel'        => $r['nivel'],
        'seq'          => (int)$r['seq'],
        'ts'           => $r['ts_utc'],
        'usuario'      => $r['usuario'],
    ]);
    if ((int)$r['seq'] !== ($idx + 1) || $r['hash_anterior'] !== $prev || $r['hash_actual'] !== $expected) {
        $chainValid = false;
        break;
    }
    $prev = $r['hash_actual'];
}
assertTrue($chainValid, 'Cadena SHA-256 de eventos de auditoría OTP es 100 % íntegra');

Database::setConnectionForTesting(null);
Session::setConfigForTesting(null);

echo "\nResumen PHP CLI: {$passed} pasaron, {$failed} fallaron.\n";
exit($failed > 0 ? 1 : 0);
