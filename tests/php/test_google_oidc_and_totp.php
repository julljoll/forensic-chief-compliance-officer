<?php
/**
 * SHA256.US — Suite de Pruebas Unitarias PHP CLI (Opción C — Grado Forense)
 *
 * Verifica determinísticamente en PHP 8.2+ sin servicios externos:
 *  1. PKCE S256 (RFC 7636) y URL de autorización Google OIDC.
 *  2. Conversión ASN.1 DER JWK RSA -> PEM y verificación criptográfica RS256 JWKS de ID Tokens.
 *  3. Rechazos obligatorios JWT: firma adulterada, alg=none, alg=HS256, kid desconocido,
 *     iss inválido, aud inválido, exp vencido, nonce mismatch, email_verified !== true.
 *  4. Lista blanca inmutable estricta de exactamente 2 correos de peritos.
 *  5. TOTP RFC 6238 (vectores oficiales), cifrado en reposo AES-256-GCM (enc:v1:),
 *     detección de manipulación de tag GCM y 8 códigos de respaldo bcrypt.
 *  6. Aislamiento de sesión `pending_mfa` (TTL 5 min sin acceso a Session::getUser()),
 *     expiración por inactividad (30 min) y absoluta (8 h), CSRF y password_login_enabled=false.
 *  7. Cadena SHA-256 de auditoría inmutable (AuditLog) + Rate-Limit (5 intentos / 15 min) en SQLite PDO.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../public/api/lib/canonical.php';
require_once __DIR__ . '/../../public/api/lib/google_oidc.php';
require_once __DIR__ . '/../../public/api/lib/totp.php';
require_once __DIR__ . '/../../public/api/lib/audit.php';
require_once __DIR__ . '/../../public/api/lib/db.php';
require_once __DIR__ . '/../../public/api/lib/auth.php';

use Sha256\Audit\AuditLog;
use Sha256\Auth\GoogleOidc;
use Sha256\Auth\GoogleOidcException;
use Sha256\Auth\Session;
use Sha256\Auth\Totp;
use Sha256\Crypto\Canonical;
use Sha256\Db\Database;

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
    assertTrue($expected === $actual, $label . ($expected === $actual ? '' : ' (esperado=' . var_export($expected, true) . ', actual=' . var_export($actual, true) . ')'));
}

function assertThrows(callable $fn, string $expectedClass, ?string $expectedErrorCode, string $label): void
{
    try {
        $fn();
        assertTrue(false, "{$label} (no lanzó excepción)");
    } catch (\Throwable $e) {
        $okClass = $e instanceof $expectedClass;
        $okCode = true;
        if ($expectedErrorCode !== null && $e instanceof GoogleOidcException) {
            $okCode = $e->getErrorCode() === $expectedErrorCode;
        }
        assertTrue($okClass && $okCode, "{$label} [" . get_class($e) . ($e instanceof GoogleOidcException ? ':' . $e->getErrorCode() : '') . ']');
    }
}

function signTestJwt(array $header, array $payload, \OpenSSLAsymmetricKey $privateKey): string
{
    $h = GoogleOidc::base64UrlEncode((string)json_encode($header, JSON_UNESCAPED_SLASHES));
    $p = GoogleOidc::base64UrlEncode((string)json_encode($payload, JSON_UNESCAPED_SLASHES));
    $signingInput = "{$h}.{$p}";
    $sig = '';
    if (!openssl_sign($signingInput, $sig, $privateKey, OPENSSL_ALGO_SHA256)) {
        throw new \RuntimeException('openssl_sign falló');
    }
    return "{$signingInput}." . GoogleOidc::base64UrlEncode($sig);
}

echo "=== SHA256.US — Suite PHP CLI (OIDC / JWKS / TOTP AES-256-GCM / Session / Audit) ===\n";

// ----------------------------------------------------------------------------
// 1. PKCE S256 & URL de Autorización Google OIDC
// ----------------------------------------------------------------------------
$pkce = GoogleOidc::generatePkcePair();
assertSame('S256', $pkce['method'], 'PKCE utiliza método S256');
assertSame(43, strlen($pkce['verifier']), 'PKCE verifier tiene 43 caracteres Base64URL (256 bits)');
assertSame(
    GoogleOidc::base64UrlEncode(hash('sha256', $pkce['verifier'], true)),
    $pkce['challenge'],
    'PKCE challenge coincide exactamente con SHA-256 Base64URL del verifier'
);

$state = GoogleOidc::generateState();
$nonce = GoogleOidc::generateNonce();
$authUrl = GoogleOidc::buildAuthorizationUrl([
    'client_id'    => '123456-test.apps.googleusercontent.com',
    'redirect_uri' => 'https://sha256.us/api/auth-google-callback.php',
], $state, $nonce, $pkce['challenge']);

assertTrue(str_starts_with($authUrl, 'https://accounts.google.com/o/oauth2/v2/auth?'), 'Auth URL apunta al endpoint oficial de Google');
assertTrue(str_contains($authUrl, 'code_challenge_method=S256'), 'Auth URL incluye code_challenge_method=S256');
assertTrue(str_contains($authUrl, 'state=' . rawurlencode($state)), 'Auth URL incluye parámetro state');
assertTrue(str_contains($authUrl, 'nonce=' . rawurlencode($nonce)), 'Auth URL incluye parámetro nonce');
assertTrue(str_contains($authUrl, 'response_type=code'), 'Auth URL utiliza Authorization Code Flow');

assertThrows(
    fn() => GoogleOidc::buildAuthorizationUrl(['client_id' => 'REEMPLAZAR.apps.googleusercontent.com', 'redirect_uri' => 'https://sha256.us/cb'], $state, $nonce, $pkce['challenge']),
    GoogleOidcException::class,
    'OAUTH_NOT_CONFIGURED',
    'buildAuthorizationUrl rechaza client_id placeholder en modo fail-closed'
);

// ----------------------------------------------------------------------------
// 2. Generación RSA-2048 -> JWK -> PEM -> Verificación RS256 JWKS
// ----------------------------------------------------------------------------
$rsaKey = openssl_pkey_new([
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
assertTrue($rsaKey !== false, 'OpenSSL genera par RSA-2048 para pruebas JWKS');
$details = openssl_pkey_get_details($rsaKey);
assertTrue(is_array($details) && isset($details['rsa']['n'], $details['rsa']['e']), 'Detalles RSA n y e extraídos correctamente');

$kid = 'google-test-kid-2026';
$jwk = [
    'kty' => 'RSA',
    'use' => 'sig',
    'alg' => 'RS256',
    'kid' => $kid,
    'n'   => GoogleOidc::base64UrlEncode($details['rsa']['n']),
    'e'   => GoogleOidc::base64UrlEncode($details['rsa']['e']),
];
$jwks = ['keys' => [$jwk]];

$pem = GoogleOidc::jwkToPem($jwk);
assertTrue(str_contains($pem, '-----BEGIN PUBLIC KEY-----'), 'jwkToPem produce PEM X.509 válido');
assertTrue(openssl_pkey_get_public($pem) !== false, 'PEM derivado del JWK es cargado sin errores por OpenSSL');

$now = 1770000000;
$clientId = '999999-forensic.apps.googleusercontent.com';
$basePayload = [
    'iss'            => 'https://accounts.google.com',
    'aud'            => $clientId,
    'sub'            => '108452319876543210987',
    'email'          => 'Perito.Uno@Example.COM',
    'email_verified' => true,
    'name'           => 'Perito Uno',
    'nonce'          => $nonce,
    'iat'            => $now - 10,
    'exp'            => $now + 3600,
];

$validJwt = signTestJwt(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid], $basePayload, $rsaKey);
$claims = GoogleOidc::verifyIdToken($validJwt, $jwks, $clientId, $nonce, $now);
assertSame('108452319876543210987', $claims['sub'], 'verifyIdToken extrae sub inmutable');
assertSame('perito.uno@example.com', $claims['email'], 'verifyIdToken normaliza email a minúsculas');
assertSame(true, $claims['email_verified'], 'verifyIdToken confirma email_verified === true');

// Firma adulterada
$jwtParts = explode('.', $validJwt);
$tamperedPayload = $basePayload;
$tamperedPayload['email'] = 'atacante@evil.com';
$tamperedJwt = $jwtParts[0] . '.' . GoogleOidc::base64UrlEncode((string)json_encode($tamperedPayload)) . '.' . $jwtParts[2];
assertThrows(
    fn() => GoogleOidc::verifyIdToken($tamperedJwt, $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_SIGNATURE_INVALID',
    'verifyIdToken rechaza payload adulterado con firma inválida'
);

// Ataque alg=none
$noneJwt = GoogleOidc::base64UrlEncode((string)json_encode(['alg' => 'none', 'kid' => $kid])) . '.'
    . GoogleOidc::base64UrlEncode((string)json_encode($basePayload)) . '.AAAA';
assertThrows(
    fn() => GoogleOidc::verifyIdToken($noneJwt, $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_ALG_INVALID',
    'verifyIdToken rechaza ataque alg=none'
);

// Ataque algorithm confusion HS256
$hsHeader = GoogleOidc::base64UrlEncode((string)json_encode(['alg' => 'HS256', 'kid' => $kid]));
$hsPayload = GoogleOidc::base64UrlEncode((string)json_encode($basePayload));
$hsSig = GoogleOidc::base64UrlEncode(hash_hmac('sha256', "{$hsHeader}.{$hsPayload}", $pem, true));
assertThrows(
    fn() => GoogleOidc::verifyIdToken("{$hsHeader}.{$hsPayload}.{$hsSig}", $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_ALG_INVALID',
    'verifyIdToken rechaza ataque algorithm confusion HS256'
);

// kid desconocido (señal para refrescar JWKS)
$unknownKidJwt = signTestJwt(['alg' => 'RS256', 'kid' => 'kid-rotado'], $basePayload, $rsaKey);
assertThrows(
    fn() => GoogleOidc::verifyIdToken($unknownKidJwt, $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWKS_KID_NOT_FOUND',
    'verifyIdToken señala JWKS_KID_NOT_FOUND ante rotación de claves'
);

// iss inválido
$badIssPayload = $basePayload;
$badIssPayload['iss'] = 'https://evil.example.com';
assertThrows(
    fn() => GoogleOidc::verifyIdToken(signTestJwt(['alg' => 'RS256', 'kid' => $kid], $badIssPayload, $rsaKey), $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_ISS_INVALID',
    'verifyIdToken rechaza emisor iss no autorizado'
);

// aud inválido
$badAudPayload = $basePayload;
$badAudPayload['aud'] = 'otro-client-id.apps.googleusercontent.com';
assertThrows(
    fn() => GoogleOidc::verifyIdToken(signTestJwt(['alg' => 'RS256', 'kid' => $kid], $badAudPayload, $rsaKey), $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_AUD_INVALID',
    'verifyIdToken rechaza audiencia aud distinta de client_id'
);

// exp expirado
$expiredPayload = $basePayload;
$expiredPayload['exp'] = $now - 120;
assertThrows(
    fn() => GoogleOidc::verifyIdToken(signTestJwt(['alg' => 'RS256', 'kid' => $kid], $expiredPayload, $rsaKey), $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_EXPIRED',
    'verifyIdToken rechaza ID Token expirado'
);

// nonce mismatch
$badNoncePayload = $basePayload;
$badNoncePayload['nonce'] = 'nonce-falso';
assertThrows(
    fn() => GoogleOidc::verifyIdToken(signTestJwt(['alg' => 'RS256', 'kid' => $kid], $badNoncePayload, $rsaKey), $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_NONCE_MISMATCH',
    'verifyIdToken rechaza nonce distinto al de sesión'
);

// email_verified !== true
$unverifiedPayload = $basePayload;
$unverifiedPayload['email_verified'] = false;
assertThrows(
    fn() => GoogleOidc::verifyIdToken(signTestJwt(['alg' => 'RS256', 'kid' => $kid], $unverifiedPayload, $rsaKey), $jwks, $clientId, $nonce, $now),
    GoogleOidcException::class,
    'JWT_EMAIL_UNVERIFIED',
    'verifyIdToken rechaza email_verified === false'
);

// ----------------------------------------------------------------------------
// 3. Lista Blanca Inmutable de Exactamente 2 Correos
// ----------------------------------------------------------------------------
$wl = ['Perito.Uno@Example.com', 'perito.dos@example.com'];
assertSame(['perito.uno@example.com', 'perito.dos@example.com'], GoogleOidc::validateAllowedEmails($wl), 'validateAllowedEmails normaliza exactamente 2 correos');
assertTrue(GoogleOidc::isEmailWhitelisted('PERITO.UNO@example.com', $wl), 'isEmailWhitelisted acepta correo #1 (case-insensitive)');
assertTrue(GoogleOidc::isEmailWhitelisted('perito.dos@example.com', $wl), 'isEmailWhitelisted acepta correo #2');
assertTrue(!GoogleOidc::isEmailWhitelisted('tercero@example.com', $wl), 'isEmailWhitelisted rechaza correo no listado');

assertThrows(fn() => GoogleOidc::validateAllowedEmails([]), GoogleOidcException::class, 'WHITELIST_COUNT_INVALID', 'Lista blanca vacía rechazada');
assertThrows(fn() => GoogleOidc::validateAllowedEmails(['uno@example.com']), GoogleOidcException::class, 'WHITELIST_COUNT_INVALID', 'Lista blanca de 1 correo rechazada');
assertThrows(fn() => GoogleOidc::validateAllowedEmails(['a@x.com', 'b@x.com', 'c@x.com']), GoogleOidcException::class, 'WHITELIST_COUNT_INVALID', 'Lista blanca de 3 correos rechazada');
assertThrows(fn() => GoogleOidc::validateAllowedEmails(['dup@x.com', 'DUP@x.com']), GoogleOidcException::class, 'WHITELIST_COUNT_INVALID', 'Lista blanca con 2 correos duplicados rechazada');

// ----------------------------------------------------------------------------
// 4. TOTP RFC 6238 + Cifrado en Reposo AES-256-GCM + 8 Códigos de Respaldo bcrypt
// ----------------------------------------------------------------------------
$rfcSecret = Totp::base32Encode('12345678901234567890');
assertSame('287082', Totp::getCode($rfcSecret, 1), 'Vector RFC 6238 SHA-1 T=59s (step 1) -> 287082');
assertSame('081804', Totp::getCode($rfcSecret, 37037036), 'Vector RFC 6238 SHA-1 T=1111111109s -> 081804');
assertSame(1, Totp::verifyAndGetSlice($rfcSecret, '287082', 0, 59), 'verifyAndGetSlice devuelve el step exacto para anti-replay');
assertSame(null, Totp::verifyAndGetSlice($rfcSecret, '000000', 0, 59), 'verifyAndGetSlice rechaza código incorrecto');

$hexKey = bin2hex(random_bytes(32));
$b64Key = 'base64:' . base64_encode(random_bytes(32));
$secretPlain = Totp::generateSecret(20);
$enc1 = Totp::encryptSecret($secretPlain, $hexKey);
$enc2 = Totp::encryptSecret($secretPlain, $hexKey);
assertTrue(Totp::isEncryptedSecret($enc1), 'encryptSecret genera formato versionado enc:v1:');
assertTrue($enc1 !== $enc2, 'encryptSecret usa IV CSPRNG único por cifrado (no determinista)');
assertSame($secretPlain, Totp::decryptSecret($enc1, $hexKey), 'decryptSecret recupera el secreto Base32 exacto con clave hex');

$encB64 = Totp::encryptSecret($secretPlain, $b64Key);
assertSame($secretPlain, Totp::decryptSecret($encB64, $b64Key), 'encryptSecret/decryptSecret soporta clave base64:');

// Integridad AES-256-GCM: alterar 1 byte del ciphertext debe fallar verificación de tag
$rawEnc = base64_decode(substr($enc1, 7), true);
$rawEnc[strlen($rawEnc) - 1] = chr(ord($rawEnc[strlen($rawEnc) - 1]) ^ 0xFF);
$tamperedEnc = 'enc:v1:' . base64_encode($rawEnc);
assertThrows(fn() => Totp::decryptSecret($tamperedEnc, $hexKey), \RuntimeException::class, null, 'decryptSecret detecta manipulación de tag AES-256-GCM');
assertThrows(fn() => Totp::decryptSecret($enc1, bin2hex(random_bytes(32))), \RuntimeException::class, null, 'decryptSecret rechaza clave AES incorrecta');
assertThrows(fn() => Totp::decryptSecret($secretPlain, $hexKey), \RuntimeException::class, null, 'decryptSecret rechaza secreto en texto plano');
assertThrows(fn() => Totp::encryptSecret($secretPlain, 'REEMPLAZAR_CLAVE'), \RuntimeException::class, null, 'encryptSecret rechaza clave placeholder');

// 8 Códigos de respaldo bcrypt
$recovery = Totp::generateRecoveryCodes(8);
assertSame(8, count($recovery['plain']), 'generateRecoveryCodes genera exactamente 8 códigos planos');
assertSame(8, count($recovery['hashes']), 'generateRecoveryCodes genera exactamente 8 hashes bcrypt');
assertSame(8, count(array_unique($recovery['plain'])), 'Los 8 códigos de respaldo son únicos');
$matchedIdx = Totp::verifyRecoveryCode($recovery['plain'][3], $recovery['hashes']);
assertSame(3, $matchedIdx, 'verifyRecoveryCode valida código con guion contra hash bcrypt');
assertSame(3, Totp::verifyRecoveryCode(str_replace('-', '', $recovery['plain'][3]), $recovery['hashes']), 'verifyRecoveryCode valida código sin guion');
assertSame(null, Totp::verifyRecoveryCode('ZZZZ-ZZZZ', $recovery['hashes']), 'verifyRecoveryCode rechaza código inexistente');

// ----------------------------------------------------------------------------
// 5. Sesiones Forenses: password_login_enabled=false, pending_mfa TTL 5m, 30m idle / 8h abs, CSRF
// ----------------------------------------------------------------------------
$testConfig = [
    'session' => [
        'name'             => 'SHA256_TEST_SESS',
        'lifetime'         => 28800,
        'idle_timeout'     => 1800,
        'absolute_timeout' => 28800,
        'pending_mfa_ttl'  => 300,
        'oidc_state_ttl'   => 600,
        'secure'           => true,
        'httponly'         => true,
        'samesite'         => 'Lax',
    ],
    'security' => [
        'require_https'          => false,
        'password_login_enabled' => false,
        'rate_limit_max'         => 5,
        'rate_limit_minutes'     => 15,
        'allowed_emails'         => $wl,
        'totp_encryption_key'    => $hexKey,
    ],
];
Session::setConfigForTesting($testConfig);
assertSame(false, Session::isPasswordLoginEnabled(), 'password_login_enabled === false verificado en Session');

$realConfig = require __DIR__ . '/../../public/api/config.php';
assertSame(false, $realConfig['security']['password_login_enabled'], 'config.php mantiene password_login_enabled === false');
assertSame('Lax', $realConfig['session']['samesite'], 'config.php configura cookie SameSite=Lax para OAuth callback');
assertSame(true, $realConfig['session']['httponly'], 'config.php configura cookie HttpOnly=true');
assertSame(1800, $realConfig['session']['idle_timeout'], 'config.php configura 30 min (1800s) de expiración por inactividad');
assertSame(28800, $realConfig['session']['absolute_timeout'], 'config.php configura 8 h (28800s) de expiración absoluta');
assertSame(300, $realConfig['session']['pending_mfa_ttl'], 'config.php configura TTL de 5 min (300s) para pending_mfa');

$fakeUserRow = [
    'id'                   => 'usr-test-01',
    'email'                => 'perito.uno@example.com',
    'google_sub'           => '108452319876543210987',
    'password_hash'        => '!DISABLED_GOOGLE_OIDC_ONLY!',
    'totp_secret'          => $enc1,
    'totp_enabled'         => 1,
    'totp_enrolled_at'     => '2026-11-25 10:00:00',
    'totp_last_step'       => 59000000,
    'totp_recovery_hashes' => json_encode($recovery['hashes']),
    'last_login_at'        => '2026-11-25 12:00:00',
    'last_login_ip'        => '198.51.100.10',
    'nombre'               => 'Perito',
    'apellido'             => 'Forense',
    'rol'                  => 'admin',
    'activo'               => 1,
];

$t0 = 1770000000;
$pending = Session::setPendingMfa($fakeUserRow, '108452319876543210987', '198.51.100.10', $t0);
assertSame(true, $pending['totp_enrolled'], 'pending_mfa detecta TOTP cifrado enrolado');
assertSame(null, Session::getUser($t0), 'Con solo $_SESSION[pending_mfa], Session::getUser() devuelve null (sin acceso a gatekeeper/API)');
assertTrue(Session::getPendingMfa($t0 + 299) !== null, 'pending_mfa sigue vigente dentro de los 5 min (299s)');
assertSame(null, Session::getPendingMfa($t0 + 301), 'pending_mfa expira estrictamente tras 5 min (301s)');

// Promoción tras TOTP verificado
Session::setPendingMfa($fakeUserRow, '108452319876543210987', '198.51.100.10', $t0);
$promoted = Session::promotePendingToAuthenticated($fakeUserRow, $t0);
assertTrue(!isset($promoted['password_hash'], $promoted['totp_secret'], $promoted['totp_recovery_hashes'], $promoted['google_sub']), 'sanitizeUserRow elimina secretos, hashes y sub crudo');
assertSame(true, $promoted['google_linked'], 'Usuario saneado expone google_linked=true');
assertSame(8, $promoted['recovery_codes_remaining'], 'Usuario saneado expone conteo exacto de códigos de respaldo');
assertTrue(Session::getUser($t0 + 1799) !== null, 'Sesión activa dentro del umbral de 30 min de inactividad');
assertSame(null, Session::getUser($t0 + 1799 + 1801), 'Sesión expira en servidor tras superar 30 min de inactividad');

// Expiración absoluta de 8 h aunque haya actividad continua
Session::promotePendingToAuthenticated($fakeUserRow, $t0);
assertTrue(Session::getUser($t0 + 1000) !== null, 'Actividad continua actualiza last_activity');
assertTrue(Session::getUser($t0 + 28000) === null, 'Salto > 30 min expira por inactividad');
Session::promotePendingToAuthenticated($fakeUserRow, $t0);
for ($step = 1; $step <= 16; $step++) {
    Session::getUser($t0 + ($step * 1700)); // cada 28.3 min (<30m), hasta 27200s (<8h)
}
assertTrue(Session::getUser($t0 + 28799) !== null, 'Sesión sigue activa justo antes de 8 h absolutas');
assertSame(null, Session::getUser($t0 + 28801), 'Sesión expira estrictamente al superar 8 h absolutas (28800s)');

// CSRF verification
Session::promotePendingToAuthenticated($fakeUserRow, $t0);
$csrf = Session::getCsrfToken();
assertTrue(strlen($csrf) === 64, 'Token CSRF tiene 256 bits (64 hex)');
assertTrue(Session::verifyCsrf($csrf), 'verifyCsrf acepta token exacto');
assertTrue(!Session::verifyCsrf('invalid-token'), 'verifyCsrf rechaza token inválido');
assertTrue(!Session::verifyCsrf(null), 'verifyCsrf rechaza token nulo');

// ----------------------------------------------------------------------------
// 6. Auditoría Inmutable SHA-256 (AuditLog) + Rate-Limit 5 intentos / 15 min (SQLite PDO)
// ----------------------------------------------------------------------------
$sqlite = new PDO('sqlite::memory:');
$sqlite->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$sqlite->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$sqlite->exec('
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
    CREATE TABLE login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        usuario TEXT NOT NULL,
        intentado_en TEXT NOT NULL,
        exitoso INTEGER NOT NULL DEFAULT 0
    );
');
Database::setConnectionForTesting($sqlite);

$eventsToAudit = [
    ['intruso@evil.com', 'LOGIN_CORREO_NO_AUTORIZADO', 'Correo fuera de lista blanca', 'error'],
    ['perito.uno@example.com', 'LOGIN_GOOGLE_SUB_MISMATCH', 'Mismatch de claim sub', 'error'],
    ['perito.uno@example.com', 'MFA_TOTP_FALLIDO', 'Código TOTP inválido o replay', 'warning'],
    ['perito.uno@example.com', 'MFA_RECOVERY_CODE_USADO', 'Código de recuperación consumido', 'warning'],
    ['perito.uno@example.com', 'LOGIN_AUTORIZADO', 'Google OIDC + TOTP verificado', 'success'],
];
foreach ($eventsToAudit as [$u, $acc, $det, $lvl]) {
    AuditLog::append($sqlite, $u, $acc, $det, $lvl);
}

$rows = $sqlite->query('SELECT * FROM auditoria ORDER BY seq ASC')->fetchAll();
assertSame(5, count($rows), 'AuditLog registró los 5 eventos obligatorios de seguridad');
$prev = Canonical::GENESIS_HASH;
$chainOk = true;
foreach ($rows as $idx => $r) {
    $expectedSeq = $idx + 1;
    $recomputed = Canonical::hash([
        'accion'       => $r['accion'],
        'casoId'       => $r['caso_id'],
        'detalle'      => $r['detalle'],
        'hashAnterior' => $r['hash_anterior'],
        'nivel'        => $r['nivel'],
        'seq'          => (int)$r['seq'],
        'ts'           => $r['ts_utc'],
        'usuario'      => $r['usuario'],
    ]);
    if ((int)$r['seq'] !== $expectedSeq || $r['hash_anterior'] !== $prev || $r['hash_actual'] !== $recomputed) {
        $chainOk = false;
        break;
    }
    $prev = $r['hash_actual'];
}
assertTrue($chainOk, 'Cadena SHA-256 de eventos de auditoría de seguridad es 100 % íntegra y verificable');

// Rate-Limit: 5 intentos fallidos en 15 minutos
$rlIp = '203.0.113.55';
$rlUser = 'perito.uno@example.com';
for ($i = 1; $i <= 4; $i++) {
    Session::recordAttempt($rlIp, $rlUser, false, $t0 + $i);
    assertSame(false, Session::isRateLimited($rlIp, $rlUser, $t0 + $i), "Intento fallido #{$i} aún por debajo del umbral (5)");
}
Session::recordAttempt($rlIp, $rlUser, false, $t0 + 5);
assertSame(true, Session::isRateLimited($rlIp, $rlUser, $t0 + 5), '5.º intento fallido en 15 min activa bloqueo rate-limit');
assertSame(false, Session::isRateLimited($rlIp, $rlUser, $t0 + 910), 'Tras vencer la ventana de 15 min (900s), rate-limit se libera');
Session::recordAttempt($rlIp, $rlUser, true, $t0 + 6);
assertSame(false, Session::isRateLimited($rlIp, $rlUser, $t0 + 6), 'Intento exitoso limpia el contador de fallos');

Database::setConnectionForTesting(null);
Session::setConfigForTesting(null);

echo "\nResumen PHP CLI: {$passed} pasaron, {$failed} fallaron.\n";
exit($failed > 0 ? 1 : 0);
