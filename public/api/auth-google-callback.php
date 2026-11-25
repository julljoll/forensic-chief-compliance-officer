<?php
/**
 * SHA256.US — Callback Server-to-Server Google OAuth 2.0 / OIDC (RS256 JWKS + Whitelist 2 Peritos + Binding google_sub)
 *
 * Flujo estricto de Grado Forense (Opción C):
 * 1. Valida state anti-CSRF y TTL de sesión OIDC (consumo único anti-replay).
 * 2. Intercambia code + PKCE S256 code_verifier server-to-server en Google Token Endpoint.
 * 3. Verifica criptográficamente el ID Token con firma RS256 contra JWKS de Google (iss, aud, exp, iat, nonce, email_verified=true).
 * 4. Exige pertenencia a la lista blanca inmutable de EXACTAMENTE 2 correos en config.local.php.
 * 5. Valida usuario activo en MySQL y aplica binding permanente del claim inmutable `google_sub`.
 * 6. Crea ÚNICAMENTE `$_SESSION['pending_mfa']` (TTL 5 min) SIN otorgar acceso a gatekeeper.php ni /api/*.php.
 * 7. Audita en tabla inmutable `auditoria` (SHA-256 chain) los rechazos y vinculaciones.
 */

declare(strict_types=1);

header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/google_oidc.php';
require_once __DIR__ . '/lib/audit.php';

use Sha256\Audit\AuditLog;
use Sha256\Auth\GoogleOidc;
use Sha256\Auth\GoogleOidcException;
use Sha256\Auth\Session;
use Sha256\Db\Database;

function redirectLoginWithMsg(string $msg): never
{
    header('Location: /?msg=' . rawurlencode($msg), true, 302);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'Método no permitido.'], JSON_UNESCAPED_UNICODE);
    exit;
}

Session::start();
$config = Session::getConfig();
$ip = Session::getClientIp();
$pdo = Database::getConnection();

// 1. Verificar si Google devolvió error (cancelación o denegación)
if (!empty($_GET['error'])) {
    $errCode = substr(preg_replace('/[^a-zA-Z0-9_\-]/', '', (string)$_GET['error']) ?? 'unknown', 0, 64);
    unset($_SESSION['oidc_auth']);
    AuditLog::appendSafe($pdo, 'anonimo@oidc', 'LOGIN_OIDC_ERROR', "Autorización Google cancelada o rechazada (error={$errCode}, ip={$ip})", 'warning');
    redirectLoginWithMsg('google_cancelado');
}

$code = trim((string)($_GET['code'] ?? ''));
$state = trim((string)($_GET['state'] ?? ''));

// 2. Recuperar y consumir inmediatamente estado OIDC de sesión (uso único)
$oidcSession = $_SESSION['oidc_auth'] ?? null;
unset($_SESSION['oidc_auth']);

if (!is_array($oidcSession) || $code === '' || $state === '') {
    AuditLog::appendSafe($pdo, 'anonimo@oidc', 'LOGIN_OIDC_ERROR', "Callback OIDC sin código, state o sesión activa (ip={$ip})", 'warning');
    redirectLoginWithMsg('estado_invalido');
}

$expectedState = (string)($oidcSession['state'] ?? '');
$expectedNonce = (string)($oidcSession['nonce'] ?? '');
$codeVerifier = (string)($oidcSession['code_verifier'] ?? '');
$createdAt = (int)($oidcSession['created_at'] ?? 0);
$stateTtl = (int)($config['session']['oidc_state_ttl'] ?? 600);

if (
    $expectedState === '' ||
    $expectedNonce === '' ||
    $codeVerifier === '' ||
    (time() - $createdAt) > $stateTtl ||
    !hash_equals($expectedState, $state)
) {
    AuditLog::appendSafe($pdo, 'anonimo@oidc', 'LOGIN_OIDC_ERROR', "State OIDC inválido o expirado en callback (ip={$ip})", 'warning');
    redirectLoginWithMsg('estado_invalido');
}

// 3. Comprobar rate-limit por IP antes del intercambio
if (Session::isRateLimited($ip, '__oidc_ip__')) {
    AuditLog::appendSafe($pdo, 'anonimo@oidc', 'LOGIN_OIDC_ERROR', "Bloqueo temporal (rate-limit) aplicado en callback OIDC para IP {$ip}", 'warning');
    redirectLoginWithMsg('rate_limited');
}

$googleCfg = $config['google_oidc'] ?? [];
$clientId = trim((string)($googleCfg['client_id'] ?? ''));
$jwksUri = (string)($googleCfg['jwks_uri'] ?? GoogleOidc::DEFAULT_JWKS_URI);
$jwksCachePath = (string)($googleCfg['jwks_cache_path'] ?? (sys_get_temp_dir() . '/sha256_google_jwks.json'));
$jwksCacheTtl = (int)($googleCfg['jwks_cache_ttl'] ?? 3600);

// 4. Intercambio server-to-server Authorization Code + PKCE S256 y verificación RS256 JWKS
try {
    $tokenResponse = GoogleOidc::exchangeCodeForTokens($googleCfg, $code, $codeVerifier);
    $idToken = (string)$tokenResponse['id_token'];

    $jwks = GoogleOidc::fetchJwks($jwksUri, $jwksCachePath, $jwksCacheTtl, false);
    try {
        $claims = GoogleOidc::verifyIdToken($idToken, $jwks, $clientId, $expectedNonce);
    } catch (GoogleOidcException $kidEx) {
        if ($kidEx->getErrorCode() === 'JWKS_KID_NOT_FOUND') {
            // Rotación de claves de Google: refrescar JWKS una única vez y re-verificar
            $jwks = GoogleOidc::fetchJwks($jwksUri, $jwksCachePath, $jwksCacheTtl, true);
            $claims = GoogleOidc::verifyIdToken($idToken, $jwks, $clientId, $expectedNonce);
        } else {
            throw $kidEx;
        }
    }
} catch (GoogleOidcException $e) {
    error_log('[FCCO OIDC Callback Verify Error] ' . $e->getErrorCode() . ': ' . $e->getMessage());
    Session::recordAttempt($ip, '__oidc_ip__', false);
    AuditLog::appendSafe($pdo, 'anonimo@oidc', 'LOGIN_OIDC_ERROR', "Fallo criptográfico OIDC/JWKS ({$e->getErrorCode()}): {$e->getMessage()} | IP: {$ip}", 'error');
    redirectLoginWithMsg('oidc_error');
} catch (\Throwable $e) {
    error_log('[FCCO OIDC Callback Fatal] ' . $e->getMessage());
    redirectLoginWithMsg('oidc_error');
}

$email = $claims['email'];
$googleSub = $claims['sub'];

// 5. Validar lista blanca inmutable estricta de exactamente 2 correos de peritos
try {
    $isWhitelisted = GoogleOidc::isEmailWhitelisted($email, $config['security']['allowed_emails'] ?? null);
} catch (GoogleOidcException $e) {
    error_log('[FCCO Whitelist Config Error] ' . $e->getMessage());
    AuditLog::appendSafe($pdo, $email, 'LOGIN_OIDC_ERROR', "Lista blanca de 2 correos mal configurada en servidor: {$e->getMessage()} | IP: {$ip}", 'error');
    Session::logout();
    redirectLoginWithMsg('config_whitelist_invalida');
}

if (!$isWhitelisted) {
    Session::recordAttempt($ip, $email, false);
    $maskedSub = Session::maskGoogleSub($googleSub) ?? 'N/A';
    AuditLog::appendSafe(
        $pdo,
        $email,
        'LOGIN_CORREO_NO_AUTORIZADO',
        "Acceso denegado: correo Google '{$email}' (sub={$maskedSub}) no figura en la lista blanca inmutable de 2 peritos. IP: {$ip}",
        'error'
    );
    Session::logout();
    redirectLoginWithMsg('correo_no_autorizado');
}

// 6. Rate-limit específico para la cuenta autorizada
if (Session::isRateLimited($ip, $email)) {
    AuditLog::appendSafe($pdo, $email, 'MFA_TOTP_FALLIDO', "Cuenta bloqueada temporalmente por rate-limit (5 intentos / 15 min) al iniciar OIDC. IP: {$ip}", 'warning');
    Session::logout();
    redirectLoginWithMsg('rate_limited');
}

// 7. Verificar existencia y estado activo en MySQL + binding permanente del claim inmutable `google_sub`
$stmt = $pdo->prepare('SELECT * FROM usuarios WHERE email = :email LIMIT 1');
$stmt->execute(['email' => $email]);
$userRow = $stmt->fetch();

if (!$userRow || !(bool)$userRow['activo']) {
    Session::recordAttempt($ip, $email, false);
    AuditLog::appendSafe(
        $pdo,
        $email,
        'LOGIN_CORREO_NO_AUTORIZADO',
        "Acceso denegado: correo en lista blanca '{$email}' no existe o se encuentra inactivo en MySQL. IP: {$ip}",
        'error'
    );
    Session::logout();
    redirectLoginWithMsg('usuario_no_autorizado');
}

$storedSub = trim((string)($userRow['google_sub'] ?? ''));

if ($storedSub === '') {
    // Primer ingreso Google OIDC del perito: fijar binding permanente e inmutable de google_sub
    $pdo->beginTransaction();
    try {
        $stmtBind = $pdo->prepare('
            UPDATE usuarios
            SET google_sub = :sub
            WHERE id = :id AND (google_sub IS NULL OR google_sub = "")
        ');
        $stmtBind->execute([
            'sub' => $googleSub,
            'id'  => $userRow['id'],
        ]);

        // Releer para confirmar que ningún otro proceso vinculó un sub distinto en paralelo
        $stmtCheck = $pdo->prepare('SELECT google_sub FROM usuarios WHERE id = :id LIMIT 1');
        $stmtCheck->execute(['id' => $userRow['id']]);
        $boundRow = $stmtCheck->fetch();
        $boundSub = trim((string)($boundRow['google_sub'] ?? ''));

        if ($boundSub === '' || !hash_equals($boundSub, $googleSub)) {
            $pdo->rollBack();
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'LOGIN_GOOGLE_SUB_MISMATCH',
                "VIOLACIÓN DE INTEGRIDAD DE IDENTIDAD: colisión o mismatch al vincular google_sub para {$email}. IP: {$ip}",
                'error'
            );
            Session::logout();
            redirectLoginWithMsg('google_sub_mismatch');
        }

        $maskedSub = Session::maskGoogleSub($googleSub) ?? 'N/A';
        AuditLog::append(
            $pdo,
            $email,
            'GOOGLE_SUB_VINCULADO',
            "Binding permanente establecido del claim inmutable google_sub ({$maskedSub}) para {$email}. IP: {$ip}",
            'info'
        );
        $pdo->commit();
        $userRow['google_sub'] = $googleSub;
    } catch (\Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[FCCO GoogleSub Bind Error] ' . $e->getMessage());
        AuditLog::appendSafe(
            $pdo,
            $email,
            'LOGIN_GOOGLE_SUB_MISMATCH',
            "Error al vincular google_sub único para {$email} (posible duplicación de sub). IP: {$ip}",
            'error'
        );
        Session::logout();
        redirectLoginWithMsg('google_sub_mismatch');
    }
} elseif (!hash_equals($storedSub, $googleSub)) {
    // Mismatch crítico del claim inmutable google_sub
    Session::recordAttempt($ip, $email, false);
    $maskedExpected = Session::maskGoogleSub($storedSub) ?? 'N/A';
    $maskedReceived = Session::maskGoogleSub($googleSub) ?? 'N/A';
    AuditLog::appendSafe(
        $pdo,
        $email,
        'LOGIN_GOOGLE_SUB_MISMATCH',
        "VIOLACIÓN DE IDENTIDAD: mismatch del claim inmutable google_sub para {$email} (esperado={$maskedExpected}, recibido={$maskedReceived}). IP: {$ip}",
        'error'
    );
    Session::logout();
    redirectLoginWithMsg('google_sub_mismatch');
}

// 8. Google OIDC validado -> Crear ÚNICAMENTE $_SESSION['pending_mfa'] (TTL 5 min) SIN acceso a gatekeeper ni /api/*
$pending = Session::setPendingMfa($userRow, $googleSub, $ip);
$nextStep = $pending['totp_enrolled'] ? 'mfa' : 'enroll';

header('Location: /?step=' . $nextStep, true, 302);
exit;
