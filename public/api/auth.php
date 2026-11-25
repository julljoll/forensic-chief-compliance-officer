<?php
/**
 * SHA256.US — API Endpoint: Autenticación Forense (Google OIDC + Google Authenticator TOTP Obligatorio)
 *
 * - GET  /api/auth.php: Devuelve estado autoritativo de sesión (200 solo si Google OIDC + TOTP verificado;
 *                       401 en cualquier otro caso, incluyendo estado intermedio `pending_mfa`).
 * - POST /api/auth.php (requiere X-CSRF-Token en todas las acciones mutantes):
 *     * action=login                   -> BLOQUEADO (HTTP 403, password_login_enabled = false)
 *     * action=verify_mfa              -> Verifica código TOTP (6 dígitos, anti-replay totp_last_step)
 *                                         o código de recuperación (bcrypt un solo uso) desde `pending_mfa`.
 *     * action=enroll_mfa_start        -> Genera secreto CSPRNG 160-bit en sesión y URI otpauth para QR 100 % local.
 *     * action=enroll_mfa_confirm      -> Valida 1.er código TOTP, cifra secreto con AES-256-GCM en reposo,
 *                                         genera 8 códigos de respaldo (bcrypt) y promueve la sesión.
 *     * action=regenerate_recovery_codes -> Requiere sesión activa + código TOTP vigente; rota los 8 códigos bcrypt.
 *     * action=cancel_pending_mfa      -> Cancela el estado intermedio `pending_mfa`.
 *     * action=logout                  -> Cierra sesión y audita el cierre.
 *
 * Cumplimiento: NIST SP 800-63B (AAL2/FAL2) · RFC 6238 · NIST SP 800-38D (AES-256-GCM) · OWASP ASVS v4.0.3
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/totp.php';
require_once __DIR__ . '/lib/audit.php';

use Sha256\Audit\AuditLog;
use Sha256\Auth\Session;
use Sha256\Auth\Totp;
use Sha256\Db\Database;

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$config = Session::getConfig();
$ip = Session::getClientIp();

// ============================================================================
// GET: Estado autoritativo de sesión y token CSRF
// ============================================================================
if ($method === 'GET') {
    $user = Session::getUser();
    $csrf = Session::getCsrfToken();

    if ($user === null) {
        $pending = Session::getPendingMfa();
        http_response_code(401);
        $payload = [
            'ok'                     => false,
            'authenticated'          => false,
            'user'                   => null,
            'csrf_token'             => $csrf,
            'password_login_enabled' => false,
            'pending_mfa'            => $pending !== null,
            'mfa_step'               => $pending !== null ? ($pending['totp_enrolled'] ? 'verify' : 'enroll') : null,
            'pending_email'          => $pending['email'] ?? null,
            'pending_nombre'         => $pending['nombre'] ?? null,
            'pending_expires_in'     => $pending !== null ? max(0, (int)$pending['expires_at'] - time()) : 0,
            'error'                  => 'Sesión no autorizada o expirada. Debe iniciar sesión.',
        ];
        echo json_encode($payload, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Refrescar estado autoritativo desde MySQL (verificar usuario aún activo y con TOTP + google_sub)
    try {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $user['id']]);
        $row = $stmt->fetch();

        if (!$row || !(bool)$row['activo'] || empty($row['google_sub']) || !(bool)$row['totp_enabled'] || !Totp::isEncryptedSecret($row['totp_secret'] ?? null)) {
            Session::logout();
            http_response_code(401);
            echo json_encode([
                'ok'                     => false,
                'authenticated'          => false,
                'user'                   => null,
                'csrf_token'             => Session::getCsrfToken(),
                'password_login_enabled' => false,
                'pending_mfa'            => false,
                'error'                  => 'Sesión revocada o configuración MFA incompleta. Inicie sesión nuevamente.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $clean = Session::sanitizeUserRow($row);
        $_SESSION['usuario'] = $clean;
        $user = $clean;
    } catch (\Throwable $e) {
        error_log('[FCCO Auth GET Refresh Error] ' . $e->getMessage());
        http_response_code(503);
        echo json_encode([
            'ok'            => false,
            'authenticated' => false,
            'user'          => null,
            'error'         => 'No se pudo verificar la sesión contra la base de datos.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    echo json_encode([
        'ok'                     => true,
        'authenticated'          => true,
        'auth_method'            => 'google_oidc_totp',
        'password_login_enabled' => false,
        'pending_mfa'            => false,
        'user'                   => $user,
        'csrf_token'             => $csrf,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ============================================================================
// POST: Acciones de autenticación MFA, enrolamiento, regeneración y cierre
// ============================================================================
if ($method === 'POST') {
    Session::requireCsrf();

    $raw = (string)file_get_contents('php://input');
    $input = json_decode($raw, true);
    if (!is_array($input)) {
        $input = [];
    }
    $action = (string)($input['action'] ?? '');
    $pdo = Database::getConnection();

    // 1. Bloqueo absoluto de inicio de sesión por contraseña local (password_login_enabled = false)
    if ($action === 'login') {
        $attemptedEmail = strtolower(trim((string)($input['email'] ?? 'anonimo@local')));
        AuditLog::appendSafe(
            $pdo,
            $attemptedEmail !== '' ? $attemptedEmail : 'anonimo@local',
            'LOGIN_PASSWORD_BLOQUEADO',
            "Intento bloqueado de login por contraseña local (password_login_enabled=false). IP: {$ip}",
            'warning'
        );
        http_response_code(403);
        echo json_encode([
            'ok'                     => false,
            'password_login_enabled' => false,
            'error'                  => 'El inicio de sesión con contraseña local está deshabilitado. Utilice su Cuenta Google autorizada y Google Authenticator.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 2. Cerrar Sesión
    if ($action === 'logout') {
        $currentUser = Session::getUser();
        if ($currentUser && !empty($currentUser['email'])) {
            AuditLog::appendSafe(
                $pdo,
                (string)$currentUser['email'],
                'LOGOUT_PERITO',
                "Cierre explícito de sesión pericial desde IP {$ip}",
                'info'
            );
        }
        Session::logout();
        echo json_encode([
            'ok'      => true,
            'success' => true,
            'message' => 'Sesión cerrada exitosamente.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 3. Cancelar estado intermedio pending_mfa
    if ($action === 'cancel_pending_mfa') {
        Session::clearPendingMfa();
        echo json_encode([
            'ok'      => true,
            'message' => 'Verificación MFA cancelada.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 4. Verificar 2.º Factor Obligatorio (TOTP 6 dígitos o Código de Recuperación) desde pending_mfa
    if ($action === 'verify_mfa') {
        $pending = Session::getPendingMfa();
        if ($pending === null) {
            http_response_code(401);
            echo json_encode([
                'ok'                  => false,
                'pending_mfa_expired' => true,
                'error'               => 'La ventana de verificación MFA (5 min) expiró. Inicie sesión nuevamente con Google.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $email = (string)$pending['email'];

        if (Session::isRateLimited($ip, $email)) {
            AuditLog::appendSafe(
                $pdo,
                $email,
                'MFA_TOTP_FALLIDO',
                "Verificación MFA rechazada por rate-limit (5 intentos / 15 min). IP: {$ip}",
                'warning'
            );
            http_response_code(429);
            echo json_encode([
                'ok'    => false,
                'error' => 'Demasiados intentos fallidos. Por seguridad pericial, espere 15 minutos.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $useRecovery = (bool)($input['use_recovery'] ?? false);
        $code = trim((string)($input['code'] ?? $input['totp_code'] ?? $input['recovery_code'] ?? ''));

        if ($code === '') {
            http_response_code(400);
            echo json_encode([
                'ok'    => false,
                'error' => $useRecovery
                    ? 'Ingrese uno de sus códigos de recuperación de emergencia.'
                    : 'Ingrese el código de 6 dígitos de Google Authenticator.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $pending['user_id']]);
        $row = $stmt->fetch();

        if (
            !$row ||
            !(bool)$row['activo'] ||
            empty($row['google_sub']) ||
            !hash_equals((string)$row['google_sub'], (string)$pending['google_sub'])
        ) {
            Session::clearPendingMfa();
            AuditLog::appendSafe(
                $pdo,
                $email,
                'LOGIN_GOOGLE_SUB_MISMATCH',
                "Inconsistencia de usuario o google_sub durante verificación MFA. IP: {$ip}",
                'error'
            );
            http_response_code(401);
            echo json_encode([
                'ok'    => false,
                'error' => 'Identidad inconsistente. Inicie sesión nuevamente con Google.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if (!(bool)$row['totp_enabled'] || !Totp::isEncryptedSecret($row['totp_secret'] ?? null)) {
            http_response_code(409);
            echo json_encode([
                'ok'           => false,
                'needs_enroll' => true,
                'error'        => 'Debe completar primero el enrolamiento de Google Authenticator.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Rama A: Código de Recuperación de Emergencia (bcrypt, un solo uso)
        if ($useRecovery) {
            $hashes = json_decode((string)($row['totp_recovery_hashes'] ?? '[]'), true);
            if (!is_array($hashes)) {
                $hashes = [];
            }

            $matchedIdx = Totp::verifyRecoveryCode($code, $hashes);
            if ($matchedIdx === null) {
                Session::recordAttempt($ip, $email, false);
                AuditLog::appendSafe(
                    $pdo,
                    $email,
                    'MFA_TOTP_FALLIDO',
                    "Código de recuperación de emergencia inválido o ya utilizado. IP: {$ip}",
                    'warning'
                );
                http_response_code(401);
                echo json_encode([
                    'ok'    => false,
                    'error' => 'Código de recuperación inválido o ya consumido.',
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }

            // Consumir código usado permanentemente en transacción atómica
            unset($hashes[$matchedIdx]);
            $remainingHashes = array_values($hashes);
            $remainingCount = count($remainingHashes);
            $nowDb = gmdate('Y-m-d H:i:s');

            $pdo->beginTransaction();
            try {
                $stmtUp = $pdo->prepare('
                    UPDATE usuarios
                    SET totp_recovery_hashes = :hashes,
                        last_login_at = :login_at,
                        last_login_ip = :login_ip
                    WHERE id = :id
                ');
                $stmtUp->execute([
                    'hashes'   => json_encode($remainingHashes),
                    'login_at' => $nowDb,
                    'login_ip' => $ip,
                    'id'       => $row['id'],
                ]);

                AuditLog::append(
                    $pdo,
                    $email,
                    'MFA_RECOVERY_CODE_USADO',
                    "Código de respaldo de un solo uso consumido por {$email} (restantes: {$remainingCount}/8). IP: {$ip}",
                    'warning'
                );
                AuditLog::append(
                    $pdo,
                    $email,
                    'LOGIN_AUTORIZADO',
                    "Inicio de sesión autorizado vía Google OIDC + Código de Recuperación para {$email}. IP: {$ip}",
                    'success'
                );

                $pdo->commit();
            } catch (\Throwable $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                error_log('[FCCO Recovery Verify Error] ' . $e->getMessage());
                http_response_code(500);
                echo json_encode(['ok' => false, 'error' => 'Error interno al procesar el código de recuperación.'], JSON_UNESCAPED_UNICODE);
                exit;
            }

            Session::recordAttempt($ip, $email, true);
            $row['totp_recovery_hashes'] = json_encode($remainingHashes);
            $row['last_login_at'] = $nowDb;
            $row['last_login_ip'] = $ip;
            $cleanUser = Session::promotePendingToAuthenticated($row);

            echo json_encode([
                'ok'                       => true,
                'authenticated'            => true,
                'used_recovery_code'       => true,
                'recovery_codes_remaining' => $remainingCount,
                'user'                     => $cleanUser,
                'csrf_token'               => Session::getCsrfToken(),
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Rama B: Código TOTP de 6 dígitos (Google Authenticator RFC 6238 + AES-256-GCM + anti-replay totp_last_step)
        $encKey = (string)($config['security']['totp_encryption_key'] ?? '');
        try {
            $plaintextSecret = Totp::decryptSecret((string)$row['totp_secret'], $encKey);
        } catch (\Throwable $e) {
            error_log('[FCCO TOTP Decrypt Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode([
                'ok'    => false,
                'error' => 'Error de configuración criptográfica AES-256-GCM (totp_encryption_key). Contacte al administrador.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $matchedStep = Totp::verifyAndGetSlice($plaintextSecret, $code, 1);
        $lastStep = isset($row['totp_last_step']) && $row['totp_last_step'] !== null ? (int)$row['totp_last_step'] : null;

        if ($matchedStep === null) {
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'MFA_TOTP_FALLIDO',
                "Código Google Authenticator inválido o desfasado para {$email}. IP: {$ip}",
                'warning'
            );
            http_response_code(401);
            echo json_encode([
                'ok'    => false,
                'error' => 'Código de Google Authenticator incorrecto o expirado.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if ($lastStep !== null && $matchedStep <= $lastStep) {
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'MFA_TOTP_FALLIDO',
                "Intento de replay TOTP bloqueado (step={$matchedStep} <= totp_last_step={$lastStep}) para {$email}. IP: {$ip}",
                'warning'
            );
            http_response_code(401);
            echo json_encode([
                'ok'    => false,
                'error' => 'Este código TOTP ya fue utilizado (protección anti-replay). Espere el siguiente código de 30 segundos.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $nowDb = gmdate('Y-m-d H:i:s');
        $pdo->beginTransaction();
        try {
            $stmtUp = $pdo->prepare('
                UPDATE usuarios
                SET totp_last_step = :step,
                    last_login_at = :login_at,
                    last_login_ip = :login_ip
                WHERE id = :id
            ');
            $stmtUp->execute([
                'step'     => $matchedStep,
                'login_at' => $nowDb,
                'login_ip' => $ip,
                'id'       => $row['id'],
            ]);

            AuditLog::append(
                $pdo,
                $email,
                'LOGIN_AUTORIZADO',
                "Inicio de sesión autorizado vía Google OIDC + Google Authenticator (TOTP step={$matchedStep}) para {$email}. IP: {$ip}",
                'success'
            );

            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('[FCCO TOTP Verify Commit Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Error interno al confirmar verificación MFA.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        Session::recordAttempt($ip, $email, true);
        $row['totp_last_step'] = $matchedStep;
        $row['last_login_at'] = $nowDb;
        $row['last_login_ip'] = $ip;
        $cleanUser = Session::promotePendingToAuthenticated($row);

        echo json_encode([
            'ok'            => true,
            'authenticated' => true,
            'user'          => $cleanUser,
            'csrf_token'    => Session::getCsrfToken(),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 5. Iniciar Enrolamiento MFA (permitido en primer ingreso pending_mfa SIN TOTP, o usuario autenticado en /seguridad)
    if ($action === 'enroll_mfa_start') {
        $authUser = Session::getUser();
        $pending = Session::getPendingMfa();

        $targetUserId = null;
        $targetEmail = null;
        $mode = null;

        if ($authUser !== null) {
            $targetUserId = (string)$authUser['id'];
            $targetEmail = (string)$authUser['email'];
            $mode = 're_enroll';
        } elseif ($pending !== null && !$pending['totp_enrolled']) {
            $targetUserId = (string)$pending['user_id'];
            $targetEmail = (string)$pending['email'];
            $mode = 'initial_enroll';
        } else {
            http_response_code(401);
            echo json_encode([
                'ok'    => false,
                'error' => 'No autorizado para iniciar enrolamiento MFA. Autentíquese con Google primero.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Verificar fail-closed que la clave maestra AES-256-GCM esté configurada antes de emitir secreto
        try {
            Totp::parseEncryptionKey((string)($config['security']['totp_encryption_key'] ?? ''));
        } catch (\Throwable $e) {
            error_log('[FCCO Enroll Key Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode([
                'ok'    => false,
                'error' => 'Clave criptográfica totp_encryption_key (AES-256-GCM) no configurada en config.local.php.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $secret = Totp::generateSecret(20);
        $uri = Totp::buildProvisioningUri($targetEmail, $secret, 'SHA256.US');

        $_SESSION['pending_totp_enroll'] = [
            'user_id'    => $targetUserId,
            'email'      => $targetEmail,
            'secret'     => $secret,
            'mode'       => $mode,
            'expires_at' => time() + 300,
        ];

        echo json_encode([
            'ok'     => true,
            'secret' => $secret,
            'uri'    => $uri,
            'email'  => $targetEmail,
            'mode'   => $mode,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 6. Confirmar Enrolamiento MFA: valida 1.er código, cifra AES-256-GCM y entrega única de 8 códigos bcrypt
    if ($action === 'enroll_mfa_confirm') {
        $enroll = $_SESSION['pending_totp_enroll'] ?? null;
        if (!is_array($enroll) || time() > (int)($enroll['expires_at'] ?? 0)) {
            unset($_SESSION['pending_totp_enroll']);
            http_response_code(400);
            echo json_encode([
                'ok'    => false,
                'error' => 'El proceso de enrolamiento TOTP expiró. Genere un nuevo código QR.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $authUser = Session::getUser();
        $pending = Session::getPendingMfa();
        $isInitialFromPending = ($enroll['mode'] === 'initial_enroll');

        if ($isInitialFromPending) {
            if ($pending === null || $pending['user_id'] !== $enroll['user_id']) {
                unset($_SESSION['pending_totp_enroll']);
                http_response_code(401);
                echo json_encode([
                    'ok'                  => false,
                    'pending_mfa_expired' => true,
                    'error'               => 'Sesión de enrolamiento expirada. Inicie sesión nuevamente con Google.',
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
        } else {
            if ($authUser === null || $authUser['id'] !== $enroll['user_id']) {
                unset($_SESSION['pending_totp_enroll']);
                http_response_code(401);
                echo json_encode([
                    'ok'    => false,
                    'error' => 'Sesión no autorizada para confirmar reconfiguración MFA.',
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
        }

        $email = (string)$enroll['email'];
        $userId = (string)$enroll['user_id'];

        if (Session::isRateLimited($ip, $email)) {
            http_response_code(429);
            echo json_encode([
                'ok'    => false,
                'error' => 'Demasiados intentos fallidos. Espere 15 minutos antes de reintentar.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $code = trim((string)($input['code'] ?? ''));
        $serverSecret = (string)$enroll['secret'];

        $matchedStep = Totp::verifyAndGetSlice($serverSecret, $code, 1);
        if ($matchedStep === null) {
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'MFA_TOTP_FALLIDO',
                "Código de confirmación inválido durante enrolamiento Google Authenticator para {$email}. IP: {$ip}",
                'warning'
            );
            http_response_code(400);
            echo json_encode([
                'ok'    => false,
                'error' => 'Código de 6 dígitos inválido o desfasado. Verifique la hora de su dispositivo e intente nuevamente.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Cifrar secreto en reposo con AES-256-GCM
        $encKey = (string)($config['security']['totp_encryption_key'] ?? '');
        try {
            $encryptedSecret = Totp::encryptSecret($serverSecret, $encKey);
        } catch (\Throwable $e) {
            error_log('[FCCO TOTP Encrypt Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode([
                'ok'    => false,
                'error' => 'Error al cifrar secreto TOTP con AES-256-GCM (verifique totp_encryption_key en config.local.php).',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Generar 8 códigos de respaldo (hashes bcrypt en BD; entrega plana única en esta respuesta)
        $recovery = Totp::generateRecoveryCodes(8);
        $nowDb = gmdate('Y-m-d H:i:s');

        $pdo->beginTransaction();
        try {
            $stmtUp = $pdo->prepare('
                UPDATE usuarios
                SET totp_secret = :secret,
                    totp_enabled = 1,
                    totp_enrolled_at = :enrolled_at,
                    totp_last_step = :step,
                    totp_recovery_hashes = :hashes,
                    last_login_at = :login_at,
                    last_login_ip = :login_ip
                WHERE id = :id
            ');
            $stmtUp->execute([
                'secret'      => $encryptedSecret,
                'enrolled_at' => $nowDb,
                'step'        => $matchedStep,
                'hashes'      => json_encode($recovery['hashes']),
                'login_at'    => $nowDb,
                'login_ip'    => $ip,
                'id'          => $userId,
            ]);

            $stmtReload = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id LIMIT 1');
            $stmtReload->execute(['id' => $userId]);
            $updatedRow = $stmtReload->fetch();

            AuditLog::append(
                $pdo,
                $email,
                'MFA_TOTP_ENROLADO',
                "Enrolamiento Google Authenticator (RFC 6238, AES-256-GCM en reposo) y emisión de 8 códigos de respaldo bcrypt para {$email}. IP: {$ip}",
                'success'
            );

            if ($isInitialFromPending) {
                AuditLog::append(
                    $pdo,
                    $email,
                    'LOGIN_AUTORIZADO',
                    "Primer inicio de sesión autorizado vía Google OIDC + Enrolamiento Google Authenticator para {$email}. IP: {$ip}",
                    'success'
                );
            }

            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('[FCCO Enroll Commit Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Error interno al persistir el enrolamiento MFA en MySQL.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        unset($_SESSION['pending_totp_enroll']);
        Session::recordAttempt($ip, $email, true);

        if ($isInitialFromPending && is_array($updatedRow)) {
            $cleanUser = Session::promotePendingToAuthenticated($updatedRow);
        } else {
            $cleanUser = is_array($updatedRow) ? Session::sanitizeUserRow($updatedRow) : $authUser;
            $_SESSION['usuario'] = $cleanUser;
        }

        echo json_encode([
            'ok'                       => true,
            'success'                  => true,
            'authenticated'            => true,
            'message'                  => 'Google Authenticator activado y cifrado con AES-256-GCM exitosamente.',
            'recovery_codes'           => $recovery['plain'],
            'recovery_codes_remaining' => count($recovery['plain']),
            'user'                     => $cleanUser,
            'csrf_token'               => Session::getCsrfToken(),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 7. Regenerar los 8 Códigos de Respaldo (requiere sesión activa + CSRF + código TOTP vigente)
    if ($action === 'regenerate_recovery_codes') {
        $authUser = Session::requireUser();
        $email = (string)$authUser['email'];

        if (Session::isRateLimited($ip, $email)) {
            http_response_code(429);
            echo json_encode([
                'ok'    => false,
                'error' => 'Demasiados intentos fallidos. Espere 15 minutos.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $code = trim((string)($input['code'] ?? ''));
        if ($code === '') {
            http_response_code(400);
            echo json_encode([
                'ok'    => false,
                'error' => 'Debe confirmar con su código actual de 6 dígitos de Google Authenticator para regenerar los códigos de respaldo.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $authUser['id']]);
        $row = $stmt->fetch();

        if (!$row || !(bool)$row['totp_enabled'] || !Totp::isEncryptedSecret($row['totp_secret'] ?? null)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Google Authenticator no está activo en su cuenta.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        try {
            $plaintextSecret = Totp::decryptSecret((string)$row['totp_secret'], (string)($config['security']['totp_encryption_key'] ?? ''));
        } catch (\Throwable $e) {
            error_log('[FCCO Regen Decrypt Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Error de clave AES-256-GCM en servidor.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $matchedStep = Totp::verifyAndGetSlice($plaintextSecret, $code, 1);
        $lastStep = isset($row['totp_last_step']) && $row['totp_last_step'] !== null ? (int)$row['totp_last_step'] : null;

        if ($matchedStep === null || ($lastStep !== null && $matchedStep <= $lastStep)) {
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'MFA_TOTP_FALLIDO',
                "Fallo o replay TOTP al solicitar regeneración de códigos de respaldo para {$email}. IP: {$ip}",
                'warning'
            );
            http_response_code(401);
            echo json_encode([
                'ok'    => false,
                'error' => 'Código de Google Authenticator inválido o ya utilizado. Espere al próximo ciclo de 30s.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $recovery = Totp::generateRecoveryCodes(8);

        $pdo->beginTransaction();
        try {
            $stmtUp = $pdo->prepare('
                UPDATE usuarios
                SET totp_last_step = :step,
                    totp_recovery_hashes = :hashes
                WHERE id = :id
            ');
            $stmtUp->execute([
                'step'   => $matchedStep,
                'hashes' => json_encode($recovery['hashes']),
                'id'     => $row['id'],
            ]);

            AuditLog::append(
                $pdo,
                $email,
                'MFA_RECOVERY_CODES_REGENERADOS',
                "Regeneración de 8 códigos de respaldo bcrypt (anteriores invalidados) para {$email}. IP: {$ip}",
                'info'
            );

            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('[FCCO Regen Commit Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Error interno al regenerar códigos de respaldo.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        Session::recordAttempt($ip, $email, true);
        $row['totp_recovery_hashes'] = json_encode($recovery['hashes']);
        $_SESSION['usuario'] = Session::sanitizeUserRow($row);

        echo json_encode([
            'ok'                       => true,
            'message'                  => 'Se han generado 8 nuevos códigos de respaldo. Los códigos anteriores quedaron invalidados.',
            'recovery_codes'           => $recovery['plain'],
            'recovery_codes_remaining' => 8,
            'user'                     => $_SESSION['usuario'],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => "Acción desconocida: {$action}"], JSON_UNESCAPED_UNICODE);
    exit;
}

http_response_code(405);
echo json_encode(['ok' => false, 'error' => 'Método no permitido'], JSON_UNESCAPED_UNICODE);
