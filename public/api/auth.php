<?php
/**
 * SHA256.US — API Endpoint: Inicio de Sesión Seguro por Código de 6 Dígitos y Enlace Mágico por Correo
 *
 * - GET  /api/auth.php: Estado autoritativo de sesión (200 solo si autenticado; 401 en caso contrario).
 * - POST /api/auth.php (requiere X-CSRF-Token en todas las acciones):
 *     * action=request_otp       -> Valida correo en lista blanca de 2 peritos, genera OTP 6 dígitos +
 *                                   Enlace Mágico (TTL 5 min, hashes SHA-256 en BD) y lo envía por correo.
 *     * action=verify_otp        -> Valida código de 6 dígitos (uso único, máx 5 intentos) y abre sesión.
 *     * action=verify_magic_link -> Valida token de enlace mágico de 1 clic (uso único) y abre sesión.
 *     * action=send_test_email   -> (Autenticado) Envía correo de verificación de entrega desde /seguridad.
 *     * action=login             -> BLOQUEADO (HTTP 403, password_login_enabled = false).
 *     * action=logout            -> Cierra sesión y audita en cadena SHA-256.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/email_otp.php';
require_once __DIR__ . '/lib/mailer.php';
require_once __DIR__ . '/lib/audit.php';

use Sha256\Audit\AuditLog;
use Sha256\Auth\EmailOtp;
use Sha256\Auth\EmailOtpException;
use Sha256\Auth\Session;
use Sha256\Db\Database;
use Sha256\Mail\Mailer;

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$config = Session::getConfig();
$ip = Session::getClientIp();
$mailCfg = $config['mail'] ?? [];
$mailDriver = Mailer::resolveDriver($mailCfg);

// ============================================================================
// GET: Estado autoritativo de sesión y token CSRF
// ============================================================================
if ($method === 'GET') {
    $user = Session::getUser();
    $csrf = Session::getCsrfToken();

    if ($user === null) {
        http_response_code(401);
        echo json_encode([
            'ok'                     => false,
            'authenticated'          => false,
            'user'                   => null,
            'csrf_token'             => $csrf,
            'auth_method'            => 'email_otp',
            'password_login_enabled' => false,
            'error'                  => 'Sesión no autorizada o expirada. Debe iniciar sesión.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    try {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $user['id']]);
        $row = $stmt->fetch();

        if (!$row || !(bool)$row['activo']) {
            Session::logout();
            http_response_code(401);
            echo json_encode([
                'ok'                     => false,
                'authenticated'          => false,
                'user'                   => null,
                'csrf_token'             => Session::getCsrfToken(),
                'password_login_enabled' => false,
                'error'                  => 'Cuenta desactivada o sesión revocada.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $clean = Session::sanitizeUserRow($row);
        $clean['auth_method'] = (string)($_SESSION['auth_method'] ?? 'email_otp');
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
        'auth_method'            => (string)($_SESSION['auth_method'] ?? 'email_otp'),
        'mail_driver'            => $mailDriver,
        'password_login_enabled' => false,
        'user'                   => $user,
        'csrf_token'             => $csrf,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ============================================================================
// POST: Solicitud OTP, Verificación OTP / Enlace Mágico, Correo Prueba, Logout
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

    // 1. Bloqueo permanente de inicio de sesión con contraseña local
    if ($action === 'login') {
        $attemptedEmail = strtolower(trim((string)($input['email'] ?? 'anonimo@local')));
        AuditLog::appendSafe(
            $pdo,
            $attemptedEmail !== '' ? $attemptedEmail : 'anonimo@local',
            'LOGIN_PASSWORD_BLOQUEADO',
            "Intento bloqueado de login con contraseña local (password_login_enabled=false). IP: {$ip}",
            'warning'
        );
        http_response_code(403);
        echo json_encode([
            'ok'                     => false,
            'password_login_enabled' => false,
            'error'                  => 'El inicio de sesión con contraseña local está deshabilitado. Solicite un código de 6 dígitos a su correo autorizado.',
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

    // 3. Solicitar Código OTP de 6 Dígitos + Enlace Mágico al Correo Autorizado
    if ($action === 'request_otp') {
        $email = strtolower(trim((string)($input['email'] ?? '')));
        if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            http_response_code(400);
            echo json_encode([
                'ok'    => false,
                'error' => 'Ingrese un correo electrónico válido.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if (Session::isRateLimited($ip, $email)) {
            AuditLog::appendSafe(
                $pdo,
                $email,
                'OTP_VERIFICACION_FALLIDA',
                "Solicitud OTP bloqueada por rate-limit (5 intentos / 15 min). IP: {$ip}",
                'warning'
            );
            http_response_code(429);
            echo json_encode([
                'ok'    => false,
                'error' => 'Demasiados intentos fallidos. Por seguridad pericial, espere 15 minutos.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Verificar lista blanca estricta de exactamente 2 peritos
        try {
            $whitelisted = EmailOtp::isEmailWhitelisted($email, $config['security']['allowed_emails'] ?? null);
        } catch (EmailOtpException $e) {
            error_log('[FCCO Whitelist Config Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode([
                'ok'    => false,
                'error' => 'Configuración de lista blanca de peritos incompleta en el servidor.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if (!$whitelisted) {
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'LOGIN_CORREO_NO_AUTORIZADO',
                "Solicitud OTP rechazada: el correo '{$email}' no pertenece a la lista blanca inmutable de 2 peritos. IP: {$ip}",
                'error'
            );
            http_response_code(403);
            echo json_encode([
                'ok'    => false,
                'error' => 'Acceso denegado: este correo no está autorizado en la lista blanca de SHA256.US. El intento ha sido auditado.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        $row = $stmt->fetch();

        if (!$row || !(bool)$row['activo']) {
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'LOGIN_CORREO_NO_AUTORIZADO',
                "Solicitud OTP rechazada: usuario '{$email}' inexistente o inactivo en MySQL. IP: {$ip}",
                'error'
            );
            http_response_code(403);
            echo json_encode([
                'ok'    => false,
                'error' => 'Usuario no encontrado o desactivado en la base de datos.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        try {
            $challenge = EmailOtp::createChallenge(
                $pdo,
                (string)$row['id'],
                $email,
                $ip,
                $config['security'] ?? []
            );
        } catch (EmailOtpException $e) {
            $statusCode = ($e->getErrorCode() === 'OTP_COOLDOWN' || $e->getErrorCode() === 'OTP_QUOTA_EXCEEDED') ? 429 : 400;
            http_response_code($statusCode);
            echo json_encode([
                'ok'          => false,
                'error'       => $e->getMessage(),
                'retry_after' => $e->getRetryAfterSeconds(),
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Construir URL del Enlace Mágico (usa ?magic=... que luego hace POST con CSRF para evitar consumo por escáneres de correo)
        $appUrl = rtrim((string)($mailCfg['app_url'] ?? ''), '/');
        if ($appUrl === '') {
            $host = (string)($_SERVER['HTTP_HOST'] ?? 'sha256.us');
            $scheme = Session::isHttpsRequest() ? 'https' : 'http';
            $appUrl = "{$scheme}://{$host}";
        }
        $magicUrl = $appUrl . '/?magic=' . rawurlencode($challenge['magic_token']);
        $nombre = trim(((string)($row['nombre'] ?? '')) . ' ' . ((string)($row['apellido'] ?? '')));

        $sent = Mailer::sendLoginOtp(
            $mailCfg,
            $email,
            $nombre,
            $challenge['otp_code'],
            $magicUrl,
            $challenge['ttl_seconds'],
            $ip
        );

        if (!$sent) {
            error_log("[FCCO Mailer Error] No se pudo enviar correo OTP a {$email} usando driver={$mailDriver}");
            http_response_code(502);
            echo json_encode([
                'ok'    => false,
                'error' => 'El servidor no pudo enviar el correo de acceso. Verifique la configuración de correo/SMTP en cPanel.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        AuditLog::appendSafe(
            $pdo,
            $email,
            'OTP_SOLICITADO',
            "Código OTP de 6 dígitos y enlace mágico enviados a {$email} vía {$mailDriver} (TTL {$challenge['ttl_seconds']}s). IP: {$ip}",
            'info'
        );

        echo json_encode([
            'ok'          => true,
            'email'       => $email,
            'expires_in'  => $challenge['ttl_seconds'],
            'cooldown'    => (int)($config['security']['otp_resend_cooldown'] ?? 45),
            'message'     => "Enviamos un código de 6 dígitos y un enlace de 1 clic a {$email}. Revise su bandeja de entrada o carpeta Spam.",
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 4. Verificar Código OTP de 6 Dígitos
    if ($action === 'verify_otp') {
        $email = strtolower(trim((string)($input['email'] ?? '')));
        $code = trim((string)($input['code'] ?? ''));

        if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Correo electrónico inválido.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if (Session::isRateLimited($ip, $email)) {
            AuditLog::appendSafe(
                $pdo,
                $email,
                'OTP_VERIFICACION_FALLIDA',
                "Verificación OTP bloqueada por rate-limit (5 intentos / 15 min). IP: {$ip}",
                'warning'
            );
            http_response_code(429);
            echo json_encode([
                'ok'    => false,
                'error' => 'Demasiados intentos fallidos. Por seguridad pericial, espere 15 minutos.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        try {
            $whitelisted = EmailOtp::isEmailWhitelisted($email, $config['security']['allowed_emails'] ?? null);
        } catch (EmailOtpException) {
            $whitelisted = false;
        }

        if (!$whitelisted) {
            Session::recordAttempt($ip, $email, false);
            AuditLog::appendSafe(
                $pdo,
                $email,
                'LOGIN_CORREO_NO_AUTORIZADO',
                "Intento de verificación OTP para correo fuera de lista blanca '{$email}'. IP: {$ip}",
                'error'
            );
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'Correo no autorizado en la lista blanca.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $verif = EmailOtp::verifyOtp($pdo, $email, $code);
        if (!$verif['ok']) {
            Session::recordAttempt($ip, $email, false);
            $reason = (string)($verif['reason'] ?? 'UNKNOWN');
            AuditLog::appendSafe(
                $pdo,
                $email,
                'OTP_VERIFICACION_FALLIDA',
                "Fallo al verificar código OTP de 6 dígitos para {$email} (motivo={$reason}). IP: {$ip}",
                'warning'
            );

            $errorMap = [
                'EXPIRED'               => 'El código expiró (5 minutos). Solicite un código nuevo.',
                'MAX_ATTEMPTS_EXCEEDED' => 'El código quedó invalidado tras 5 intentos fallidos. Solicite uno nuevo.',
                'NO_ACTIVE_CHALLENGE'   => 'No existe un código activo para este correo. Solicite un código primero.',
                'ALREADY_USED'          => 'Este código ya fue utilizado. Solicite un código nuevo.',
                'INVALID_FORMAT'        => 'Ingrese exactamente los 6 dígitos numéricos enviados a su correo.',
            ];
            http_response_code(401);
            echo json_encode([
                'ok'     => false,
                'reason' => $reason,
                'error'  => $errorMap[$reason] ?? 'Código de 6 dígitos incorrecto. Verifique su correo e intente nuevamente.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id AND activo = 1 LIMIT 1');
        $stmt->execute(['id' => $verif['usuario_id']]);
        $row = $stmt->fetch();

        if (!$row) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'Cuenta de perito inactiva o inexistente.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $nowDb = gmdate('Y-m-d H:i:s');
        $pdo->beginTransaction();
        try {
            $stmtUp = $pdo->prepare('UPDATE usuarios SET last_login_at = :login_at, last_login_ip = :login_ip WHERE id = :id');
            $stmtUp->execute(['login_at' => $nowDb, 'login_ip' => $ip, 'id' => $row['id']]);

            AuditLog::append(
                $pdo,
                $email,
                'LOGIN_AUTORIZADO',
                "Inicio de sesión autorizado vía Código OTP de 6 dígitos por correo para {$email}. IP: {$ip}",
                'success'
            );
            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('[FCCO OTP Verify Commit Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Error interno al registrar el acceso.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        Session::recordAttempt($ip, $email, true);
        $row['last_login_at'] = $nowDb;
        $row['last_login_ip'] = $ip;
        $cleanUser = Session::createAuthenticatedSession($row, 'email_otp');

        echo json_encode([
            'ok'            => true,
            'authenticated' => true,
            'auth_method'   => 'email_otp',
            'user'          => $cleanUser,
            'csrf_token'    => Session::getCsrfToken(),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 5. Verificar Enlace Mágico de 1 Clic (POST con X-CSRF-Token para evitar pre-escaneo de correo)
    if ($action === 'verify_magic_link') {
        $token = trim((string)($input['token'] ?? ''));

        if (Session::isRateLimited($ip, '__magic_ip__')) {
            AuditLog::appendSafe(
                $pdo,
                'anonimo@magic',
                'OTP_VERIFICACION_FALLIDA',
                "Enlace mágico bloqueado por rate-limit para IP {$ip}",
                'warning'
            );
            http_response_code(429);
            echo json_encode([
                'ok'    => false,
                'error' => 'Demasiados intentos fallidos. Espere 15 minutos antes de reintentar.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $verif = EmailOtp::verifyMagicToken($pdo, $token);
        if (!$verif['ok']) {
            Session::recordAttempt($ip, '__magic_ip__', false);
            $reason = (string)($verif['reason'] ?? 'UNKNOWN');
            AuditLog::appendSafe(
                $pdo,
                'anonimo@magic',
                'OTP_VERIFICACION_FALLIDA',
                "Fallo al verificar enlace mágico (motivo={$reason}). IP: {$ip}",
                'warning'
            );

            $errorMap = [
                'EXPIRED'      => 'El enlace mágico expiró (5 minutos). Solicite un nuevo código de acceso.',
                'ALREADY_USED' => 'Este enlace mágico ya fue utilizado. Solicite uno nuevo si desea ingresar.',
            ];
            http_response_code(401);
            echo json_encode([
                'ok'     => false,
                'reason' => $reason,
                'error'  => $errorMap[$reason] ?? 'Enlace mágico inválido o expirado. Solicite un nuevo código.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $email = (string)$verif['email'];
        try {
            $whitelisted = EmailOtp::isEmailWhitelisted($email, $config['security']['allowed_emails'] ?? null);
        } catch (EmailOtpException) {
            $whitelisted = false;
        }

        if (!$whitelisted) {
            AuditLog::appendSafe(
                $pdo,
                $email,
                'LOGIN_CORREO_NO_AUTORIZADO',
                "Enlace mágico rechazado: correo '{$email}' fuera de lista blanca actual. IP: {$ip}",
                'error'
            );
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'Cuenta no autorizada en la lista blanca actual.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id AND activo = 1 LIMIT 1');
        $stmt->execute(['id' => $verif['usuario_id']]);
        $row = $stmt->fetch();

        if (!$row) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'Cuenta de perito inactiva o inexistente.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $nowDb = gmdate('Y-m-d H:i:s');
        $pdo->beginTransaction();
        try {
            $stmtUp = $pdo->prepare('UPDATE usuarios SET last_login_at = :login_at, last_login_ip = :login_ip WHERE id = :id');
            $stmtUp->execute(['login_at' => $nowDb, 'login_ip' => $ip, 'id' => $row['id']]);

            AuditLog::append(
                $pdo,
                $email,
                'LOGIN_AUTORIZADO',
                "Inicio de sesión autorizado vía Enlace Mágico de 1 clic por correo para {$email}. IP: {$ip}",
                'success'
            );
            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('[FCCO MagicLink Verify Commit Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Error interno al completar el inicio de sesión.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        Session::recordAttempt($ip, $email, true);
        $row['last_login_at'] = $nowDb;
        $row['last_login_ip'] = $ip;
        $cleanUser = Session::createAuthenticatedSession($row, 'magic_link');

        echo json_encode([
            'ok'            => true,
            'authenticated' => true,
            'auth_method'   => 'magic_link',
            'user'          => $cleanUser,
            'csrf_token'    => Session::getCsrfToken(),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 6. Enviar Correo de Prueba de Entrega (desde /seguridad, requiere sesión activa)
    if ($action === 'send_test_email') {
        $authUser = Session::requireUser();
        $email = (string)$authUser['email'];
        $nombre = trim(((string)($authUser['nombre'] ?? '')) . ' ' . ((string)($authUser['apellido'] ?? '')));

        $sent = Mailer::sendTestEmail($mailCfg, $email, $nombre, $ip);
        if (!$sent) {
            http_response_code(502);
            echo json_encode([
                'ok'    => false,
                'error' => "No se pudo enviar el correo de prueba a {$email} vía {$mailDriver}. Revise configuración de correo en cPanel.",
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        echo json_encode([
            'ok'          => true,
            'mail_driver' => $mailDriver,
            'message'     => "Correo de prueba enviado a {$email} mediante {$mailDriver}.",
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => "Acción desconocida: {$action}"], JSON_UNESCAPED_UNICODE);
    exit;
}

http_response_code(405);
echo json_encode(['ok' => false, 'error' => 'Método no permitido'], JSON_UNESCAPED_UNICODE);
