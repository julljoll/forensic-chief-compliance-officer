<?php
/**
 * SHA256.US — Autenticación y Sesiones Forenses (Opción C — Grado Forense)
 *
 * - Solo Google OIDC (Authorization Code + PKCE S256 + RS256 JWKS) + Google Authenticator obligatorio (TOTP RFC 6238).
 * - Inicio de sesión por contraseña local deshabilitado permanentemente (`password_login_enabled = false`).
 * - Estado intermedio aislado `$_SESSION['pending_mfa']` (TTL 5 min) SIN acceso a `gatekeeper.php` ni `/api/*.php`.
 * - Cookie de sesión: `SameSite=Lax`, `HttpOnly`, `Secure`, expiración en servidor de 30 min inactividad y 8 h absolutas.
 * - Protección CSRF obligatoria vía `X-CSRF-Token` en todos los POST/PUT/DELETE.
 * - Rate-limit persistente en BD (5 intentos / 15 min) + anti-replay por `totp_last_step`.
 *
 * Cumplimiento: NIST SP 800-63B (AAL2/FAL2) · OWASP ASVS v4.0.3 · ISO/IEC 27001 A.9.4.2
 */

declare(strict_types=1);

namespace Sha256\Auth;

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/totp.php';

use Sha256\Db\Database;

class Session
{
    private static ?array $configOverride = null;

    /**
     * Inyección de configuración exclusiva para pruebas unitarias en PHP CLI.
     */
    public static function setConfigForTesting(?array $config): void
    {
        if (PHP_SAPI !== 'cli') {
            throw new \RuntimeException('setConfigForTesting solo está permitido en CLI');
        }
        self::$configOverride = $config;
    }

    public static function getConfig(): array
    {
        if (self::$configOverride !== null) {
            return self::$configOverride;
        }
        return require __DIR__ . '/../config.php';
    }

    public static function isPasswordLoginEnabled(): bool
    {
        $config = self::getConfig();
        return ($config['security']['password_login_enabled'] ?? false) === true;
    }

    public static function isHttpsRequest(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
            || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
    }

    public static function getClientIp(): string
    {
        return substr((string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), 0, 45);
    }

    public static function start(): void
    {
        $config = self::getConfig();

        // Exigir HTTPS en producción si require_https está activado
        if (PHP_SAPI !== 'cli' && !empty($config['security']['require_https']) && !self::isHttpsRequest()) {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok'    => false,
                'error' => 'Se requiere conexión cifrada HTTPS (TLS) para acceder a la bóveda pericial.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if (session_status() === PHP_SESSION_NONE) {
            if (PHP_SAPI === 'cli' && headers_sent()) {
                if (!isset($_SESSION) || !is_array($_SESSION)) {
                    $_SESSION = [];
                }
                return;
            }

            $sCfg = $config['session'];
            $absoluteTimeout = (int)($sCfg['absolute_timeout'] ?? $sCfg['lifetime'] ?? 28800);
            $sameSite = (string)($sCfg['samesite'] ?? 'Lax');
            if (!in_array($sameSite, ['Lax', 'Strict', 'None'], true)) {
                $sameSite = 'Lax';
            }

            if (PHP_SAPI !== 'cli' && !headers_sent()) {
                ini_set('session.use_strict_mode', '1');
                ini_set('session.use_only_cookies', '1');
                ini_set('session.cookie_httponly', '1');
                ini_set('session.gc_maxlifetime', (string)$absoluteTimeout);

                session_set_cookie_params([
                    'lifetime' => $absoluteTimeout,
                    'path'     => '/',
                    'domain'   => '',
                    'secure'   => (bool)($sCfg['secure'] ?? self::isHttpsRequest()),
                    'httponly' => true,
                    'samesite' => $sameSite,
                ]);
                session_name((string)($sCfg['name'] ?? 'SHA256_SESSID'));
            }
            session_start();
        }
    }

    /**
     * Enmascara el claim google_sub para mostrar estado de vinculación en UI sin exponer el valor íntegro.
     */
    public static function maskGoogleSub(?string $sub): ?string
    {
        if (!is_string($sub) || trim($sub) === '') {
            return null;
        }
        $clean = trim($sub);
        if (strlen($clean) <= 6) {
            return '••••••';
        }
        return substr($clean, 0, 3) . '••••••••' . substr($clean, -4);
    }

    /**
     * Sanea una fila de `usuarios` eliminando secretos, hashes y claims sensibles antes de guardarla en sesión o enviarla al cliente.
     */
    public static function sanitizeUserRow(array $row): array
    {
        $googleSub = isset($row['google_sub']) ? trim((string)$row['google_sub']) : '';
        $recoveryHashes = [];
        if (!empty($row['totp_recovery_hashes']) && is_string($row['totp_recovery_hashes'])) {
            $decoded = json_decode($row['totp_recovery_hashes'], true);
            if (is_array($decoded)) {
                $recoveryHashes = $decoded;
            }
        }

        $totpEncrypted = Totp::isEncryptedSecret($row['totp_secret'] ?? null);
        $totpEnabled = (bool)($row['totp_enabled'] ?? false) && $totpEncrypted;

        unset(
            $row['password_hash'],
            $row['totp_secret'],
            $row['totp_recovery_hashes'],
            $row['totp_last_step'],
            $row['totp_last_used_slice'],
            $row['google_sub']
        );

        $row['totp_enabled'] = $totpEnabled ? 1 : 0;
        $row['activo'] = (int)($row['activo'] ?? 1);
        $row['google_linked'] = $googleSub !== '';
        $row['google_sub_masked'] = self::maskGoogleSub($googleSub);
        $row['totp_enrolled_at'] = $row['totp_enrolled_at'] ?? null;
        $row['last_login_at'] = $row['last_login_at'] ?? null;
        $row['last_login_ip'] = $row['last_login_ip'] ?? null;
        $row['recovery_codes_remaining'] = count($recoveryHashes);

        return $row;
    }

    /**
     * Devuelve el usuario completamente autenticado (Google OIDC + TOTP verificado),
     * validando expiración por inactividad (30 min) y expiración absoluta (8 h) en servidor.
     *
     * Si únicamente existe `$_SESSION['pending_mfa']`, devuelve estrictamente `null`.
     */
    public static function getUser(?int $now = null): ?array
    {
        self::start();

        // Bloqueo estricto: pending_mfa jamás equivale a una sesión autenticada
        if (!empty($_SESSION['pending_mfa'])) {
            return null;
        }

        if (empty($_SESSION['usuario']) || !is_array($_SESSION['usuario'])) {
            return null;
        }

        if (($_SESSION['auth_mfa_verified'] ?? false) !== true) {
            return null;
        }

        $config = self::getConfig();
        $idleTimeout = (int)($config['session']['idle_timeout'] ?? 1800);
        $absoluteTimeout = (int)($config['session']['absolute_timeout'] ?? 28800);
        $nowTs = $now ?? time();

        $createdAt = (int)($_SESSION['auth_created_at'] ?? 0);
        $lastActivity = (int)($_SESSION['auth_last_activity'] ?? 0);

        if ($createdAt <= 0 || ($nowTs - $createdAt) > $absoluteTimeout) {
            self::logout();
            return null;
        }

        if ($lastActivity <= 0 || ($nowTs - $lastActivity) > $idleTimeout) {
            self::logout();
            return null;
        }

        $_SESSION['auth_last_activity'] = $nowTs;
        return $_SESSION['usuario'];
    }

    public static function requireUser(): array
    {
        $user = self::getUser();
        if (!$user) {
            http_response_code(401);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, private');
            echo json_encode([
                'ok'            => false,
                'authenticated' => false,
                'error'         => 'Sesión no autorizada o expirada. Por favor autentíquese nuevamente.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
        return $user;
    }

    /**
     * Crea únicamente `$_SESSION['pending_mfa']` (TTL 5 min) tras validar Google OIDC.
     * Destruye cualquier sesión autenticada previa para impedir escalamiento sin TOTP.
     */
    public static function setPendingMfa(array $userRow, string $googleSub, string $ip, ?int $now = null): array
    {
        self::start();
        $config = self::getConfig();
        $ttl = (int)($config['session']['pending_mfa_ttl'] ?? 300);
        $nowTs = $now ?? time();

        unset(
            $_SESSION['usuario'],
            $_SESSION['auth_mfa_verified'],
            $_SESSION['auth_created_at'],
            $_SESSION['auth_last_activity'],
            $_SESSION['pending_totp_enroll'],
            $_SESSION['oidc_auth']
        );

        if (PHP_SAPI !== 'cli' && !headers_sent()) {
            session_regenerate_id(true);
        }

        $totpEnrolled = (bool)($userRow['totp_enabled'] ?? false)
            && Totp::isEncryptedSecret($userRow['totp_secret'] ?? null);

        $pending = [
            'user_id'       => (string)$userRow['id'],
            'email'         => strtolower(trim((string)$userRow['email'])),
            'google_sub'    => $googleSub,
            'nombre'        => trim(((string)($userRow['nombre'] ?? '')) . ' ' . ((string)($userRow['apellido'] ?? ''))),
            'totp_enrolled' => $totpEnrolled,
            'created_at'    => $nowTs,
            'expires_at'    => $nowTs + $ttl,
            'ip'            => $ip,
        ];

        $_SESSION['pending_mfa'] = $pending;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        return $pending;
    }

    /**
     * Devuelve el estado `pending_mfa` si existe y no ha excedido su TTL de 5 minutos.
     */
    public static function getPendingMfa(?int $now = null): ?array
    {
        self::start();
        $pending = $_SESSION['pending_mfa'] ?? null;
        if (!is_array($pending)) {
            return null;
        }

        $nowTs = $now ?? time();
        $expiresAt = (int)($pending['expires_at'] ?? 0);
        if ($expiresAt <= 0 || $nowTs > $expiresAt) {
            unset($_SESSION['pending_mfa'], $_SESSION['pending_totp_enroll']);
            return null;
        }

        return $pending;
    }

    /**
     * Limpia el estado intermedio pending_mfa y cualquier enrolamiento en curso.
     */
    public static function clearPendingMfa(): void
    {
        self::start();
        unset($_SESSION['pending_mfa'], $_SESSION['pending_totp_enroll'], $_SESSION['oidc_auth']);
    }

    /**
     * Promueve una sesión `pending_mfa` a sesión forense completa tras validar TOTP o código de respaldo.
     */
    public static function promotePendingToAuthenticated(array $userRow, ?int $now = null): array
    {
        self::start();
        $nowTs = $now ?? time();
        $cleanUser = self::sanitizeUserRow($userRow);

        unset(
            $_SESSION['pending_mfa'],
            $_SESSION['pending_totp_enroll'],
            $_SESSION['oidc_auth']
        );

        if (PHP_SAPI !== 'cli' && !headers_sent()) {
            session_regenerate_id(true);
        }

        $_SESSION['usuario'] = $cleanUser;
        $_SESSION['auth_mfa_verified'] = true;
        $_SESSION['auth_created_at'] = $nowTs;
        $_SESSION['auth_last_activity'] = $nowTs;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        return $cleanUser;
    }

    public static function getCsrfToken(): string
    {
        self::start();
        if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyCsrf(?string $token): bool
    {
        self::start();
        $stored = $_SESSION['csrf_token'] ?? null;
        if (!is_string($stored) || $stored === '' || !is_string($token) || $token === '') {
            return false;
        }
        return hash_equals($stored, $token);
    }

    /**
     * Exige cabecera `X-CSRF-Token` válida en toda petición mutante (POST, PUT, DELETE, PATCH).
     */
    public static function requireCsrf(): void
    {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        if ($token === null && function_exists('getallheaders')) {
            $headers = getallheaders();
            if (is_array($headers)) {
                foreach ($headers as $name => $val) {
                    if (strcasecmp((string)$name, 'X-CSRF-Token') === 0) {
                        $token = (string)$val;
                        break;
                    }
                }
            }
        }

        if (!self::verifyCsrf(is_string($token) ? $token : null)) {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, private');
            echo json_encode([
                'ok'    => false,
                'error' => 'Validación de token CSRF (X-CSRF-Token) fallida. Solicitud denegada.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    /**
     * Verifica si una IP o usuario ha superado el umbral de intentos fallidos (5 intentos / 15 min).
     */
    public static function isRateLimited(string $ip, string $user, ?int $now = null): bool
    {
        try {
            $pdo = Database::getConnection();
            $config = self::getConfig();
            $maxAttempts = (int)($config['security']['rate_limit_max'] ?? 5);
            $windowMinutes = (int)($config['security']['rate_limit_minutes'] ?? 15);
            $nowTs = $now ?? time();
            $cutoff = gmdate('Y-m-d H:i:s', $nowTs - ($windowMinutes * 60));

            $stmt = $pdo->prepare('
                SELECT COUNT(*) as fallos
                FROM login_attempts
                WHERE (ip = :ip OR usuario = :usuario)
                  AND exitoso = 0
                  AND intentado_en >= :cutoff
            ');
            $stmt->execute([
                'ip'      => $ip,
                'usuario' => strtolower(trim($user)),
                'cutoff'  => $cutoff,
            ]);
            $row = $stmt->fetch();
            return (int)($row['fallos'] ?? 0) >= $maxAttempts;
        } catch (\Throwable $e) {
            error_log('[FCCO RateLimit Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Registra un intento de autenticación o verificación MFA en `login_attempts`.
     */
    public static function recordAttempt(string $ip, string $user, bool $success, ?int $now = null): void
    {
        try {
            $pdo = Database::getConnection();
            $cleanUser = strtolower(trim($user));
            $nowStr = gmdate('Y-m-d H:i:s', $now ?? time());

            $stmt = $pdo->prepare('
                INSERT INTO login_attempts (ip, usuario, intentado_en, exitoso)
                VALUES (:ip, :usuario, :intentado_en, :exitoso)
            ');
            $stmt->execute([
                'ip'           => $ip,
                'usuario'      => $cleanUser,
                'intentado_en' => $nowStr,
                'exitoso'      => $success ? 1 : 0,
            ]);

            if ($success) {
                $stmtClear = $pdo->prepare('DELETE FROM login_attempts WHERE usuario = :usuario OR ip = :ip');
                $stmtClear->execute(['usuario' => $cleanUser, 'ip' => $ip]);
            }
        } catch (\Throwable $e) {
            error_log('[FCCO AttemptRecord Error] ' . $e->getMessage());
        }
    }

    /**
     * Destruye por completo la sesión y expira la cookie en el navegador.
     */
    public static function logout(): void
    {
        self::start();
        $_SESSION = [];
        if (PHP_SAPI !== 'cli' && !headers_sent() && ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires'  => time() - 42000,
                'path'     => $params['path'] ?: '/',
                'domain'   => $params['domain'] ?: '',
                'secure'   => (bool)$params['secure'],
                'httponly' => true,
                'samesite' => $params['samesite'] ?: 'Lax',
            ]);
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }
}
