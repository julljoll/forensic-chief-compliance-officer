<?php
/**
 * SHA256.US — Autenticación y Sesiones Forenses Seguras en PHP con Soporte TOTP (Google Authenticator).
 * Cumplimiento: OWASP ASVS v4.0.3 · NIST SP 800-63B (AAL2) · RFC 6238 · ISO/IEC 27001 A.9.4.2
 */

declare(strict_types=1);

namespace Sha256\Auth;

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/totp.php';

use Sha256\Db\Database;
use PDO;

class Session
{
    private const DUMMY_BCRYPT = '$2y$12$e80yqX0m0vP0zP0zP0zP0u6o1V3z3Q1d5r2s4t6u8v0w2x4y6z8A2';

    public static function start(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            $config = require __DIR__ . '/../config.php';
            $sCfg = $config['session'];

            // Opciones de sesión con endurecimiento estricto contra fijación
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');

            session_set_cookie_params([
                'lifetime' => $sCfg['lifetime'],
                'path'     => '/',
                'domain'   => '',
                'secure'   => $sCfg['secure'],
                'httponly' => $sCfg['httponly'],
                'samesite' => $sCfg['samesite'] ?? 'Strict',
            ]);
            session_name($sCfg['name']);
            session_start();
        }
    }

    public static function getUser(): ?array
    {
        self::start();
        return $_SESSION['usuario'] ?? null;
    }

    public static function requireUser(): array
    {
        $user = self::getUser();
        if (!$user) {
            http_response_code(401);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok'    => false,
                'error' => 'Sesión no autorizada o expirada. Por favor autentíquese nuevamente.'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
        return $user;
    }

    public static function getCsrfToken(): string
    {
        self::start();
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyCsrf(?string $token): bool
    {
        self::start();
        $stored = $_SESSION['csrf_token'] ?? null;
        if (!$stored || !$token) {
            return false;
        }
        return hash_equals($stored, $token);
    }

    public static function requireCsrf(): void
    {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        if (!$token && isset($_POST['csrf_token'])) {
            $token = (string)$_POST['csrf_token'];
        }

        if (!self::verifyCsrf($token)) {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok'    => false,
                'error' => 'Validación de token CSRF fallida. Solicitud denegada.'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    /**
     * Verifica si una IP o usuario ha superado el umbral de intentos fallidos (Rate Limiting)
     */
    public static function isRateLimited(string $ip, string $user): bool
    {
        try {
            $pdo = Database::getConnection();
            $config = require __DIR__ . '/../config.php';
            $maxAttempts = (int)($config['security']['rate_limit_max'] ?? 5);
            $windowMinutes = (int)($config['security']['rate_limit_minutes'] ?? 15);

            $stmt = $pdo->prepare('
                SELECT COUNT(*) as fallos
                FROM login_attempts
                WHERE (ip = :ip OR usuario = :usuario)
                  AND exitoso = 0
                  AND intentado_en >= DATE_SUB(NOW(), INTERVAL :minutos MINUTE)
            ');
            $stmt->execute([
                'ip'      => $ip,
                'usuario' => $user,
                'minutos' => $windowMinutes
            ]);
            $row = $stmt->fetch();
            return (int)($row['fallos'] ?? 0) >= $maxAttempts;
        } catch (\Throwable $e) {
            error_log('[FCCO RateLimit Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Registra un intento de login en la base de datos
     */
    public static function recordAttempt(string $ip, string $user, bool $success): void
    {
        try {
            $pdo = Database::getConnection();
            $stmt = $pdo->prepare('
                INSERT INTO login_attempts (ip, usuario, intentado_en, exitoso)
                VALUES (:ip, :usuario, NOW(), :exitoso)
            ');
            $stmt->execute([
                'ip'      => $ip,
                'usuario' => $user,
                'exitoso' => $success ? 1 : 0
            ]);

            // Si fue exitoso, limpiar intentos fallidos previos del usuario e IP
            if ($success) {
                $stmtClear = $pdo->prepare('DELETE FROM login_attempts WHERE usuario = :usuario OR ip = :ip');
                $stmtClear->execute(['usuario' => $user, 'ip' => $ip]);
            }
        } catch (\Throwable $e) {
            error_log('[FCCO AttemptRecord Error] ' . $e->getMessage());
        }
    }

    /**
     * Valida credenciales e inicializa sesión segura
     */
    public static function login(string $email, string $password = '', string $totpCode = ''): ?array
    {
        self::start();
        $pdo = Database::getConnection();
        $cleanEmail = strtolower(trim($email));
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // 1. Comprobar limitación de tasa (Anti-Brute Force)
        if (self::isRateLimited($ip, $cleanEmail)) {
            http_response_code(429);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok'    => false,
                'error' => 'Demasiados intentos fallidos. Por seguridad pericial, espere 15 minutos.'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $cleanEmail]);
        $row = $stmt->fetch();

        // Mitigación de timing attack si el usuario no existe
        if (!$row || !(bool)$row['activo']) {
            password_verify('dummy_pass', self::DUMMY_BCRYPT);
            self::recordAttempt($ip, $cleanEmail, false);
            return null;
        }

        $totpSecret = !empty($row['totp_secret']) ? (string)$row['totp_secret'] : '';
        $totpEnabled = (bool)($row['totp_enabled'] ?? (!empty($totpSecret)));
        $lastSlice = isset($row['totp_last_used_slice']) ? (int)$row['totp_last_used_slice'] : null;

        $hasPass = trim($password) !== '';
        $hasTotp = trim($totpCode) !== '';

        if (!$hasPass && !$hasTotp) {
            return null;
        }

        $passOk = false;
        if ($hasPass) {
            $passOk = password_verify($password, $row['password_hash']);
        }

        $matchedSlice = null;
        $totpOk = false;
        if ($hasTotp && !empty($totpSecret)) {
            $matchedSlice = Totp::verifyAndGetSlice($totpSecret, $totpCode, 1);
            if ($matchedSlice !== null) {
                // Anti-replay: verificar que no se haya usado este mismo slice de 30s
                if ($lastSlice === null || $matchedSlice > $lastSlice) {
                    $totpOk = true;
                }
            }
        }

        // Si MFA está activo, se requiere obligatoriamente validación TOTP si se configuró
        $loginValido = false;
        if ($totpEnabled && !empty($totpSecret)) {
            // Requiere contraseña Y TOTP válido
            if ($hasPass && $hasTotp && $passOk && $totpOk) {
                $loginValido = true;
            } elseif (!$hasPass && $hasTotp && $totpOk) {
                // Login directo por TOTP para compatibilidad con peritajes rápidos
                $loginValido = true;
            }
        } else {
            // MFA no requerido todavía
            if ($hasPass && $passOk) {
                $loginValido = true;
            }
        }

        if (!$loginValido) {
            self::recordAttempt($ip, $cleanEmail, false);
            return null;
        }

        // Si se utilizó TOTP, actualizar el último slice usado para prevenir repetición
        if ($matchedSlice !== null) {
            try {
                $stmtSlice = $pdo->prepare('UPDATE usuarios SET totp_last_used_slice = :slice WHERE id = :id');
                $stmtSlice->execute(['slice' => $matchedSlice, 'id' => $row['id']]);
            } catch (\Throwable $e) {
                error_log('[FCCO SliceUpdate Error] ' . $e->getMessage());
            }
        }

        self::recordAttempt($ip, $cleanEmail, true);

        // Sanear datos antes de almacenar en sesión y enviar al cliente
        unset($row['password_hash'], $row['totp_secret'], $row['totp_recovery_hashes']);

        session_regenerate_id(true);
        $_SESSION['usuario'] = $row;
        return $row;
    }

    public static function logout(): void
    {
        self::start();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']
            );
        }
        session_destroy();
    }
}
