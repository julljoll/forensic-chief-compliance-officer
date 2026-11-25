<?php
/**
 * SHA256.US — Configuración de Seguridad Forense (Opción C — Grado Forense) para cPanel / Apache.
 *
 * En cPanel, copie `config.example.php` como `public/api/config.local.php` (excluido de Git)
 * y defina allí:
 *  - Credenciales MySQL
 *  - Credenciales Google OAuth 2.0 / OIDC (client_id, client_secret, redirect_uri)
 *  - Lista blanca inmutable de exactamente 2 correos de peritos (`security.allowed_emails`)
 *  - Clave maestra AES-256-GCM de 32 bytes para cifrado en reposo de TOTP (`security.totp_encryption_key`)
 */

declare(strict_types=1);

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
    || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);

$envAllowedRaw = (string)($_SERVER['ALLOWED_EXPERT_EMAILS'] ?? $_ENV['ALLOWED_EXPERT_EMAILS'] ?? (getenv('ALLOWED_EXPERT_EMAILS') ?: ''));
$envAllowedEmails = $envAllowedRaw !== ''
    ? array_values(array_filter(array_map('trim', explode(',', $envAllowedRaw))))
    : [];

$defaultConfig = [
    'db' => [
        'host'     => $_SERVER['DB_HOST'] ?? $_ENV['DB_HOST'] ?? (getenv('DB_HOST') ?: 'localhost'),
        'port'     => (int)($_SERVER['DB_PORT'] ?? $_ENV['DB_PORT'] ?? (getenv('DB_PORT') ?: 3306)),
        'database' => $_SERVER['DB_NAME'] ?? $_ENV['DB_NAME'] ?? (getenv('DB_NAME') ?: 'sirixutr_Forensic_cco'),
        'username' => $_SERVER['DB_USER'] ?? $_ENV['DB_USER'] ?? (getenv('DB_USER') ?: 'sirixutr_julljoll'),
        'password' => $_SERVER['DB_PASS'] ?? $_ENV['DB_PASS'] ?? (getenv('DB_PASS') ?: 'Karupano15*'),
        'charset'  => 'utf8mb4',
    ],
    'session' => [
        'name'             => 'SHA256_SESSID',
        'lifetime'         => 28800, // 8 horas absolutas
        'idle_timeout'     => 1800,  // 30 minutos de inactividad en servidor
        'absolute_timeout' => 28800, // 8 horas absolutas en servidor
        'pending_mfa_ttl'  => 300,   // 5 minutos TTL para $_SESSION['pending_mfa']
        'oidc_state_ttl'   => 600,   // 10 minutos TTL para PKCE/state/nonce OAuth
        'secure'           => $isHttps,
        'httponly'         => true,
        'samesite'         => 'Lax', // Requerido para callback GET de Google OAuth 2.0
    ],
    'security' => [
        'require_https'          => false, // Establecer true en config.local.php (producción SSL)
        'password_login_enabled' => false, // DESHABILITADO PERMANENTEMENTE (Solo Google OIDC + TOTP)
        'rate_limit_max'         => 5,     // Máximo 5 intentos fallidos
        'rate_limit_minutes'     => 15,    // Ventana de bloqueo de 15 minutos
        // Lista blanca estricta e inmutable de exactamente 2 correos de peritos (definir en config.local.php)
        'allowed_emails'         => $envAllowedEmails,
        // Clave maestra de 32 bytes (64 hex o base64:...) para AES-256-GCM de totp_secret (definir en config.local.php)
        'totp_encryption_key'    => (string)($_SERVER['TOTP_ENCRYPTION_KEY'] ?? $_ENV['TOTP_ENCRYPTION_KEY'] ?? (getenv('TOTP_ENCRYPTION_KEY') ?: '')),
    ],
    'google_oidc' => [
        'client_id'       => (string)($_SERVER['GOOGLE_CLIENT_ID'] ?? $_ENV['GOOGLE_CLIENT_ID'] ?? (getenv('GOOGLE_CLIENT_ID') ?: '')),
        'client_secret'   => (string)($_SERVER['GOOGLE_CLIENT_SECRET'] ?? $_ENV['GOOGLE_CLIENT_SECRET'] ?? (getenv('GOOGLE_CLIENT_SECRET') ?: '')),
        'redirect_uri'    => (string)($_SERVER['GOOGLE_REDIRECT_URI'] ?? $_ENV['GOOGLE_REDIRECT_URI'] ?? (getenv('GOOGLE_REDIRECT_URI') ?: 'https://sha256.us/api/auth-google-callback.php')),
        'auth_endpoint'   => 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint'  => 'https://oauth2.googleapis.com/token',
        'jwks_uri'        => 'https://www.googleapis.com/oauth2/v3/certs',
        'jwks_cache_path' => sys_get_temp_dir() . '/sha256_google_jwks.json',
        'jwks_cache_ttl'  => 3600,
    ],
];

// Cargar override local privado (excluido de Git) si existe
$localConfigPath = __DIR__ . '/config.local.php';
if (file_exists($localConfigPath)) {
    $localConfig = require $localConfigPath;
    if (is_array($localConfig)) {
        // Reemplazo seguro de listas numéricas (allowed_emails) para no fusionar índices con defaults
        $overrideAllowed = $localConfig['security']['allowed_emails'] ?? null;
        $defaultConfig = array_replace_recursive($defaultConfig, $localConfig);
        if (is_array($overrideAllowed)) {
            $defaultConfig['security']['allowed_emails'] = array_values($overrideAllowed);
        }
    }
}

// Regla inmutable de Grado Forense: el inicio de sesión por contraseña local permanece deshabilitado
$defaultConfig['security']['password_login_enabled'] = false;

return $defaultConfig;
