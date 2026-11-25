<?php
/**
 * SHA256.US — Configuración Simplificada y Segura (Código OTP 6 Dígitos + Enlace Mágico por Correo).
 *
 * CERO Google Cloud Console · CERO app autenticadora externa · CERO contraseñas locales.
 * Funciona de inmediato en cPanel usando el correo del servidor (`mail()`), o con SMTP autenticado
 * opcional si se crea `public/api/config.local.php` (excluido de Git).
 */

declare(strict_types=1);

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
    || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);

$envAllowedRaw = (string)($_SERVER['ALLOWED_EXPERT_EMAILS'] ?? $_ENV['ALLOWED_EXPERT_EMAILS'] ?? (getenv('ALLOWED_EXPERT_EMAILS') ?: ''));
$defaultAllowedEmails = $envAllowedRaw !== ''
    ? array_values(array_filter(array_map('trim', explode(',', $envAllowedRaw))))
    : [
        'julljoll@gmail.com',
        'sha256.us@gmail.com',
    ];

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
        'secure'           => $isHttps,
        'httponly'         => true,
        'samesite'         => 'Lax', // Permite abrir enlaces mágicos desde clientes de correo
    ],
    'security' => [
        'require_https'          => false, // Establecer true en config.local.php si se desea forzar HTTPS en PHP
        'password_login_enabled' => false, // DESHABILITADO PERMANENTEMENTE (Solo Código OTP / Magic Link)
        'rate_limit_max'         => 5,     // Máximo 5 intentos fallidos
        'rate_limit_minutes'     => 15,    // Ventana de bloqueo de 15 minutos
        'otp_ttl_seconds'        => 300,   // Código OTP y Enlace Mágico válidos por 5 minutos
        'otp_max_attempts'       => 5,     // Máximo 5 intentos erróneos por código antes de invalidarlo
        'otp_resend_cooldown'    => 45,    // Segundos mínimos entre reenvíos de código
        'otp_max_requests_15m'   => 5,     // Máximo 5 códigos solicitados cada 15 minutos
        // Lista blanca estricta e inmutable de exactamente 2 correos de peritos
        'allowed_emails'         => $defaultAllowedEmails,
    ],
    'mail' => [
        // 'auto' usa SMTP si smtp_host/smtp_user/smtp_pass están completos; si no, usa mail() nativo de cPanel
        'driver'          => (string)($_SERVER['MAIL_DRIVER'] ?? $_ENV['MAIL_DRIVER'] ?? (getenv('MAIL_DRIVER') ?: 'auto')),
        'from_email'      => (string)($_SERVER['MAIL_FROM_EMAIL'] ?? $_ENV['MAIL_FROM_EMAIL'] ?? (getenv('MAIL_FROM_EMAIL') ?: 'no-reply@sha256.us')),
        'from_name'       => (string)($_SERVER['MAIL_FROM_NAME'] ?? $_ENV['MAIL_FROM_NAME'] ?? (getenv('MAIL_FROM_NAME') ?: 'SHA256.US — Bóveda Pericial')),
        'app_url'         => (string)($_SERVER['APP_URL'] ?? $_ENV['APP_URL'] ?? (getenv('APP_URL') ?: 'https://sha256.us')),
        // Opcional: credenciales SMTP de cPanel (ej. mail.sha256.us:465 SSL) para máxima entregabilidad a Gmail
        'smtp_host'       => (string)($_SERVER['SMTP_HOST'] ?? $_ENV['SMTP_HOST'] ?? (getenv('SMTP_HOST') ?: '')),
        'smtp_port'       => (int)($_SERVER['SMTP_PORT'] ?? $_ENV['SMTP_PORT'] ?? (getenv('SMTP_PORT') ?: 465)),
        'smtp_encryption' => (string)($_SERVER['SMTP_ENCRYPTION'] ?? $_ENV['SMTP_ENCRYPTION'] ?? (getenv('SMTP_ENCRYPTION') ?: 'ssl')), // 'ssl' | 'tls' | 'none'
        'smtp_user'       => (string)($_SERVER['SMTP_USER'] ?? $_ENV['SMTP_USER'] ?? (getenv('SMTP_USER') ?: '')),
        'smtp_pass'       => (string)($_SERVER['SMTP_PASS'] ?? $_ENV['SMTP_PASS'] ?? (getenv('SMTP_PASS') ?: '')),
    ],
];

// Cargar override local privado opcional (excluido de Git) si existe
$localConfigPath = __DIR__ . '/config.local.php';
if (file_exists($localConfigPath)) {
    $localConfig = require $localConfigPath;
    if (is_array($localConfig)) {
        $overrideAllowed = $localConfig['security']['allowed_emails'] ?? null;
        $defaultConfig = array_replace_recursive($defaultConfig, $localConfig);
        if (is_array($overrideAllowed)) {
            $defaultConfig['security']['allowed_emails'] = array_values($overrideAllowed);
        }
    }
}

// Regla inmutable: el inicio de sesión por contraseña local permanece deshabilitado
$defaultConfig['security']['password_login_enabled'] = false;

return $defaultConfig;
