<?php
/**
 * SHA256.US — Plantilla de Configuración Local para cPanel / Apache (Opción C — Grado Forense).
 *
 * INSTRUCCIONES DE DESPLIEGUE:
 * 1. Copie este archivo como `public/api/config.local.php` (o `dist/api/config.local.php` en cPanel).
 *    Ese archivo está excluido en `.gitignore` y bloqueado por `.htaccess`.
 * 2. Configure las credenciales de MySQL, Google OAuth 2.0 (Web Application), los EXACTAMENTE 2 correos
 *    de peritos autorizados y una clave AES-256-GCM generada con:
 *      openssl rand -hex 32
 * 3. Registre en Google Cloud Console como Authorized Redirect URI:
 *      https://sha256.us/api/auth-google-callback.php
 */

declare(strict_types=1);

return [
    'db' => [
        'host'     => 'localhost',
        'port'     => 3306,
        'database' => 'nombre_base_datos_cpanel',
        'username' => 'usuario_mysql_cpanel',
        'password' => 'clave_segura_mysql',
        'charset'  => 'utf8mb4',
    ],
    'session' => [
        'name'             => 'SHA256_SESSID',
        'lifetime'         => 28800, // 8 horas absolutas
        'idle_timeout'     => 1800,  // 30 minutos de inactividad
        'absolute_timeout' => 28800, // 8 horas absolutas
        'pending_mfa_ttl'  => 300,   // 5 minutos para completar Google Authenticator
        'oidc_state_ttl'   => 600,   // 10 minutos para flujo OAuth PKCE/state
        'secure'           => true,  // Obligatorio true en producción HTTPS (SSL)
        'httponly'         => true,
        'samesite'         => 'Lax', // Requerido para callback GET de Google OAuth 2.0
    ],
    'security' => [
        'require_https'          => true,
        'password_login_enabled' => false, // Siempre deshabilitado: solo Google OIDC + TOTP
        'rate_limit_max'         => 5,     // 5 intentos fallidos
        'rate_limit_minutes'     => 15,    // Bloqueo de 15 minutos
        // Lista blanca inmutable estricta: EXACTAMENTE 2 correos de peritos autorizados
        'allowed_emails'         => [
            'perito.principal@example.com',
            'perito.adquisicion@example.com',
        ],
        // Clave maestra AES-256-GCM (32 bytes en hexadecimal: ejecutar `openssl rand -hex 32`)
        'totp_encryption_key'    => 'REEMPLAZAR_CON_64_CARACTERES_HEX_GENERADOS_CON_OPENSSL_RAND_HEX_32',
    ],
    'google_oidc' => [
        'client_id'     => 'REEMPLAZAR_CLIENT_ID.apps.googleusercontent.com',
        'client_secret' => 'GOCSPX-REEMPLAZAR_CLIENT_SECRET',
        'redirect_uri'  => 'https://sha256.us/api/auth-google-callback.php',
    ],
];
