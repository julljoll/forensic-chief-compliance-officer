<?php
/**
 * SHA256.US — Plantilla Opcional de Configuración Local para cPanel (`config.local.php`).
 *
 * OPCIONAL: El sistema ya funciona en cPanel usando el correo local (`mail()`).
 * Si deseas usar SMTP autenticado de cPanel (recomendado para evitar carpeta Spam en Gmail)
 * o personalizar credenciales de MySQL / lista blanca, copia este archivo como
 * `public_html/api/config.local.php` (excluido de Git y bloqueado por `.htaccess`).
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
        'secure'   => true,  // true en producción HTTPS (SSL)
        'httponly' => true,
        'samesite' => 'Lax',
    ],
    'security' => [
        'require_https'          => true,
        'password_login_enabled' => false,
        // Lista blanca estricta de EXACTAMENTE 2 correos de peritos autorizados
        'allowed_emails'         => [
            'perito.principal@example.com',
            'perito.adquisicion@example.com',
        ],
    ],
    'mail' => [
        'driver'          => 'smtp', // 'auto' | 'smtp' | 'php_mail'
        'from_email'      => 'no-reply@sha256.us',
        'from_name'       => 'SHA256.US — Bóveda Pericial',
        'app_url'         => 'https://sha256.us',
        // Datos de cuenta de correo creada en cPanel -> Cuentas de correo electrónico
        'smtp_host'       => 'sha256.us',
        'smtp_port'       => 465,
        'smtp_encryption' => 'ssl', // 'ssl' (puerto 465) o 'tls' (puerto 587)
        'smtp_user'       => 'no-reply@sha256.us',
        'smtp_pass'       => 'CLAVE_DE_LA_CUENTA_NO_REPLY_EN_CPANEL',
    ],
];
