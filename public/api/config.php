<?php
/**
 * SHA256.US — Configuración de Base de Datos para cPanel / Apache.
 *
 * En cPanel, puedes definir variables de entorno en el archivo .htaccess,
 * en las variables de entorno del servidor, o crear un archivo local
 * `public/api/config.local.php` que no se sube a Git.
 */

declare(strict_types=1);

$defaultConfig = [
    'db' => [
        'host'     => $_SERVER['DB_HOST'] ?? $_ENV['DB_HOST'] ?? (getenv('DB_HOST') ?: 'localhost'),
        'port'     => (int)($_SERVER['DB_PORT'] ?? $_ENV['DB_PORT'] ?? (getenv('DB_PORT') ?: 3306)),
        'database' => $_SERVER['DB_NAME'] ?? $_ENV['DB_NAME'] ?? (getenv('DB_NAME') ?: 'sha256us_forensic'),
        'username' => $_SERVER['DB_USER'] ?? $_ENV['DB_USER'] ?? (getenv('DB_USER') ?: 'sha256us_user'),
        'password' => $_SERVER['DB_PASS'] ?? $_ENV['DB_PASS'] ?? (getenv('DB_PASS') ?: ''),
        'charset'  => 'utf8mb4',
    ],
    'session' => [
        'name'     => 'SHA256_SESSID',
        'lifetime' => 86400, // 24 horas
        'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
        'httponly' => true,
        'samesite' => 'Strict',
    ],
    'security' => [
        'require_https'      => false, // Cambiar a true en producción con SSL
        'rate_limit_max'     => 5,     // Máximo intentos fallidos
        'rate_limit_minutes' => 15,    // Ventana de bloqueo
    ]
];

// Cargar override local si existe
$localConfigPath = __DIR__ . '/config.local.php';
if (file_exists($localConfigPath)) {
    $localConfig = require $localConfigPath;
    if (is_array($localConfig)) {
        $defaultConfig = array_replace_recursive($defaultConfig, $localConfig);
    }
}

return $defaultConfig;
