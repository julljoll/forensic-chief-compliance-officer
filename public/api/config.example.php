<?php
/**
 * SHA256.US — Plantilla de Configuración Local para cPanel / Apache.
 *
 * Copie este archivo como `config.local.php` en el servidor y ajuste sus credenciales.
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
        'name'     => 'SHA256_SESSID',
        'lifetime' => 86400,
        'secure'   => true, // true en servidores con certificado SSL (HTTPS)
        'httponly' => true,
        'samesite' => 'Strict',
    ],
    'security' => [
        'require_https'      => true,
        'rate_limit_max'     => 5,
        'rate_limit_minutes' => 15,
    ]
];
