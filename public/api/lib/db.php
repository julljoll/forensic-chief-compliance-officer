<?php
/**
 * SHA256.US — Conexión y Gestión de Base de Datos PDO (MySQL).
 * Cumplimiento: OWASP ASVS · ISO/IEC 27001 (Prevención de fuga de información de depuración).
 */

declare(strict_types=1);

namespace Sha256\Db;

use PDO;
use PDOException;

class Database
{
    private static ?PDO $instance = null;

    public static function getConnection(): PDO
    {
        if (self::$instance === null) {
            $config = require __DIR__ . '/../config.php';
            $dbCfg = $config['db'];

            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $dbCfg['host'],
                $dbCfg['port'],
                $dbCfg['database'],
                $dbCfg['charset']
            );

            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];

            try {
                self::$instance = new PDO($dsn, $dbCfg['username'], $dbCfg['password'], $options);
            } catch (PDOException $e) {
                // Registrar detalle internamente en el log del servidor web sin exponer credenciales
                error_log('[FCCO DB Error] ' . $e->getMessage());

                http_response_code(503);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode([
                    'ok'    => false,
                    'error' => 'Servicio temporalmente no disponible (Error interno de conexión a base de datos)',
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
        }

        return self::$instance;
    }
}
