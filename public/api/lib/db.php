<?php
/**
 * SHA256.US — Conexión y Gestión de Base de Datos PDO (MySQL).
 * Auto-crea de forma idempotente las tablas necesarias (incluyendo `email_otp_tokens`)
 * para un despliegue inmediato en cPanel sin migraciones manuales obligatorias.
 */

declare(strict_types=1);

namespace Sha256\Db;

use PDO;
use PDOException;

class Database
{
    private static ?PDO $instance = null;

    /**
     * Inyección de conexión PDO exclusiva para pruebas unitarias en PHP CLI.
     */
    public static function setConnectionForTesting(?PDO $pdo): void
    {
        if (PHP_SAPI !== 'cli') {
            throw new \RuntimeException('setConnectionForTesting solo está permitido en CLI');
        }
        self::$instance = $pdo;
    }

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
                self::ensureSchema(self::$instance);
            } catch (PDOException $e) {
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

    /**
     * Garantiza que las tablas de acceso Email OTP, auditoría y usuarios oficiales existan en cPanel.
     */
    private static function ensureSchema(PDO $pdo): void
    {
        try {
            // 1. Tabla usuarios (sin contraseñas locales utilizables)
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS `usuarios` (
                  `id` VARCHAR(64) NOT NULL,
                  `email` VARCHAR(191) NOT NULL,
                  `password_hash` VARCHAR(255) NOT NULL DEFAULT '!DISABLED_EMAIL_OTP_ONLY!',
                  `totp_secret` VARCHAR(255) DEFAULT NULL,
                  `totp_enabled` TINYINT(1) NOT NULL DEFAULT 0,
                  `totp_last_step` BIGINT NULL DEFAULT NULL,
                  `totp_recovery_hashes` TEXT NULL DEFAULT NULL,
                  `last_login_at` DATETIME DEFAULT NULL,
                  `last_login_ip` VARCHAR(45) DEFAULT NULL,
                  `nombre` VARCHAR(150) NOT NULL,
                  `apellido` VARCHAR(150) NOT NULL DEFAULT '',
                  `ci` VARCHAR(32) NOT NULL DEFAULT '',
                  `cargo` VARCHAR(120) NOT NULL DEFAULT 'Perito Informático Forense',
                  `rol` ENUM('admin', 'perito_lider', 'perito_asistente', 'fiscal', 'compliance_officer', 'coordinador') NOT NULL DEFAULT 'perito_lider',
                  `organismo` VARCHAR(150) NOT NULL DEFAULT 'Laboratorio Privado SHA256.US',
                  `despacho` VARCHAR(150) NOT NULL DEFAULT 'División Pericial Digital',
                  `telefono` VARCHAR(64) NOT NULL DEFAULT '',
                  `direccion` VARCHAR(255) NOT NULL DEFAULT '',
                  `especialidad` VARCHAR(180) NOT NULL DEFAULT 'Informática Forense y Evidencia Digital',
                  `civ` VARCHAR(64) NOT NULL DEFAULT '',
                  `inpre` VARCHAR(64) NOT NULL DEFAULT '',
                  `activo` TINYINT(1) NOT NULL DEFAULT 1,
                  `creado_en` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `actualizado_en` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                  PRIMARY KEY (`id`),
                  UNIQUE KEY `uk_usuarios_email` (`email`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ");

            $colsStmt = $pdo->query("SHOW COLUMNS FROM `usuarios`");
            $existingCols = $colsStmt ? array_column($colsStmt->fetchAll(), 'Field') : [];

            if (!in_array('last_login_at', $existingCols, true)) {
                $pdo->exec("ALTER TABLE `usuarios` ADD COLUMN `last_login_at` DATETIME DEFAULT NULL");
            }
            if (!in_array('last_login_ip', $existingCols, true)) {
                $pdo->exec("ALTER TABLE `usuarios` ADD COLUMN `last_login_ip` VARCHAR(45) DEFAULT NULL");
            }
            if (!in_array('direccion', $existingCols, true)) {
                $pdo->exec("ALTER TABLE `usuarios` ADD COLUMN `direccion` VARCHAR(255) NOT NULL DEFAULT '' AFTER `telefono`");
            }
            if (!in_array('especialidad', $existingCols, true)) {
                $pdo->exec("ALTER TABLE `usuarios` ADD COLUMN `especialidad` VARCHAR(180) NOT NULL DEFAULT 'Informática Forense y Evidencia Digital' AFTER `direccion`");
            }

            // 2. Tabla login_attempts (Rate Limiting)
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS `login_attempts` (
                  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                  `ip` VARCHAR(45) NOT NULL,
                  `usuario` VARCHAR(191) NOT NULL,
                  `intentado_en` DATETIME NOT NULL,
                  `exitoso` TINYINT(1) NOT NULL DEFAULT 0,
                  PRIMARY KEY (`id`),
                  KEY `idx_ip_intentos` (`ip`, `intentado_en`),
                  KEY `idx_usuario_intentos` (`usuario`, `intentado_en`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ");

            // 2b. Tabla email_otp_tokens (Códigos OTP de 6 dígitos + Enlaces Mágicos por Correo)
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS `email_otp_tokens` (
                  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                  `usuario_id` VARCHAR(64) NOT NULL,
                  `email` VARCHAR(191) NOT NULL,
                  `otp_hash` CHAR(64) NOT NULL,
                  `magic_token_hash` CHAR(64) NOT NULL,
                  `attempts` TINYINT UNSIGNED NOT NULL DEFAULT 0,
                  `max_attempts` TINYINT UNSIGNED NOT NULL DEFAULT 5,
                  `ip_solicitud` VARCHAR(45) NOT NULL DEFAULT '',
                  `expires_at` DATETIME NOT NULL,
                  `consumed_at` DATETIME DEFAULT NULL,
                  `creado_en` DATETIME NOT NULL,
                  PRIMARY KEY (`id`),
                  UNIQUE KEY `uk_email_otp_magic` (`magic_token_hash`),
                  KEY `idx_email_otp_email_exp` (`email`, `expires_at`),
                  KEY `idx_email_otp_usuario` (`usuario_id`, `creado_en`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ");

            // 2c. Tabla planillas_emitidas
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS `planillas_emitidas` (
                  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                  `codigo_planilla` VARCHAR(32) NOT NULL,
                  `planilla_slug` VARCHAR(80) NOT NULL,
                  `codigo_doc` VARCHAR(32) NOT NULL DEFAULT 'FO-FOR-01',
                  `titulo_planilla` VARCHAR(255) NOT NULL,
                  `fase_iso` VARCHAR(8) NOT NULL DEFAULT 'F0',
                  `caso_id` VARCHAR(64) DEFAULT NULL,
                  `numero_caso` VARCHAR(64) DEFAULT NULL,
                  `numero_prcc` VARCHAR(64) DEFAULT NULL,
                  `perito_usuario_id` VARCHAR(64) NOT NULL,
                  `perito_nombre` VARCHAR(200) NOT NULL,
                  `perito_ci` VARCHAR(32) NOT NULL DEFAULT '',
                  `perito_civ` VARCHAR(64) NOT NULL DEFAULT '',
                  `perito_inpre` VARCHAR(64) NOT NULL DEFAULT '',
                  `perito_cargo` VARCHAR(150) NOT NULL DEFAULT '',
                  `perito_organismo` VARCHAR(150) NOT NULL DEFAULT 'Laboratorio Privado SHA256.US',
                  `co_perito_nombre` VARCHAR(200) DEFAULT NULL,
                  `co_perito_civ` VARCHAR(64) DEFAULT NULL,
                  `modalidad_firma` ENUM('adobe_electronica', 'manual_autografa', 'hibrida') NOT NULL DEFAULT 'hibrida',
                  `estado_firma` ENUM('PENDIENTE_FIRMA', 'FIRMADA_ADOBE', 'FIRMADA_MANUAL', 'FIRMADA_HIBRIDA', 'REVOCADA') NOT NULL DEFAULT 'PENDIENTE_FIRMA',
                  `firmada_en` DATETIME DEFAULT NULL,
                  `hash_emision_sha256` CHAR(64) NOT NULL,
                  `hash_pdf_sha256` CHAR(64) DEFAULT NULL,
                  `hash_pdf_firmado_sha256` CHAR(64) DEFAULT NULL,
                  `auditoria_seq` BIGINT UNSIGNED DEFAULT NULL,
                  `ip_emision` VARCHAR(45) DEFAULT NULL,
                  `emitido_en_utc` VARCHAR(35) NOT NULL,
                  `creado_en` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `actualizado_en` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                  PRIMARY KEY (`id`),
                  UNIQUE KEY `uk_planillas_codigo` (`codigo_planilla`),
                  KEY `idx_planillas_caso` (`caso_id`),
                  KEY `idx_planillas_perito` (`perito_usuario_id`),
                  KEY `idx_planillas_hash_emision` (`hash_emision_sha256`),
                  KEY `idx_planillas_hash_pdf` (`hash_pdf_sha256`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ");

            // 3. Semilla idempotente de los 2 peritos oficiales (sin contraseñas locales)
            $pdo->exec("
                INSERT INTO `usuarios` (`id`, `email`, `password_hash`, `totp_secret`, `totp_enabled`, `nombre`, `apellido`, `ci`, `cargo`, `rol`, `organismo`, `despacho`, `telefono`, `civ`, `inpre`, `activo`)
                VALUES
                (
                  'usr-jull-01',
                  'julljoll@gmail.com',
                  '!DISABLED_EMAIL_OTP_ONLY!',
                  NULL,
                  0,
                  'Jull',
                  'Joll',
                  'V-18.999.001',
                  'Perito Analizador de Datos Forenses',
                  'admin',
                  'Laboratorio Privado SHA256.US',
                  'Área de Análisis e Interpretación (F3/F4)',
                  '+58 412-0000000',
                  'CIV-299410',
                  'INPRE-184920',
                  1
                ),
                (
                  'usr-sha256-02',
                  'sha256.us@gmail.com',
                  '!DISABLED_EMAIL_OTP_ONLY!',
                  NULL,
                  0,
                  'SHA256',
                  'Adquisición',
                  'V-15.816.003',
                  'Encargado de la Etapa de Adquisición',
                  'perito_lider',
                  'Laboratorio Privado SHA256.US',
                  'Área de Adquisición y Cadena de Custodia (F1/F2)',
                  '+58 414-0000000',
                  'CIV-310520',
                  'INPRE-201450',
                  1
                )
                ON DUPLICATE KEY UPDATE
                  `password_hash` = '!DISABLED_EMAIL_OTP_ONLY!',
                  `activo` = 1;
            ");
        } catch (\Throwable $e) {
            error_log('[FCCO Schema Ensure Warning] ' . $e->getMessage());
        }
    }
}
