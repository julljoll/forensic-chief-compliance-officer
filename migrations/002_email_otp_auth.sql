-- ==============================================================================
-- 🏛️ SHA256.US — Migración 002: Acceso Seguro por Código OTP (6 Dígitos) y Enlace Mágico por Correo
--
-- Migración idempotente para MySQL 5.7/8.0 y MariaDB (cPanel / phpMyAdmin).
-- Nota: `public/api/lib/db.php` también crea estas tablas/columnas automáticamente
--       al primer acceso si aún no existen.
-- ==============================================================================

SET NAMES utf8mb4;

-- 1. Tabla de Retos de Acceso por Correo (OTP 6 dígitos + Magic Link de un solo uso, TTL 5 min)
--    Solo almacena hashes SHA-256; jamás se guarda el código o token en texto plano.
CREATE TABLE IF NOT EXISTS `email_otp_tokens` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `usuario_id` VARCHAR(64) NOT NULL,
  `email` VARCHAR(191) NOT NULL,
  `otp_hash` CHAR(64) NOT NULL COMMENT 'SHA-256 con dominio de contexto del código de 6 dígitos',
  `magic_token_hash` CHAR(64) NOT NULL COMMENT 'SHA-256 del token de enlace mágico de 256 bits',
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

-- 2. Agregar columna last_login_at si no existe
SET @col_last_login_at := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'last_login_at'
);
SET @sql_last_login_at := IF(
  @col_last_login_at = 0,
  'ALTER TABLE `usuarios` ADD COLUMN `last_login_at` DATETIME DEFAULT NULL AFTER `totp_recovery_hashes`',
  'SELECT 1'
);
PREPARE stmt FROM @sql_last_login_at;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3. Agregar columna last_login_ip si no existe
SET @col_last_login_ip := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'last_login_ip'
);
SET @sql_last_login_ip := IF(
  @col_last_login_ip = 0,
  'ALTER TABLE `usuarios` ADD COLUMN `last_login_ip` VARCHAR(45) DEFAULT NULL AFTER `last_login_at`',
  'SELECT 1'
);
PREPARE stmt FROM @sql_last_login_ip;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 4. Deshabilitar permanentemente contraseñas locales
ALTER TABLE `usuarios`
  MODIFY COLUMN `password_hash` VARCHAR(255) NOT NULL DEFAULT '!DISABLED_EMAIL_OTP_ONLY!';

UPDATE `usuarios`
SET `password_hash` = '!DISABLED_EMAIL_OTP_ONLY!'
WHERE `password_hash` <> '!DISABLED_EMAIL_OTP_ONLY!';
