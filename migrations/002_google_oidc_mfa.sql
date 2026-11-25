-- ==============================================================================
-- 🏛️ SHA256.US — Migración 002: Seguridad de Inicio de Sesión (Opción C — Grado Forense)
-- Google OIDC (Authorization Code + PKCE S256 + RS256 JWKS) + TOTP RFC 6238 Obligatorio
--
-- Migración idempotente para MySQL 5.7/8.0 y MariaDB (cPanel / phpMyAdmin).
-- Agrega: google_sub (UNIQUE), totp_enrolled_at, totp_last_step, last_login_at,
--         last_login_ip; amplía totp_secret a VARCHAR(255) para AES-256-GCM;
--         deshabilita hashes de contraseñas locales.
-- ==============================================================================

SET NAMES utf8mb4;

-- 1. Ampliar totp_secret a VARCHAR(255) para almacenar texto cifrado AES-256-GCM (enc:v1:...)
ALTER TABLE `usuarios`
  MODIFY COLUMN `totp_secret` VARCHAR(255) DEFAULT NULL COMMENT 'Secreto TOTP cifrado en reposo con AES-256-GCM (enc:v1:...)';

-- 2. Agregar columna google_sub (claim inmutable sub de Google OIDC) si no existe
SET @col_google_sub := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'google_sub'
);
SET @sql_google_sub := IF(
  @col_google_sub = 0,
  "ALTER TABLE `usuarios` ADD COLUMN `google_sub` VARCHAR(64) DEFAULT NULL COMMENT 'Claim inmutable sub de Google OIDC vinculado permanentemente' AFTER `email`",
  'SELECT 1'
);
PREPARE stmt FROM @sql_google_sub;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3. Índice único uk_usuarios_google_sub si no existe
SET @idx_google_sub := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND INDEX_NAME = 'uk_usuarios_google_sub'
);
SET @sql_idx_google_sub := IF(
  @idx_google_sub = 0,
  'ALTER TABLE `usuarios` ADD UNIQUE KEY `uk_usuarios_google_sub` (`google_sub`)',
  'SELECT 1'
);
PREPARE stmt FROM @sql_idx_google_sub;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 4. Agregar columna totp_enrolled_at si no existe
SET @col_totp_enrolled_at := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'totp_enrolled_at'
);
SET @sql_totp_enrolled_at := IF(
  @col_totp_enrolled_at = 0,
  'ALTER TABLE `usuarios` ADD COLUMN `totp_enrolled_at` DATETIME DEFAULT NULL AFTER `totp_enabled`',
  'SELECT 1'
);
PREPARE stmt FROM @sql_totp_enrolled_at;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 5. Agregar columna totp_last_step (anti-replay) si no existe y migrar totp_last_used_slice si existía
SET @col_totp_last_step := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'totp_last_step'
);
SET @sql_totp_last_step := IF(
  @col_totp_last_step = 0,
  "ALTER TABLE `usuarios` ADD COLUMN `totp_last_step` BIGINT NULL DEFAULT NULL COMMENT 'Último paso temporal de 30s aceptado (anti-replay)' AFTER `totp_enrolled_at`",
  'SELECT 1'
);
PREPARE stmt FROM @sql_totp_last_step;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_legacy_slice := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'totp_last_used_slice'
);
SET @sql_copy_slice := IF(
  @col_legacy_slice > 0,
  'UPDATE `usuarios` SET `totp_last_step` = `totp_last_used_slice` WHERE `totp_last_step` IS NULL AND `totp_last_used_slice` IS NOT NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql_copy_slice;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 6. Agregar columna totp_recovery_hashes si no existe
SET @col_recovery := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'totp_recovery_hashes'
);
SET @sql_recovery := IF(
  @col_recovery = 0,
  'ALTER TABLE `usuarios` ADD COLUMN `totp_recovery_hashes` TEXT NULL DEFAULT NULL AFTER `totp_last_step`',
  'SELECT 1'
);
PREPARE stmt FROM @sql_recovery;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 7. Agregar columna last_login_at si no existe
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

-- 8. Agregar columna last_login_ip si no existe
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

-- 9. Invalidar contraseñas locales (inicio de sesión por contraseña deshabilitado permanentemente)
ALTER TABLE `usuarios`
  MODIFY COLUMN `password_hash` VARCHAR(255) NOT NULL DEFAULT '!DISABLED_GOOGLE_OIDC_ONLY!';

UPDATE `usuarios`
SET `password_hash` = '!DISABLED_GOOGLE_OIDC_ONLY!'
WHERE `password_hash` <> '!DISABLED_GOOGLE_OIDC_ONLY!';

-- 10. Forzar re-enrolamiento TOTP cifrado AES-256-GCM si quedara algún secreto sin cifrar (sin prefijo enc:v1:)
UPDATE `usuarios`
SET `totp_secret` = NULL,
    `totp_enabled` = 0,
    `totp_enrolled_at` = NULL
WHERE `totp_secret` IS NOT NULL
  AND `totp_secret` NOT LIKE 'enc:v1:%';
