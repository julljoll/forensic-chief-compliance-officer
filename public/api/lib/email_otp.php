<?php
/**
 * SHA256.US — Autenticación Segura sin Contraseña: Código OTP de 6 Dígitos + Enlace Mágico por Correo
 *
 * Propiedades de seguridad forense:
 *  - Lista blanca inmutable de exactamente 2 correos de peritos (comparación en tiempo constante).
 *  - Código OTP de 6 dígitos CSPRNG + Token de Enlace Mágico de 256 bits CSPRNG.
 *  - Almacenamiento exclusivo de hashes SHA-256 en MySQL (`email_otp_tokens`); jamás texto plano.
 *  - Expiración estricta de 5 minutos (300 s) y consumo atómico de un solo uso (anti-replay).
 *  - Límite de 5 intentos por código, enfriamiento de 45 s entre reenvíos y tope de solicitudes cada 15 min.
 *
 * Cumplimiento: NIST SP 800-63B · OWASP ASVS v4.0.3 · ISO/IEC 27001 A.9.4.2
 */

declare(strict_types=1);

namespace Sha256\Auth;

use PDO;

class EmailOtpException extends \RuntimeException
{
    private string $errorCode;
    private int $retryAfterSeconds;

    public function __construct(string $message, string $errorCode = 'OTP_ERROR', int $retryAfterSeconds = 0)
    {
        parent::__construct($message);
        $this->errorCode = $errorCode;
        $this->retryAfterSeconds = $retryAfterSeconds;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function getRetryAfterSeconds(): int
    {
        return $this->retryAfterSeconds;
    }
}

class EmailOtp
{
    public const REQUIRED_WHITELIST_COUNT = 2;

    /**
     * Valida y normaliza la lista blanca inmutable estricta de exactamente 2 correos distintos de peritos.
     *
     * @return array{0: string, 1: string}
     */
    public static function validateAllowedEmails(mixed $allowedEmails): array
    {
        if (!is_array($allowedEmails)) {
            throw new EmailOtpException(
                'Configuración inválida: security.allowed_emails debe definir exactamente 2 correos de peritos.',
                'WHITELIST_INVALID'
            );
        }

        $normalized = [];
        foreach ($allowedEmails as $entry) {
            if (!is_string($entry)) {
                throw new EmailOtpException('Correo inválido en lista blanca.', 'WHITELIST_INVALID');
            }
            $clean = strtolower(trim($entry));
            if ($clean === '' || filter_var($clean, FILTER_VALIDATE_EMAIL) === false) {
                throw new EmailOtpException('Formato de correo inválido en lista blanca.', 'WHITELIST_INVALID');
            }
            if (!in_array($clean, $normalized, true)) {
                $normalized[] = $clean;
            }
        }

        if (count($normalized) !== self::REQUIRED_WHITELIST_COUNT) {
            throw new EmailOtpException(
                'Política de seguridad: la lista blanca debe contener exactamente 2 correos distintos de peritos.',
                'WHITELIST_COUNT_INVALID'
            );
        }

        return [$normalized[0], $normalized[1]];
    }

    /**
     * Comprueba en tiempo constante si un correo pertenece a la lista blanca de 2 peritos.
     */
    public static function isEmailWhitelisted(string $email, mixed $allowedEmails): bool
    {
        $whitelist = self::validateAllowedEmails($allowedEmails);
        $clean = strtolower(trim($email));
        if ($clean === '') {
            return false;
        }
        $match = false;
        foreach ($whitelist as $allowed) {
            if (hash_equals($allowed, $clean)) {
                $match = true;
            }
        }
        return $match;
    }

    /**
     * Genera un código OTP numérico de 6 dígitos con entropía CSPRNG.
     */
    public static function generateOtpCode(): string
    {
        return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Genera un token criptográfico de 256 bits (64 caracteres hex) para el enlace mágico de 1 clic.
     */
    public static function generateMagicToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Calcula hash SHA-256 con separación de dominio vinculado al correo para el código OTP de 6 dígitos.
     */
    public static function hashOtp(string $email, string $otpCode): string
    {
        $cleanEmail = strtolower(trim($email));
        $cleanCode = preg_replace('/\s+/', '', trim($otpCode)) ?? '';
        return hash('sha256', "sha256.us:email_otp:v1:{$cleanEmail}:{$cleanCode}");
    }

    /**
     * Calcula hash SHA-256 con separación de dominio para el token de enlace mágico.
     */
    public static function hashMagicToken(string $token): string
    {
        $cleanToken = strtolower(trim($token));
        return hash('sha256', "sha256.us:magic_link:v1:{$cleanToken}");
    }

    /**
     * Crea un nuevo reto de acceso (código OTP de 6 dígitos + enlace mágico de 256 bits),
     * invalidando retos anteriores pendientes y aplicando enfriamiento + límite de solicitudes.
     *
     * @return array{id: int, otp_code: string, magic_token: string, expires_at: string, ttl_seconds: int}
     */
    public static function createChallenge(
        PDO $pdo,
        string $userId,
        string $email,
        string $ip,
        array $securityCfg,
        ?int $now = null
    ): array {
        $cleanEmail = strtolower(trim($email));
        $nowTs = $now ?? time();
        $ttl = max(60, (int)($securityCfg['otp_ttl_seconds'] ?? 300));
        $maxAttempts = max(3, (int)($securityCfg['otp_max_attempts'] ?? 5));
        $cooldown = max(0, (int)($securityCfg['otp_resend_cooldown'] ?? 45));
        $maxRequests15m = max(1, (int)($securityCfg['otp_max_requests_15m'] ?? 5));

        $nowStr = gmdate('Y-m-d H:i:s', $nowTs);
        $cutoff15m = gmdate('Y-m-d H:i:s', $nowTs - 900);

        // 1. Verificar cuota de emisiones en los últimos 15 minutos (anti email-bombing)
        $stmtCount = $pdo->prepare('
            SELECT COUNT(*) AS total
            FROM email_otp_tokens
            WHERE (email = :email OR ip_solicitud = :ip)
              AND creado_en >= :cutoff
        ');
        $stmtCount->execute([
            'email'  => $cleanEmail,
            'ip'     => $ip,
            'cutoff' => $cutoff15m,
        ]);
        $countRow = $stmtCount->fetch(PDO::FETCH_ASSOC);
        if ((int)($countRow['total'] ?? 0) >= $maxRequests15m) {
            throw new EmailOtpException(
                'Se alcanzó el máximo de códigos solicitados en 15 minutos. Espere unos minutos antes de solicitar otro.',
                'OTP_QUOTA_EXCEEDED',
                300
            );
        }

        // 2. Verificar enfriamiento mínimo entre reenvíos
        if ($cooldown > 0) {
            $stmtLast = $pdo->prepare('
                SELECT creado_en
                FROM email_otp_tokens
                WHERE email = :email
                ORDER BY id DESC
                LIMIT 1
            ');
            $stmtLast->execute(['email' => $cleanEmail]);
            $lastRow = $stmtLast->fetch(PDO::FETCH_ASSOC);
            if ($lastRow && !empty($lastRow['creado_en'])) {
                $lastTs = strtotime((string)$lastRow['creado_en'] . ' UTC');
                if ($lastTs !== false) {
                    $elapsed = $nowTs - $lastTs;
                    if ($elapsed >= 0 && $elapsed < $cooldown) {
                        $wait = $cooldown - $elapsed;
                        throw new EmailOtpException(
                            "Ya enviamos un código reciente a su correo. Espere {$wait} segundos para solicitar uno nuevo.",
                            'OTP_COOLDOWN',
                            $wait
                        );
                    }
                }
            }
        }

        $otpCode = self::generateOtpCode();
        $magicToken = self::generateMagicToken();
        $otpHash = self::hashOtp($cleanEmail, $otpCode);
        $magicHash = self::hashMagicToken($magicToken);
        $expiresAt = gmdate('Y-m-d H:i:s', $nowTs + $ttl);

        // 3. Invalidar cualquier reto previo sin consumir del mismo correo y guardar solo hashes SHA-256
        $startedTx = false;
        if (!$pdo->inTransaction()) {
            $pdo->beginTransaction();
            $startedTx = true;
        }

        try {
            $stmtInv = $pdo->prepare('
                UPDATE email_otp_tokens
                SET consumed_at = :now_str
                WHERE email = :email AND consumed_at IS NULL
            ');
            $stmtInv->execute([
                'now_str' => $nowStr,
                'email'   => $cleanEmail,
            ]);

            $stmtIns = $pdo->prepare('
                INSERT INTO email_otp_tokens (
                    usuario_id, email, otp_hash, magic_token_hash,
                    attempts, max_attempts, ip_solicitud, expires_at, consumed_at, creado_en
                ) VALUES (
                    :usuario_id, :email, :otp_hash, :magic_token_hash,
                    0, :max_attempts, :ip_solicitud, :expires_at, NULL, :creado_en
                )
            ');
            $stmtIns->execute([
                'usuario_id'       => $userId,
                'email'            => $cleanEmail,
                'otp_hash'         => $otpHash,
                'magic_token_hash' => $magicHash,
                'max_attempts'     => $maxAttempts,
                'ip_solicitud'     => $ip,
                'expires_at'       => $expiresAt,
                'creado_en'        => $nowStr,
            ]);

            $newId = (int)$pdo->lastInsertId();
            if ($startedTx) {
                $pdo->commit();
            }

            return [
                'id'          => $newId,
                'otp_code'    => $otpCode,
                'magic_token' => $magicToken,
                'expires_at'  => $expiresAt,
                'ttl_seconds' => $ttl,
            ];
        } catch (\Throwable $e) {
            if ($startedTx && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Verifica un código OTP de 6 dígitos para un correo dado y lo consume atómicamente (uso único).
     * Incrementa el contador de intentos fallidos e invalida el código al alcanzar `max_attempts`.
     *
     * @return array{ok: bool, usuario_id?: string, reason?: string}
     */
    public static function verifyOtp(
        PDO $pdo,
        string $email,
        string $otpCode,
        ?int $now = null
    ): array {
        $cleanEmail = strtolower(trim($email));
        $cleanCode = preg_replace('/\s+/', '', trim($otpCode)) ?? '';

        if (strlen($cleanCode) !== 6 || !ctype_digit($cleanCode)) {
            return ['ok' => false, 'reason' => 'INVALID_FORMAT'];
        }

        $nowTs = $now ?? time();
        $nowStr = gmdate('Y-m-d H:i:s', $nowTs);

        $stmt = $pdo->prepare('
            SELECT id, usuario_id, otp_hash, attempts, max_attempts, expires_at
            FROM email_otp_tokens
            WHERE email = :email
              AND consumed_at IS NULL
            ORDER BY id DESC
            LIMIT 1
        ');
        $stmt->execute(['email' => $cleanEmail]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return ['ok' => false, 'reason' => 'NO_ACTIVE_CHALLENGE'];
        }

        $expiresTs = strtotime((string)$row['expires_at'] . ' UTC');
        if ($expiresTs === false || $nowTs > $expiresTs) {
            // Expirado: marcar como consumido para limpieza
            $stmtExp = $pdo->prepare('UPDATE email_otp_tokens SET consumed_at = :now_str WHERE id = :id AND consumed_at IS NULL');
            $stmtExp->execute(['now_str' => $nowStr, 'id' => $row['id']]);
            return ['ok' => false, 'reason' => 'EXPIRED'];
        }

        $attempts = (int)$row['attempts'];
        $maxAttempts = (int)$row['max_attempts'];
        if ($attempts >= $maxAttempts) {
            $stmtLock = $pdo->prepare('UPDATE email_otp_tokens SET consumed_at = :now_str WHERE id = :id AND consumed_at IS NULL');
            $stmtLock->execute(['now_str' => $nowStr, 'id' => $row['id']]);
            return ['ok' => false, 'reason' => 'MAX_ATTEMPTS_EXCEEDED'];
        }

        $candidateHash = self::hashOtp($cleanEmail, $cleanCode);
        if (!hash_equals((string)$row['otp_hash'], $candidateHash)) {
            $newAttempts = $attempts + 1;
            if ($newAttempts >= $maxAttempts) {
                $stmtFail = $pdo->prepare('UPDATE email_otp_tokens SET attempts = :att, consumed_at = :now_str WHERE id = :id');
                $stmtFail->execute(['att' => $newAttempts, 'now_str' => $nowStr, 'id' => $row['id']]);
                return ['ok' => false, 'reason' => 'MAX_ATTEMPTS_EXCEEDED'];
            }
            $stmtFail = $pdo->prepare('UPDATE email_otp_tokens SET attempts = :att WHERE id = :id');
            $stmtFail->execute(['att' => $newAttempts, 'id' => $row['id']]);
            return ['ok' => false, 'reason' => 'CODE_MISMATCH'];
        }

        // Consumo atómico anti-replay (solo el primer proceso que actualice consumed_at IS NULL tiene éxito)
        $stmtConsume = $pdo->prepare('
            UPDATE email_otp_tokens
            SET consumed_at = :now_str
            WHERE id = :id AND consumed_at IS NULL
        ');
        $stmtConsume->execute([
            'now_str' => $nowStr,
            'id'      => $row['id'],
        ]);

        if ($stmtConsume->rowCount() !== 1) {
            return ['ok' => false, 'reason' => 'ALREADY_USED'];
        }

        return [
            'ok'         => true,
            'usuario_id' => (string)$row['usuario_id'],
        ];
    }

    /**
     * Verifica y consume atómicamente un token de enlace mágico de 1 clic (256 bits).
     *
     * @return array{ok: bool, usuario_id?: string, email?: string, reason?: string}
     */
    public static function verifyMagicToken(
        PDO $pdo,
        string $magicToken,
        ?int $now = null
    ): array {
        $cleanToken = strtolower(trim($magicToken));
        if (strlen($cleanToken) !== 64 || !ctype_xdigit($cleanToken)) {
            return ['ok' => false, 'reason' => 'INVALID_FORMAT'];
        }

        $nowTs = $now ?? time();
        $nowStr = gmdate('Y-m-d H:i:s', $nowTs);
        $tokenHash = self::hashMagicToken($cleanToken);

        $stmt = $pdo->prepare('
            SELECT id, usuario_id, email, expires_at, consumed_at
            FROM email_otp_tokens
            WHERE magic_token_hash = :hash
            LIMIT 1
        ');
        $stmt->execute(['hash' => $tokenHash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return ['ok' => false, 'reason' => 'NOT_FOUND'];
        }

        if (!empty($row['consumed_at'])) {
            return ['ok' => false, 'reason' => 'ALREADY_USED'];
        }

        $expiresTs = strtotime((string)$row['expires_at'] . ' UTC');
        if ($expiresTs === false || $nowTs > $expiresTs) {
            $stmtExp = $pdo->prepare('UPDATE email_otp_tokens SET consumed_at = :now_str WHERE id = :id AND consumed_at IS NULL');
            $stmtExp->execute(['now_str' => $nowStr, 'id' => $row['id']]);
            return ['ok' => false, 'reason' => 'EXPIRED'];
        }

        // Consumo atómico anti-replay
        $stmtConsume = $pdo->prepare('
            UPDATE email_otp_tokens
            SET consumed_at = :now_str
            WHERE id = :id AND consumed_at IS NULL
        ');
        $stmtConsume->execute([
            'now_str' => $nowStr,
            'id'      => $row['id'],
        ]);

        if ($stmtConsume->rowCount() !== 1) {
            return ['ok' => false, 'reason' => 'ALREADY_USED'];
        }

        return [
            'ok'         => true,
            'usuario_id' => (string)$row['usuario_id'],
            'email'      => strtolower(trim((string)$row['email'])),
        ];
    }
}
