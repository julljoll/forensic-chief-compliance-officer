<?php
/**
 * SHA256.US — Verificador, Generador y Cifrador AES-256-GCM TOTP (RFC 6238 / RFC 4226)
 * para Google Authenticator.
 *
 * Cumplimiento: NIST SP 800-63B (AAL2) · RFC 6238 TOTP · RFC 4648 Base32 · NIST SP 800-38D (AES-256-GCM)
 */

declare(strict_types=1);

namespace Sha256\Auth;

class Totp
{
    private const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const RECOVERY_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    private const CIPHER_ALGO = 'aes-256-gcm';
    private const CIPHER_PREFIX = 'enc:v1:';
    private const CIPHER_AAD = 'sha256.us:totp_secret:v1';
    private const IV_LENGTH = 12;
    private const TAG_LENGTH = 16;

    /**
     * Decodifica una cadena Base32 estándar (RFC 4648).
     */
    public static function base32Decode(string $b32): string
    {
        $lut = [
            'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, 'E' => 4, 'F' => 5, 'G' => 6, 'H' => 7,
            'I' => 8, 'J' => 9, 'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15,
            'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23,
            'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29, '6' => 30, '7' => 31,
        ];
        $clean = strtoupper(trim($b32));
        $clean = preg_replace('/[\s=]/', '', $clean) ?? '';
        $n = 0;
        $j = 0;
        $binary = '';

        for ($i = 0, $len = strlen($clean); $i < $len; $i++) {
            $char = $clean[$i];
            if (!isset($lut[$char])) {
                continue;
            }
            $n = ($n << 5) | $lut[$char];
            $j += 5;
            if ($j >= 8) {
                $j -= 8;
                $binary .= chr(($n >> $j) & 0xFF);
            }
        }
        return $binary;
    }

    /**
     * Codifica una cadena binaria a Base32 estándar (RFC 4648).
     */
    public static function base32Encode(string $binary): string
    {
        $bits = 0;
        $value = 0;
        $output = '';

        for ($i = 0, $len = strlen($binary); $i < $len; $i++) {
            $value = ($value << 8) | ord($binary[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $output .= self::BASE32_CHARS[($value >> ($bits - 5)) & 31];
                $bits -= 5;
            }
        }

        if ($bits > 0) {
            $output .= self::BASE32_CHARS[($value << (5 - bits)) & 31];
        }

        return $output;
    }

    /**
     * Genera un secreto aleatorio CSPRNG de 160 bits (20 bytes) en Base32.
     */
    public static function generateSecret(int $byteLength = 20): string
    {
        $bytes = random_bytes($byteLength);
        return self::base32Encode($bytes);
    }

    /**
     * Construye la URI otpauth estándar para provisión en Google Authenticator (QR 100 % local).
     */
    public static function buildProvisioningUri(string $account, string $secret, string $issuer = 'SHA256.US'): string
    {
        $cleanUser = rawurlencode(trim($account));
        $cleanIssuer = rawurlencode(trim($issuer));
        $cleanSecret = strtoupper(preg_replace('/[\s=]/', '', $secret) ?? '');
        return "otpauth://totp/{$cleanIssuer}:{$cleanUser}?secret={$cleanSecret}&issuer={$cleanIssuer}&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * Parsea y valida la clave simétrica de 256 bits (32 bytes) para AES-256-GCM.
     * Admite 64 caracteres hexadecimales, prefijo "base64:..." o 32 bytes crudos.
     */
    public static function parseEncryptionKey(string $keyMaterial): string
    {
        $trimmed = trim($keyMaterial);
        if ($trimmed === '' || str_contains($trimmed, 'REEMPLAZAR')) {
            throw new \RuntimeException('Clave totp_encryption_key no configurada en config.local.php.');
        }

        if (str_starts_with($trimmed, 'base64:')) {
            $decoded = base64_decode(substr($trimmed, 7), true);
            if ($decoded === false || strlen($decoded) !== 32) {
                throw new \RuntimeException('Clave totp_encryption_key base64 inválida (debe decodificar a 32 bytes).');
            }
            return $decoded;
        }

        if (strlen($trimmed) === 64 && ctype_xdigit($trimmed)) {
            $bin = hex2bin($trimmed);
            if ($bin === false || strlen($bin) !== 32) {
                throw new \RuntimeException('Clave totp_encryption_key hexadecimal inválida.');
            }
            return $bin;
        }

        if (strlen($keyMaterial) === 32) {
            return $keyMaterial;
        }

        throw new \RuntimeException('Clave totp_encryption_key inválida: se requieren exactamente 32 bytes (64 hex o base64:...).');
    }

    /**
     * Indica si un valor almacenado en totp_secret ya está cifrado con AES-256-GCM (enc:v1:...).
     */
    public static function isEncryptedSecret(?string $value): bool
    {
        return is_string($value) && str_starts_with($value, self::CIPHER_PREFIX);
    }

    /**
     * Cifra el secreto TOTP en reposo con AES-256-GCM (IV aleatorio de 96 bits + Tag de 128 bits + AAD).
     */
    public static function encryptSecret(string $plaintextSecret, string $keyMaterial): string
    {
        $cleanSecret = strtoupper(trim($plaintextSecret));
        if ($cleanSecret === '') {
            throw new \InvalidArgumentException('No se puede cifrar un secreto TOTP vacío.');
        }

        $key = self::parseEncryptionKey($keyMaterial);
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $cleanSecret,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::CIPHER_AAD,
            self::TAG_LENGTH
        );

        if ($ciphertext === false || strlen($tag) !== self::TAG_LENGTH) {
            throw new \RuntimeException('Error interno al cifrar totp_secret con AES-256-GCM.');
        }

        return self::CIPHER_PREFIX . base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Descifra el secreto TOTP almacenado en reposo verificando la etiqueta de autenticación AES-256-GCM.
     */
    public static function decryptSecret(string $storedValue, string $keyMaterial): string
    {
        if (!self::isEncryptedSecret($storedValue)) {
            throw new \RuntimeException('Formato de totp_secret no cifrado o incompatible (se exige enc:v1: AES-256-GCM).');
        }

        $key = self::parseEncryptionKey($keyMaterial);
        $raw = base64_decode(substr($storedValue, strlen(self::CIPHER_PREFIX)), true);
        if ($raw === false || strlen($raw) <= (self::IV_LENGTH + self::TAG_LENGTH)) {
            throw new \RuntimeException('Payload cifrado de totp_secret truncado o corrupto.');
        }

        $iv = substr($raw, 0, self::IV_LENGTH);
        $tag = substr($raw, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($raw, self::IV_LENGTH + self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::CIPHER_AAD
        );

        if ($plaintext === false || $plaintext === '') {
            throw new \RuntimeException('Fallo de verificación de integridad AES-256-GCM al descifrar totp_secret.');
        }

        return $plaintext;
    }

    /**
     * Calcula el código TOTP de 6 dígitos para un paso temporal (timeSlice) dado (RFC 6238 / RFC 4226).
     */
    public static function getCode(string $secret, ?int $timeSlice = null): string
    {
        if ($timeSlice === null) {
            $timeSlice = (int)floor(time() / 30);
        }
        $key = self::base32Decode($secret);
        if ($key === '') {
            return '';
        }

        // Empaquetar contador de 64 bits en Big-Endian (RFC 4226)
        $high = ($timeSlice >> 32) & 0xFFFFFFFF;
        $low = $timeSlice & 0xFFFFFFFF;
        $time = pack('N2', $high, $low);
        $hm = hash_hmac('sha1', $time, $key, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart);
        $codeInt = ($value[1] & 0x7FFFFFFF) % 1000000;

        return str_pad((string)$codeInt, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Valida el código TOTP y devuelve el paso temporal (timeSlice) exacto para control anti-replay.
     *
     * @return int|null Devuelve el timeSlice válido si coincide, o null si es inválido
     */
    public static function verifyAndGetSlice(
        string $secret,
        string $code,
        int $window = 1,
        ?int $timestamp = null
    ): ?int {
        $code = preg_replace('/\s+/', '', trim($code)) ?? '';
        if (strlen($code) !== 6 || !ctype_digit($code)) {
            return null;
        }

        $now = $timestamp ?? time();
        $currentTimeSlice = (int)floor($now / 30);
        for ($offset = -$window; $offset <= $window; $offset++) {
            $slice = $currentTimeSlice + $offset;
            if ($slice < 0) {
                continue;
            }
            $calc = self::getCode($secret, $slice);
            if ($calc !== '' && hash_equals($calc, $code)) {
                return $slice;
            }
        }
        return null;
    }

    /**
     * Valida si un código de 6 dígitos coincide dentro de la ventana temporal.
     */
    public static function verify(string $secret, string $code, int $window = 1, ?int $timestamp = null): bool
    {
        return self::verifyAndGetSlice($secret, $code, $window, $timestamp) !== null;
    }

    /**
     * Genera N (por defecto 8) códigos de respaldo de un solo uso y sus hashes bcrypt.
     * Los códigos planos se entregan una sola vez al usuario; en MySQL solo se persisten los hashes bcrypt.
     *
     * @return array{plain: array<int, string>, hashes: array<int, string>}
     */
    public static function generateRecoveryCodes(int $count = 8): array
    {
        $charsetLen = strlen(self::RECOVERY_CHARSET);
        $plain = [];
        $hashes = [];
        $seen = [];

        while (count($plain) < $count) {
            $raw = '';
            for ($j = 0; $j < 8; $j++) {
                $raw .= self::RECOVERY_CHARSET[random_int(0, $charsetLen - 1)];
            }
            if (isset($seen[$raw])) {
                continue;
            }
            $seen[$raw] = true;
            $formatted = substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
            $plain[] = $formatted;
            $hashes[] = password_hash($raw, PASSWORD_BCRYPT);
        }

        return [
            'plain'  => $plain,
            'hashes' => $hashes,
        ];
    }

    /**
     * Verifica un código de recuperación de emergencia contra la lista de hashes bcrypt.
     * Devuelve el índice del hash coincidente para consumirlo/eliminarlo permanentemente.
     */
    public static function verifyRecoveryCode(string $code, array $recoveryHashes): ?int
    {
        $clean = strtoupper(preg_replace('/[^A-Z0-9]/', '', $code) ?? '');
        if (strlen($clean) !== 8) {
            return null;
        }

        foreach ($recoveryHashes as $idx => $hash) {
            if (is_string($hash) && $hash !== '' && password_verify($clean, $hash)) {
                return (int)$idx;
            }
        }
        return null;
    }
}
