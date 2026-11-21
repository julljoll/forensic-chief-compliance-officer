<?php
/**
 * SHA256.US — Verificador y Generador TOTP (RFC 6238 / RFC 4226) para Google Authenticator
 * Cumplimiento: NIST SP 800-63B (AAL2) · RFC 6238 TOTP · RFC 4648 Base32
 */

declare(strict_types=1);

namespace Sha256\Auth;

class Totp
{
    private const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Decodifica una cadena Base32 estándar (RFC 4648)
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
     * Codifica una cadena binaria a Base32 estándar (RFC 4648)
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
     * Genera un secreto aleatorio CSPRNG de 160 bits (20 bytes) en Base32
     */
    public static function generateSecret(int $byteLength = 20): string
    {
        $bytes = random_bytes($byteLength);
        return self::base32Encode($bytes);
    }

    /**
     * Construye la URI otpauth estándar para provisión en apps móviles
     */
    public static function buildProvisioningUri(string $account, string $secret, string $issuer = 'SHA256.US'): string
    {
        $cleanUser = rawurlencode(trim($account));
        $cleanIssuer = rawurlencode(trim($issuer));
        $cleanSecret = strtoupper(preg_replace('/[\s=]/', '', $secret) ?? '');
        return "otpauth://totp/{$cleanIssuer}:{$cleanUser}?secret={$cleanSecret}&issuer={$cleanIssuer}&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * Calcula el código TOTP de 6 dígitos para un timeSlice dado
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

        // Empaquetar timestamp de 64 bits en Big-Endian (RFC 4226)
        $time = pack('N*', 0) . pack('N*', $timeSlice);
        $hm = hash_hmac('sha1', $time, $key, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart);
        $value = $value[1] & 0x7FFFFFFF;

        return str_pad((string)($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Valida el código TOTP y devuelve el slice de tiempo específico validado
     * para prevenir ataques de repetición (Replay Attacks).
     *
     * @return int|null Devuelve el timeSlice válido si coincide, o null si es inválido
     */
    public static function verifyAndGetSlice(string $secret, string $code, int $window = 1): ?int
    {
        $code = trim($code);
        if (strlen($code) !== 6 || !ctype_digit($code)) {
            return null;
        }

        $currentTimeSlice = (int)floor(time() / 30);
        for ($offset = -$window; $offset <= $window; $offset++) {
            $slice = $currentTimeSlice + $offset;
            $calc = self::getCode($secret, $slice);
            if (hash_equals($calc, $code)) {
                return $slice;
            }
        }
        return null;
    }

    /**
     * Valida si un código de 6 dígitos coincide dentro de una ventana de tolerancia
     */
    public static function verify(string $secret, string $code, int $window = 1): bool
    {
        return self::verifyAndGetSlice($secret, $code, $window) !== null;
    }

    /**
     * Verifica un código de recuperación de emergencia contra una lista de hashes bcrypt
     * Devuelve el índice del hash coincidente para consumirlo / invalidarlo.
     */
    public static function verifyRecoveryCode(string $code, array $recoveryHashes): ?int
    {
        $clean = strtoupper(preg_replace('/[^A-Z0-9]/', '', $code) ?? '');
        if (strlen($clean) < 6) {
            return null;
        }

        foreach ($recoveryHashes as $idx => $hash) {
            if (password_verify($clean, (string)$hash)) {
                return (int)$idx;
            }
        }
        return null;
    }
}
