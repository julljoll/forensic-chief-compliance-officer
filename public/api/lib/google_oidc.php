<?php
/**
 * SHA256.US — Cliente y Verificador Criptográfico Google OAuth 2.0 / OpenID Connect (PHP Puro)
 *
 * Implementa Authorization Code Flow + PKCE S256 (RFC 7636) + state + nonce +
 * verificación criptográfica RS256 contra las claves públicas JWKS de Google,
 * ejecutado 100 % server-to-server sin cargar SDK JavaScript externos (CSP script-src 'self').
 *
 * Cumplimiento: OpenID Connect Core 1.0 · RFC 7636 (PKCE) · RFC 7515/7517/7519 (JWS/JWK/JWT)
 *               NIST SP 800-63B (AAL2/FAL2) · OWASP ASVS v4.0.3
 */

declare(strict_types=1);

namespace Sha256\Auth;

class GoogleOidcException extends \RuntimeException
{
    private string $errorCode;

    public function __construct(string $message, string $errorCode = 'OIDC_ERROR', ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->errorCode = $errorCode;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}

class GoogleOidc
{
    public const DEFAULT_AUTH_ENDPOINT  = 'https://accounts.google.com/o/oauth2/v2/auth';
    public const DEFAULT_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
    public const DEFAULT_JWKS_URI       = 'https://www.googleapis.com/oauth2/v3/certs';
    public const ALLOWED_ISSUERS        = ['https://accounts.google.com', 'accounts.google.com'];
    public const REQUIRED_WHITELIST_COUNT = 2;

    /**
     * Codificación Base64URL sin padding (RFC 4648 §5).
     */
    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decodificación estricta Base64URL (RFC 4648 §5).
     */
    public static function base64UrlDecode(string $data): string
    {
        $b64 = strtr($data, '-_', '+/');
        $padLen = (4 - (strlen($b64) % 4)) % 4;
        if ($padLen > 0) {
            $b64 .= str_repeat('=', $padLen);
        }
        $decoded = base64_decode($b64, true);
        if ($decoded === false) {
            throw new GoogleOidcException('Codificación Base64URL inválida', 'INVALID_BASE64URL');
        }
        return $decoded;
    }

    /**
     * Genera par PKCE S256 (RFC 7636): verifier (256 bits) y challenge SHA-256 Base64URL.
     *
     * @return array{verifier: string, challenge: string, method: string}
     */
    public static function generatePkcePair(): array
    {
        $verifier = self::base64UrlEncode(random_bytes(32));
        $challenge = self::base64UrlEncode(hash('sha256', $verifier, true));
        return [
            'verifier'  => $verifier,
            'challenge' => $challenge,
            'method'    => 'S256',
        ];
    }

    /**
     * Genera parámetro state CSPRNG de 256 bits anti-CSRF OAuth.
     */
    public static function generateState(): string
    {
        return self::base64UrlEncode(random_bytes(32));
    }

    /**
     * Genera parámetro nonce CSPRNG de 256 bits anti-replay de ID Token.
     */
    public static function generateNonce(): string
    {
        return self::base64UrlEncode(random_bytes(32));
    }

    /**
     * Valida y normaliza la lista blanca inmutable estricta de exactamente 2 correos de peritos.
     * Falla en modo fail-closed si no contiene exactamente 2 correos válidos y distintos.
     *
     * @param mixed $allowedEmails
     * @return array{0: string, 1: string}
     */
    public static function validateAllowedEmails(mixed $allowedEmails): array
    {
        if (!is_array($allowedEmails)) {
            throw new GoogleOidcException(
                'Configuración inválida: security.allowed_emails debe ser un arreglo con exactamente 2 correos.',
                'WHITELIST_INVALID'
            );
        }

        $normalized = [];
        foreach ($allowedEmails as $entry) {
            if (!is_string($entry)) {
                throw new GoogleOidcException('Correo inválido en lista blanca.', 'WHITELIST_INVALID');
            }
            $clean = strtolower(trim($entry));
            if ($clean === '' || filter_var($clean, FILTER_VALIDATE_EMAIL) === false) {
                throw new GoogleOidcException('Formato de correo inválido en lista blanca.', 'WHITELIST_INVALID');
            }
            if (!in_array($clean, $normalized, true)) {
                $normalized[] = $clean;
            }
        }

        if (count($normalized) !== self::REQUIRED_WHITELIST_COUNT) {
            throw new GoogleOidcException(
                'Política de Grado Forense: la lista blanca inmutable debe contener exactamente 2 correos distintos de peritos.',
                'WHITELIST_COUNT_INVALID'
            );
        }

        return [$normalized[0], $normalized[1]];
    }

    /**
     * Verifica en tiempo constante si un correo pertenece a la lista blanca de 2 peritos.
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
     * Construye la URL de autorización OAuth 2.0 / OIDC de Google con PKCE S256, state y nonce.
     */
    public static function buildAuthorizationUrl(
        array $googleCfg,
        string $state,
        string $nonce,
        string $codeChallenge
    ): string {
        $clientId = trim((string)($googleCfg['client_id'] ?? ''));
        $redirectUri = trim((string)($googleCfg['redirect_uri'] ?? ''));
        $authEndpoint = trim((string)($googleCfg['auth_endpoint'] ?? self::DEFAULT_AUTH_ENDPOINT));

        if ($clientId === '' || str_starts_with($clientId, 'REEMPLAZAR') || $redirectUri === '') {
            throw new GoogleOidcException(
                'Google OIDC no configurado en config.local.php (client_id / redirect_uri).',
                'OAUTH_NOT_CONFIGURED'
            );
        }

        $params = [
            'client_id'             => $clientId,
            'redirect_uri'          => $redirectUri,
            'response_type'         => 'code',
            'scope'                 => 'openid email profile',
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => $codeChallenge,
            'code_challenge_method' => 'S256',
            'prompt'                => 'select_account',
            'access_type'           => 'online',
        ];

        return $authEndpoint . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Intercambia el authorization code + PKCE code_verifier server-to-server en el Token Endpoint de Google.
     *
     * @return array<string, mixed>
     */
    public static function exchangeCodeForTokens(
        array $googleCfg,
        string $code,
        string $codeVerifier
    ): array {
        $clientId = trim((string)($googleCfg['client_id'] ?? ''));
        $clientSecret = trim((string)($googleCfg['client_secret'] ?? ''));
        $redirectUri = trim((string)($googleCfg['redirect_uri'] ?? ''));
        $tokenEndpoint = trim((string)($googleCfg['token_endpoint'] ?? self::DEFAULT_TOKEN_ENDPOINT));

        if (
            $clientId === '' || str_starts_with($clientId, 'REEMPLAZAR') ||
            $clientSecret === '' || str_contains($clientSecret, 'REEMPLAZAR') ||
            $redirectUri === ''
        ) {
            throw new GoogleOidcException(
                'Credenciales OAuth 2.0 de Google incompletas en config.local.php.',
                'OAUTH_NOT_CONFIGURED'
            );
        }

        $postFields = http_build_query([
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
            'redirect_uri'  => $redirectUri,
            'code_verifier' => $codeVerifier,
        ], '', '&', PHP_QUERY_RFC3986);

        $ch = curl_init($tokenEndpoint);
        if ($ch === false) {
            throw new GoogleOidcException('No se pudo inicializar cURL para intercambio OIDC.', 'CURL_INIT_ERROR');
        }

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $postFields,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'],
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $responseBody = curl_exec($ch);
        $curlErr = curl_error($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($responseBody === false || $curlErr !== '') {
            throw new GoogleOidcException('Error de transporte TLS al contactar Google Token Endpoint: ' . $curlErr, 'TOKEN_HTTP_ERROR');
        }

        $decoded = json_decode((string)$responseBody, true);
        if ($httpCode !== 200 || !is_array($decoded) || empty($decoded['id_token'])) {
            $errCode = is_array($decoded) ? (string)($decoded['error'] ?? 'token_exchange_failed') : 'invalid_json';
            throw new GoogleOidcException("Intercambio OAuth rechazado por Google (HTTP {$httpCode}: {$errCode}).", 'TOKEN_EXCHANGE_FAILED');
        }

        return $decoded;
    }

    /**
     * Obtiene el conjunto de claves públicas JWKS de Google con caché en disco y verificación TLS.
     *
     * @return array{keys: array<int, array<string, mixed>>}
     */
    public static function fetchJwks(
        string $jwksUri = self::DEFAULT_JWKS_URI,
        ?string $cachePath = null,
        int $ttlSeconds = 3600,
        bool $forceRefresh = false
    ): array {
        if (!$forceRefresh && $cachePath !== null && is_file($cachePath)) {
            $age = time() - (int)filemtime($cachePath);
            if ($age >= 0 && $age < $ttlSeconds) {
                $cachedRaw = @file_get_contents($cachePath);
                $cached = $cachedRaw !== false ? json_decode($cachedRaw, true) : null;
                if (is_array($cached) && isset($cached['keys']) && is_array($cached['keys']) && count($cached['keys']) > 0) {
                    return $cached;
                }
            }
        }

        $ch = curl_init($jwksUri);
        if ($ch === false) {
            throw new GoogleOidcException('No se pudo inicializar cURL para JWKS.', 'JWKS_CURL_ERROR');
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $responseBody = curl_exec($ch);
        $curlErr = curl_error($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($responseBody === false || $curlErr !== '' || $httpCode !== 200) {
            throw new GoogleOidcException("No se pudo descargar JWKS de Google (HTTP {$httpCode}): {$curlErr}", 'JWKS_FETCH_FAILED');
        }

        $jwks = json_decode((string)$responseBody, true);
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys']) || count($jwks['keys']) === 0) {
            throw new GoogleOidcException('Respuesta JWKS de Google inválida o vacía.', 'JWKS_INVALID');
        }

        if ($cachePath !== null) {
            @file_put_contents($cachePath, (string)$responseBody, LOCK_EX);
        }

        return $jwks;
    }

    /**
     * Convierte una clave pública JWK RSA (n, e) a formato PEM SubjectPublicKeyInfo (X.509 / PKCS#1)
     * usando codificación ASN.1 DER en PHP puro sin dependencias externas.
     */
    public static function jwkToPem(array $jwk): string
    {
        if (($jwk['kty'] ?? '') !== 'RSA' || empty($jwk['n']) || empty($jwk['e'])) {
            throw new GoogleOidcException('JWK inválido: se requiere clave pública RSA con parámetros n y e.', 'JWK_INVALID');
        }

        $modulus = self::base64UrlDecode((string)$jwk['n']);
        $exponent = self::base64UrlDecode((string)$jwk['e']);

        if ($modulus === '' || $exponent === '') {
            throw new GoogleOidcException('Parámetros RSA n/e vacíos en JWK.', 'JWK_INVALID');
        }

        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        $rsaPublicKey = self::derSequence(
            self::derInteger($modulus) . self::derInteger($exponent)
        );

        // AlgorithmIdentifier para rsaEncryption (OID 1.2.840.113549.1.1.1) + NULL
        $rsaAlgId = hex2bin('300d06092a864886f70d0101010500');
        if ($rsaAlgId === false) {
            throw new GoogleOidcException('Error interno al construir AlgorithmIdentifier RSA.', 'JWK_INTERNAL');
        }

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
        $spki = self::derSequence($rsaAlgId . self::derBitString($rsaPublicKey));

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        $keyResource = openssl_pkey_get_public($pem);
        if ($keyResource === false) {
            throw new GoogleOidcException('Clave PEM derivada del JWK no pudo ser cargada por OpenSSL.', 'JWK_PEM_INVALID');
        }

        return $pem;
    }

    /**
     * Verifica criptográficamente un ID Token JWT de Google (RS256 + JWKS + claims OIDC completos).
     *
     * @param string   $idToken          JWT compacto header.payload.signature
     * @param array    $jwks             Arreglo JWKS con clave 'keys'
     * @param string   $expectedClientId Client ID OAuth esperado (aud)
     * @param string   $expectedNonce    Nonce generado en sesión al iniciar login
     * @param int|null $now              Timestamp Unix actual (inyectable en pruebas unitarias)
     * @param int      $clockSkew        Tolerancia de reloj en segundos (default 60s)
     * @return array<string, mixed>      Claims validados (sub, email, email_verified, name, etc.)
     */
    public static function verifyIdToken(
        string $idToken,
        array $jwks,
        string $expectedClientId,
        string $expectedNonce,
        ?int $now = null,
        int $clockSkew = 60
    ): array {
        $nowTs = $now ?? time();

        $parts = explode('.', trim($idToken));
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw new GoogleOidcException('Estructura de ID Token JWT inválida.', 'JWT_MALFORMED');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $header = json_decode(self::base64UrlDecode($headerB64), true);
        if (!is_array($header)) {
            throw new GoogleOidcException('Encabezado JWT inválido.', 'JWT_HEADER_INVALID');
        }

        // Prevención estricta contra ataques alg=none y algorithm confusion (HS256)
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new GoogleOidcException('Algoritmo JWT no permitido: se exige estrictamente RS256.', 'JWT_ALG_INVALID');
        }

        $kid = isset($header['kid']) && is_string($header['kid']) ? trim($header['kid']) : '';
        if ($kid === '') {
            throw new GoogleOidcException('El encabezado JWT carece de kid.', 'JWT_KID_MISSING');
        }

        // Buscar clave pública correspondiente al kid en JWKS
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys) || count($keys) === 0) {
            throw new GoogleOidcException('Conjunto JWKS vacío.', 'JWKS_EMPTY');
        }

        $matchedJwk = null;
        foreach ($keys as $candidate) {
            if (!is_array($candidate) || !isset($candidate['kid']) || !is_string($candidate['kid'])) {
                continue;
            }
            if (!hash_equals($candidate['kid'], $kid)) {
                continue;
            }
            if (($candidate['kty'] ?? '') !== 'RSA') {
                continue;
            }
            if (isset($candidate['use']) && $candidate['use'] !== 'sig') {
                continue;
            }
            if (isset($candidate['alg']) && $candidate['alg'] !== 'RS256') {
                continue;
            }
            $matchedJwk = $candidate;
            break;
        }

        if ($matchedJwk === null) {
            throw new GoogleOidcException("Clave pública JWKS no encontrada para kid={$kid}.", 'JWKS_KID_NOT_FOUND');
        }

        $pem = self::jwkToPem($matchedJwk);
        $pubKey = openssl_pkey_get_public($pem);
        if ($pubKey === false) {
            throw new GoogleOidcException('No se pudo cargar la clave pública RSA.', 'JWKS_KEY_LOAD_ERROR');
        }

        $signingInput = $headerB64 . '.' . $payloadB64;
        $signature = self::base64UrlDecode($signatureB64);

        $verified = openssl_verify($signingInput, $signature, $pubKey, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            throw new GoogleOidcException('Firma criptográfica RS256 del ID Token inválida.', 'JWT_SIGNATURE_INVALID');
        }

        $payload = json_decode(self::base64UrlDecode($payloadB64), true);
        if (!is_array($payload)) {
            throw new GoogleOidcException('Payload del ID Token inválido.', 'JWT_PAYLOAD_INVALID');
        }

        // 1. Verificar emisor (iss)
        $iss = $payload['iss'] ?? null;
        if (!is_string($iss) || !in_array($iss, self::ALLOWED_ISSUERS, true)) {
            throw new GoogleOidcException('Emisor (iss) del ID Token no autorizado.', 'JWT_ISS_INVALID');
        }

        // 2. Verificar audiencia (aud) y parte autorizada (azp si aud es lista)
        $aud = $payload['aud'] ?? null;
        $audValid = false;
        if (is_string($aud)) {
            $audValid = hash_equals($expectedClientId, $aud);
        } elseif (is_array($aud)) {
            $azp = $payload['azp'] ?? null;
            $inAud = false;
            foreach ($aud as $a) {
                if (is_string($a) && hash_equals($expectedClientId, $a)) {
                    $inAud = true;
                    break;
                }
            }
            $audValid = $inAud && is_string($azp) && hash_equals($expectedClientId, $azp);
        }
        if (!$audValid) {
            throw new GoogleOidcException('Audiencia (aud) del ID Token no coincide con client_id.', 'JWT_AUD_INVALID');
        }

        // 3. Verificar expiración (exp), emisión (iat) y vigencia (nbf)
        $exp = $payload['exp'] ?? null;
        $iat = $payload['iat'] ?? null;
        if (!is_int($exp) || $nowTs > ($exp + $clockSkew)) {
            throw new GoogleOidcException('El ID Token ha expirado (exp).', 'JWT_EXPIRED');
        }
        if (!is_int($iat) || $iat > ($nowTs + $clockSkew) || ($nowTs - $iat) > 86400) {
            throw new GoogleOidcException('Marca temporal iat del ID Token fuera de ventana permitida.', 'JWT_IAT_INVALID');
        }
        if (isset($payload['nbf'])) {
            if (!is_int($payload['nbf']) || $payload['nbf'] > ($nowTs + $clockSkew)) {
                throw new GoogleOidcException('El ID Token aún no es válido (nbf).', 'JWT_NBF_INVALID');
            }
        }

        // 4. Verificar nonce anti-replay en tiempo constante
        $nonce = $payload['nonce'] ?? null;
        if (!is_string($nonce) || $nonce === '' || $expectedNonce === '' || !hash_equals($expectedNonce, $nonce)) {
            throw new GoogleOidcException('El nonce del ID Token no coincide con el estado de sesión.', 'JWT_NONCE_MISMATCH');
        }

        // 5. Verificar claim inmutable sub
        $sub = isset($payload['sub']) && is_string($payload['sub']) ? trim($payload['sub']) : '';
        if ($sub === '' || strlen($sub) > 64) {
            throw new GoogleOidcException('Claim inmutable sub inválido o ausente.', 'JWT_SUB_INVALID');
        }

        // 6. Verificar email y email_verified estrictamente booleano true
        $email = isset($payload['email']) && is_string($payload['email']) ? strtolower(trim($payload['email'])) : '';
        if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new GoogleOidcException('Claim email inválido o ausente en el ID Token.', 'JWT_EMAIL_INVALID');
        }
        if (($payload['email_verified'] ?? null) !== true) {
            throw new GoogleOidcException('La cuenta Google no posee correo electrónico verificado (email_verified !== true).', 'JWT_EMAIL_UNVERIFIED');
        }

        return [
            'sub'            => $sub,
            'email'          => $email,
            'email_verified' => true,
            'name'           => isset($payload['name']) && is_string($payload['name']) ? trim($payload['name']) : '',
            'given_name'     => isset($payload['given_name']) && is_string($payload['given_name']) ? trim($payload['given_name']) : '',
            'family_name'    => isset($payload['family_name']) && is_string($payload['family_name']) ? trim($payload['family_name']) : '',
            'iss'            => $iss,
            'aud'            => $expectedClientId,
            'iat'            => $iat,
            'exp'            => $exp,
            'nonce'          => $nonce,
        ];
    }

    /**
     * Codifica longitud ASN.1 DER (forma corta o larga).
     */
    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Codifica un entero positivo sin signo como ASN.1 DER INTEGER.
     */
    private static function derInteger(string $unsignedBytes): string
    {
        $bytes = ltrim($unsignedBytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    /**
     * Codifica contenido como ASN.1 DER SEQUENCE.
     */
    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    /**
     * Codifica contenido como ASN.1 DER BIT STRING (0 bits sin usar).
     */
    private static function derBitString(string $content): string
    {
        return "\x03" . self::derLength(strlen($content) + 1) . "\x00" . $content;
    }
}
