<?php
/**
 * SHA256.US — Inicio de Flujo Google OAuth 2.0 / OIDC (Authorization Code + PKCE S256 + state + nonce)
 *
 * Ejecutado 100 % en servidor PHP puro sin dependencias JavaScript externas (CSP script-src 'self').
 */

declare(strict_types=1);

header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');

require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/google_oidc.php';

use Sha256\Auth\GoogleOidc;
use Sha256\Auth\GoogleOidcException;
use Sha256\Auth\Session;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'Método no permitido. Use GET.'], JSON_UNESCAPED_UNICODE);
    exit;
}

Session::start();
$config = Session::getConfig();

try {
    // Validar fail-closed que la lista blanca de exactamente 2 peritos esté configurada antes de iniciar OAuth
    GoogleOidc::validateAllowedEmails($config['security']['allowed_emails'] ?? null);

    $googleCfg = $config['google_oidc'] ?? [];
    if (
        empty($googleCfg['client_id']) || str_starts_with((string)$googleCfg['client_id'], 'REEMPLAZAR') ||
        empty($googleCfg['client_secret']) || str_contains((string)$googleCfg['client_secret'], 'REEMPLAZAR') ||
        empty($googleCfg['redirect_uri'])
    ) {
        throw new GoogleOidcException('Credenciales Google OIDC no configuradas en config.local.php.', 'OAUTH_NOT_CONFIGURED');
    }

    $pkce = GoogleOidc::generatePkcePair();
    $state = GoogleOidc::generateState();
    $nonce = GoogleOidc::generateNonce();

    // Limpiar cualquier estado pendiente previo antes de iniciar un nuevo flujo OIDC
    Session::clearPendingMfa();

    $_SESSION['oidc_auth'] = [
        'state'         => $state,
        'nonce'         => $nonce,
        'code_verifier' => $pkce['verifier'],
        'created_at'    => time(),
    ];

    $authUrl = GoogleOidc::buildAuthorizationUrl($googleCfg, $state, $nonce, $pkce['challenge']);
    header('Location: ' . $authUrl, true, 302);
    exit;
} catch (GoogleOidcException $e) {
    error_log('[FCCO OIDC Start Error] ' . $e->getErrorCode() . ': ' . $e->getMessage());
    $msg = str_starts_with($e->getErrorCode(), 'WHITELIST') ? 'config_whitelist_invalida' : 'oauth_no_configurado';
    header('Location: /?msg=' . rawurlencode($msg), true, 302);
    exit;
} catch (\Throwable $e) {
    error_log('[FCCO OIDC Start Fatal] ' . $e->getMessage());
    header('Location: /?msg=oauth_no_configurado', true, 302);
    exit;
}
