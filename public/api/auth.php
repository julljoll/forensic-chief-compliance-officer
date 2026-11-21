<?php
/**
 * SHA256.US — API Endpoint: Autenticación de Usuario (Login / MFA / Logout / Status)
 * Cumplimiento: NIST SP 800-63B (AAL2) · RFC 6238 · OWASP ASVS v4.0.3
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/totp.php';

use Sha256\Auth\Session;
use Sha256\Auth\Totp;
use Sha256\Db\Database;

$method = $_SERVER['REQUEST_METHOD'];

// GET: Estado de sesión actual y token CSRF
if ($method === 'GET') {
    $user = Session::getUser();
    $csrf = Session::getCsrfToken();
    if ($user === null) {
        http_response_code(401);
        echo json_encode([
            'ok'            => false,
            'authenticated' => false,
            'user'          => null,
            'csrf_token'    => $csrf,
            'error'         => 'Sesión no autorizada o expirada. Debe iniciar sesión.'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    echo json_encode([
        'ok'            => true,
        'authenticated' => true,
        'user'          => $user,
        'csrf_token'    => $csrf,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// POST: Acciones de autenticación
if ($method === 'POST') {
    $raw = file_get_contents('php://input');
    $input = json_decode($raw, true) ?? [];
    $action = $input['action'] ?? 'login';

    // 1. Cerrar Sesión
    if ($action === 'logout') {
        Session::logout();
        echo json_encode(['ok' => true, 'success' => true, 'message' => 'Sesión cerrada exitosamente']);
        exit;
    }

    // 2. Obtener Token CSRF
    if ($action === 'csrf_token') {
        echo json_encode(['ok' => true, 'csrf_token' => Session::getCsrfToken()]);
        exit;
    }

    // 3. Inicio de Sesión (Login)
    if ($action === 'login') {
        $email = (string)($input['email'] ?? '');
        $password = (string)($input['password'] ?? '');
        $totpCode = (string)($input['totp_code'] ?? $input['totpCode'] ?? '');

        if (empty($email) || (empty($password) && empty($totpCode))) {
            http_response_code(400);
            echo json_encode([
                'ok'    => false,
                'error' => 'Se requiere correo electrónico y contraseña o código Google Authenticator'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Si se suministró contraseña pero no TOTP, comprobar si el usuario requiere MFA
        if (!empty($password) && empty($totpCode)) {
            $pdo = Database::getConnection();
            $cleanEmail = strtolower(trim($email));
            $stmt = $pdo->prepare('SELECT id, password_hash, totp_enabled, totp_secret, activo FROM usuarios WHERE email = :email LIMIT 1');
            $stmt->execute(['email' => $cleanEmail]);
            $row = $stmt->fetch();

            if ($row && (bool)$row['activo'] && password_verify($password, $row['password_hash'])) {
                if ((bool)$row['totp_enabled'] && !empty($row['totp_secret'])) {
                    // Contraseña válida, solicitar segundo factor (MFA)
                    echo json_encode([
                        'ok'        => true,
                        'needs_mfa' => true,
                        'email'     => $cleanEmail,
                        'message'   => 'Contraseña verificada. Ingrese el código de Google Authenticator.'
                    ], JSON_UNESCAPED_UNICODE);
                    exit;
                }
            }
        }

        $user = Session::login($email, $password, $totpCode);
        if (!$user) {
            http_response_code(401);
            echo json_encode([
                'ok'    => false,
                'error' => 'Credenciales inválidas, código 2FA erróneo o usuario inactivo'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        echo json_encode([
            'ok'         => true,
            'success'    => true,
            'user'       => $user,
            'csrf_token' => Session::getCsrfToken()
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 4. Enrolamiento / Inicio de Configuración MFA (Requiere Usuario Autenticado)
    if ($action === 'enroll_mfa_start') {
        $user = Session::requireUser();
        $secret = Totp::generateSecret(20);
        $uri = Totp::buildProvisioningUri($user['email'], $secret, 'SHA256.US');

        echo json_encode([
            'ok'     => true,
            'secret' => $secret,
            'uri'    => $uri
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 5. Confirmación de Enrolamiento MFA (Valida código y persiste en MySQL)
    if ($action === 'enroll_mfa_confirm') {
        $user = Session::requireUser();
        $secret = trim((string)($input['secret'] ?? ''));
        $code = trim((string)($input['code'] ?? ''));

        if (empty($secret) || empty($code)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Se requiere secreto y código de verificación']);
            exit;
        }

        $slice = Totp::verifyAndGetSlice($secret, $code, 1);
        if ($slice === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Código de verificación inválido o desfasado']);
            exit;
        }

        // Generar 8 códigos de recuperación de emergencia y guardar sus hashes bcrypt
        $charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $recoveryCodes = [];
        $recoveryHashes = [];
        for ($i = 0; $i < 8; $i++) {
            $rawCode = '';
            $bytes = random_bytes(8);
            for ($j = 0; $j < 8; $j++) {
                $rawCode .= $charset[ord($bytes[$j]) % strlen($charset)];
            }
            $recoveryCodes[] = $rawCode;
            $recoveryHashes[] = password_hash($rawCode, PASSWORD_BCRYPT);
        }

        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('
            UPDATE usuarios
            SET totp_secret = :secret,
                totp_enabled = 1,
                totp_last_used_slice = :slice,
                totp_recovery_hashes = :hashes
            WHERE id = :id
        ');
        $stmt->execute([
            'secret' => $secret,
            'slice'  => $slice,
            'hashes' => json_encode($recoveryHashes),
            'id'     => $user['id']
        ]);

        echo json_encode([
            'ok'             => true,
            'success'        => true,
            'message'        => 'Google Authenticator activado exitosamente.',
            'recovery_codes' => $recoveryCodes
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => "Acción desconocida: {$action}"]);
    exit;
}

http_response_code(405);
echo json_encode(['ok' => false, 'error' => 'Método no permitido']);
