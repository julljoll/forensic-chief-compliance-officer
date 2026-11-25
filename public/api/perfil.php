<?php
/**
 * SHA256.US — API Endpoint: Perfil y Credenciales del Perito Autenticado
 *
 * - GET  (Autenticado): Devuelve las credenciales actuales del perito desde MySQL y refresca la sesión.
 * - PUT  (Autenticado + CSRF): Actualiza automáticamente en MySQL (`usuarios`) los datos editables
 *   del perito (nombre, apellido, C.I., cargo, CIV, INPRE, organismo, despacho, teléfono, dirección,
 *   especialidad), refresca `$_SESSION['usuario']` y registra asiento inmutable en `auditoria`.
 * - POST (Autenticado + CSRF, action=cambiar_password): Permite actualizar la contraseña verificando
 *   la contraseña actual con `password_verify()`.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/canonical.php';

use Sha256\Db\Database;
use Sha256\Auth\Session;
use Sha256\Crypto\Canonical;

$pdo = Database::getConnection();
$method = $_SERVER['REQUEST_METHOD'];

/**
 * Sanea el registro de usuario eliminando hashes y secretos MFA antes de devolverlo o guardarlo en sesión.
 */
function sanitizeUserRow(array $row): array
{
    unset($row['password_hash'], $row['totp_secret'], $row['totp_recovery_hashes']);
    $row['totp_enabled'] = (int)($row['totp_enabled'] ?? 0);
    $row['activo'] = (int)($row['activo'] ?? 1);
    return $row;
}

/**
 * Registra un evento inmutable encadenado con SHA-256 en la tabla `auditoria`.
 */
function appendProfileAudit(\PDO $pdo, string $usuarioEmail, string $accion, string $detalle, string $nivel = 'info'): int
{
    $stmtLast = $pdo->query('SELECT hash_actual, seq FROM auditoria ORDER BY seq DESC LIMIT 1 FOR UPDATE');
    $lastRow = $stmtLast->fetch();
    $hashAnterior = $lastRow ? (string)$lastRow['hash_actual'] : Canonical::GENESIS_HASH;
    $seq = $lastRow ? ((int)$lastRow['seq'] + 1) : 1;
    $ts = gmdate('Y-m-d\TH:i:s\Z');

    $evento = [
        'accion'       => $accion,
        'casoId'       => null,
        'detalle'      => $detalle,
        'hashAnterior' => $hashAnterior,
        'nivel'        => $nivel,
        'seq'          => $seq,
        'ts'           => $ts,
        'usuario'      => $usuarioEmail,
    ];
    $hashActual = Canonical::hash($evento);

    $stmtIns = $pdo->prepare('
        INSERT INTO auditoria (seq, caso_id, usuario, accion, detalle, nivel, ts_utc, hash_anterior, hash_actual)
        VALUES (:seq, NULL, :usuario, :accion, :detalle, :nivel, :ts_utc, :hash_anterior, :hash_actual)
    ');
    $stmtIns->execute([
        'seq'           => $seq,
        'usuario'       => $usuarioEmail,
        'accion'        => $accion,
        'detalle'       => $detalle,
        'nivel'         => $nivel,
        'ts_utc'        => $ts,
        'hash_anterior' => $hashAnterior,
        'hash_actual'   => $hashActual,
    ]);

    return $seq;
}

// ============================================================================
// GET: Obtener perfil actualizado del perito logueado desde MySQL
// ============================================================================
if ($method === 'GET') {
    $sessionUser = Session::requireUser();

    $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $sessionUser['id']]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'Perfil de perito no encontrado en base de datos'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $clean = sanitizeUserRow($row);
    $_SESSION['usuario'] = $clean;

    echo json_encode([
        'ok'         => true,
        'user'       => $clean,
        'csrf_token' => Session::getCsrfToken(),
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ============================================================================
// PUT: Actualizar credenciales del perito logueado en MySQL (cPanel)
// ============================================================================
if ($method === 'PUT') {
    $sessionUser = Session::requireUser();
    Session::requireCsrf();

    $input = json_decode((string)file_get_contents('php://input'), true) ?? [];

    // Whitelist estricta de campos editables (protege id, rol, email y activo contra manipulación)
    $nombre = substr(trim((string)($input['nombre'] ?? '')), 0, 150);
    $apellido = substr(trim((string)($input['apellido'] ?? '')), 0, 150);
    $ci = substr(trim((string)($input['ci'] ?? '')), 0, 32);
    $cargo = substr(trim((string)($input['cargo'] ?? '')), 0, 120);
    $organismo = substr(trim((string)($input['organismo'] ?? '')), 0, 150);
    $despacho = substr(trim((string)($input['despacho'] ?? '')), 0, 150);
    $telefono = substr(trim((string)($input['telefono'] ?? '')), 0, 64);
    $direccion = substr(trim((string)($input['direccion'] ?? '')), 0, 255);
    $especialidad = substr(trim((string)($input['especialidad'] ?? '')), 0, 180);
    $civ = substr(trim((string)($input['civ'] ?? '')), 0, 64);
    $inpre = substr(trim((string)($input['inpre'] ?? '')), 0, 64);

    if ($nombre === '') {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'El nombre del perito es obligatorio'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $pdo->beginTransaction();

    try {
        $stmtUp = $pdo->prepare('
            UPDATE usuarios
            SET nombre = :nombre,
                apellido = :apellido,
                ci = :ci,
                cargo = :cargo,
                organismo = :organismo,
                despacho = :despacho,
                telefono = :telefono,
                direccion = :direccion,
                especialidad = :especialidad,
                civ = :civ,
                inpre = :inpre
            WHERE id = :id
        ');
        $stmtUp->execute([
            'nombre'       => $nombre,
            'apellido'     => $apellido,
            'ci'           => $ci,
            'cargo'        => $cargo !== '' ? $cargo : 'Perito Informático Forense',
            'organismo'    => $organismo !== '' ? $organismo : 'Laboratorio Privado SHA256.US',
            'despacho'     => $despacho,
            'telefono'     => $telefono,
            'direccion'    => $direccion,
            'especialidad' => $especialidad !== '' ? $especialidad : 'Informática Forense y Evidencia Digital',
            'civ'          => $civ,
            'inpre'        => $inpre,
            'id'           => $sessionUser['id'],
        ]);

        // Recargar fila actualizada para sincronizar sesión PHP
        $stmtFetch = $pdo->prepare('SELECT * FROM usuarios WHERE id = :id LIMIT 1');
        $stmtFetch->execute(['id' => $sessionUser['id']]);
        $updatedRow = $stmtFetch->fetch();

        if (!$updatedRow) {
            $pdo->rollBack();
            http_response_code(404);
            echo json_encode(['ok' => false, 'error' => 'No se encontró el registro de usuario tras la actualización'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $clean = sanitizeUserRow($updatedRow);
        $fullName = trim($clean['nombre'] . ' ' . $clean['apellido']);
        $detalle = "Actualización de perfil pericial: {$fullName} | C.I.: {$clean['ci']} | CIV: {$clean['civ']} | Cargo: {$clean['cargo']}";
        $seqAudit = appendProfileAudit($pdo, (string)$clean['email'], 'ACTUALIZACION_PERFIL_PERITO', $detalle, 'success');

        $pdo->commit();

        $_SESSION['usuario'] = $clean;

        echo json_encode([
            'ok'           => true,
            'message'      => 'Credenciales del perito actualizadas y sincronizadas en MySQL.',
            'user'         => $clean,
            'auditoriaSeq' => $seqAudit,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (\Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[FCCO Perfil PUT Error] ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Error interno al actualizar las credenciales del perito'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// ============================================================================
// POST: Cambio Seguro de Contraseña (action=cambiar_password)
// ============================================================================
if ($method === 'POST') {
    $sessionUser = Session::requireUser();
    Session::requireCsrf();

    $input = json_decode((string)file_get_contents('php://input'), true) ?? [];
    $action = (string)($input['action'] ?? '');

    if ($action !== 'cambiar_password') {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Acción POST no soportada en perfil'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $passwordActual = (string)($input['passwordActual'] ?? '');
    $passwordNueva = (string)($input['passwordNueva'] ?? '');

    if ($passwordActual === '' || strlen($passwordNueva) < 10) {
        http_response_code(400);
        echo json_encode([
            'ok'    => false,
            'error' => 'Debe indicar su contraseña actual y una nueva contraseña de al menos 10 caracteres.'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $stmt = $pdo->prepare('SELECT id, email, password_hash FROM usuarios WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $sessionUser['id']]);
    $row = $stmt->fetch();

    if (!$row || !password_verify($passwordActual, (string)$row['password_hash'])) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'La contraseña actual ingresada es incorrecta.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $pdo->beginTransaction();
    try {
        $newHash = password_hash($passwordNueva, PASSWORD_BCRYPT);
        $stmtUp = $pdo->prepare('UPDATE usuarios SET password_hash = :hash WHERE id = :id');
        $stmtUp->execute(['hash' => $newHash, 'id' => $sessionUser['id']]);

        $seqAudit = appendProfileAudit(
            $pdo,
            (string)$row['email'],
            'CAMBIO_PASSWORD_PERITO',
            'Actualización de contraseña de acceso pericial verificada con credencial previa',
            'success'
        );

        $pdo->commit();
        echo json_encode([
            'ok'           => true,
            'message'      => 'Contraseña actualizada exitosamente en base de datos.',
            'auditoriaSeq' => $seqAudit,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (\Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[FCCO Perfil Password Error] ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Error interno al cambiar la contraseña'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

http_response_code(405);
echo json_encode(['ok' => false, 'error' => 'Método HTTP no permitido'], JSON_UNESCAPED_UNICODE);
exit;
