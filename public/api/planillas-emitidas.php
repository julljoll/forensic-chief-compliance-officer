<?php
/**
 * SHA256.US — API Endpoint: Registro, Sellado SHA-256 y Corroboración QR de Planillas Emitidas
 *
 * - POST (Autenticado + CSRF): Emite número correlativo único (PLN-YYYY-NNNNNN), calcula
 *   hash_emision_sha256 (RFC 8785) usando exclusivamente el usuario logueado en sesión PHP,
 *   guarda en `planillas_emitidas` y registra asiento inmutable en `auditoria`.
 * - PUT  (Autenticado + CSRF): Fija `hash_pdf_sha256` binario (una sola vez) o certifica la
 *   firma electrónica Adobe Acrobat / manuscrita de los peritos.
 * - GET  ?codigo=PLN-... (Público): Consultado al escanear el Código QR Rojo en papel impreso
 *   para corroborar autenticidad, perito emisor, SHA-256 y estado de firmas.
 * - GET  ?listar=1 (Autenticado): Lista historial de emisiones para el CMS.
 * - GET  ?peritos=1 (Autenticado): Devuelve directorio de peritos activos para selección de Co-Perito.
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
 * Formatea una fila de planillas_emitidas al contrato JSON público/estándar
 */
function formatPlanillaRow(array $row, ?string $auditoriaHash = null): array
{
    return [
        'id'                   => (int)$row['id'],
        'codigoPlanilla'       => (string)$row['codigo_planilla'],
        'planillaSlug'         => (string)$row['planilla_slug'],
        'codigoDoc'            => (string)$row['codigo_doc'],
        'tituloPlanilla'       => (string)$row['titulo_planilla'],
        'faseIso'              => (string)$row['fase_iso'],
        'casoId'               => $row['caso_id'] !== null ? (string)$row['caso_id'] : null,
        'numeroCaso'           => $row['numero_caso'] !== null ? (string)$row['numero_caso'] : null,
        'numeroPRCC'           => $row['numero_prcc'] !== null ? (string)$row['numero_prcc'] : null,
        'perito'               => [
            'usuarioId' => (string)$row['perito_usuario_id'],
            'nombre'    => (string)$row['perito_nombre'],
            'ci'        => (string)$row['perito_ci'],
            'civ'       => (string)$row['perito_civ'],
            'inpre'     => (string)$row['perito_inpre'],
            'cargo'     => (string)$row['perito_cargo'],
            'organismo' => (string)$row['perito_organismo'],
        ],
        'coPerito'             => !empty($row['co_perito_nombre']) ? [
            'nombre' => (string)$row['co_perito_nombre'],
            'civ'    => (string)($row['co_perito_civ'] ?? ''),
        ] : null,
        'modalidadFirma'       => (string)$row['modalidad_firma'],
        'estadoFirma'          => (string)$row['estado_firma'],
        'firmadaEn'            => $row['firmada_en'] !== null ? (string)$row['firmada_en'] : null,
        'hashEmisionSha256'    => (string)$row['hash_emision_sha256'],
        'hashPdfSha256'        => $row['hash_pdf_sha256'] !== null ? (string)$row['hash_pdf_sha256'] : null,
        'hashPdfFirmadoSha256' => $row['hash_pdf_firmado_sha256'] !== null ? (string)$row['hash_pdf_firmado_sha256'] : null,
        'auditoriaSeq'         => $row['auditoria_seq'] !== null ? (int)$row['auditoria_seq'] : null,
        'auditoriaHash'        => $auditoriaHash,
        'emitidoEnUtc'         => (string)$row['emitido_en_utc'],
    ];
}

// ============================================================================
// GET: Verificación Pública por QR (?codigo=...) | Listado CMS | Peritos
// ============================================================================
if ($method === 'GET') {
    // 1. Directorio de peritos activos (requiere sesión)
    if (isset($_GET['peritos']) && $_GET['peritos'] === '1') {
        Session::requireUser();
        $stmt = $pdo->query('SELECT id, nombre, apellido, ci, civ, inpre, cargo, organismo FROM usuarios WHERE activo = 1 ORDER BY nombre ASC');
        $rows = $stmt->fetchAll();
        $peritos = array_map(static function (array $u): array {
            $full = trim(($u['nombre'] ?? '') . ' ' . ($u['apellido'] ?? ''));
            return [
                'id'        => (string)$u['id'],
                'nombre'    => $full,
                'ci'        => (string)($u['ci'] ?? ''),
                'civ'       => (string)($u['civ'] ?? ''),
                'inpre'     => (string)($u['inpre'] ?? ''),
                'cargo'     => (string)($u['cargo'] ?? ''),
                'organismo' => (string)($u['organismo'] ?? ''),
            ];
        }, $rows);
        echo json_encode(['ok' => true, 'peritos' => $peritos], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 2. Consulta pública de corroboración por Código de Planilla (Escaneo QR)
    if (isset($_GET['codigo'])) {
        $codigo = strtoupper(trim((string)$_GET['codigo']));
        if (!preg_match('/^[A-Z0-9\-]{6,32}$/', $codigo)) {
            http_response_code(400);
            echo json_encode([
                'ok'         => false,
                'verificada' => false,
                'error'      => 'Formato de código de planilla inválido. Ejemplo esperado: PLN-2026-000001'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('
            SELECT p.*, a.hash_actual AS auditoria_hash
            FROM planillas_emitidas p
            LEFT JOIN auditoria a ON a.seq = p.auditoria_seq
            WHERE p.codigo_planilla = :codigo
            LIMIT 1
        ');
        $stmt->execute(['codigo' => $codigo]);
        $row = $stmt->fetch();

        if (!$row) {
            http_response_code(404);
            echo json_encode([
                'ok'         => false,
                'verificada' => false,
                'codigo'     => $codigo,
                'error'      => 'El código de planilla consultado no figura en la base de datos oficial de SHA256.US.'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $audHash = isset($row['auditoria_hash']) ? (string)$row['auditoria_hash'] : null;
        $verificada = ($row['estado_firma'] !== 'REVOCADA');

        echo json_encode([
            'ok'         => true,
            'verificada' => $verificada,
            'planilla'   => formatPlanillaRow($row, $audHash),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 3. Listado de planillas emitidas para el CMS (requiere usuario logueado)
    Session::requireUser();
    $casoId = isset($_GET['caso_id']) && trim((string)$_GET['caso_id']) !== '' ? trim((string)$_GET['caso_id']) : null;

    if ($casoId !== null) {
        $stmt = $pdo->prepare('
            SELECT p.*, a.hash_actual AS auditoria_hash
            FROM planillas_emitidas p
            LEFT JOIN auditoria a ON a.seq = p.auditoria_seq
            WHERE p.caso_id = :caso_id
            ORDER BY p.id DESC
            LIMIT 200
        ');
        $stmt->execute(['caso_id' => $casoId]);
    } else {
        $stmt = $pdo->query('
            SELECT p.*, a.hash_actual AS auditoria_hash
            FROM planillas_emitidas p
            LEFT JOIN auditoria a ON a.seq = p.auditoria_seq
            ORDER BY p.id DESC
            LIMIT 200
        ');
    }

    $rows = $stmt->fetchAll();
    $planillas = array_map(
        static fn(array $r): array => formatPlanillaRow($r, isset($r['auditoria_hash']) ? (string)$r['auditoria_hash'] : null),
        $rows
    );

    echo json_encode(['ok' => true, 'planillas' => $planillas], JSON_UNESCAPED_UNICODE);
    exit;
}

// ============================================================================
// POST: Emisión Atómica de Planilla Editable (QR Rojo + Code-128 + SHA-256)
// ============================================================================
if ($method === 'POST') {
    $user = Session::requireUser();
    Session::requireCsrf();

    $input = json_decode((string)file_get_contents('php://input'), true) ?? [];

    $slug = preg_replace('/[^a-z0-9\-]/', '', strtolower(trim((string)($input['planillaSlug'] ?? 'planilla')))) ?: 'planilla';
    $codigoDoc = substr(trim((string)($input['codigoDoc'] ?? 'FO-FOR-01')), 0, 32) ?: 'FO-FOR-01';
    $titulo = substr(trim((string)($input['tituloPlanilla'] ?? 'Planilla Pericial Oficial')), 0, 255) ?: 'Planilla Pericial Oficial';
    $faseIso = preg_replace('/[^A-Z0-9]/', '', strtoupper(trim((string)($input['faseIso'] ?? 'F0')))) ?: 'F0';
    $faseIso = substr($faseIso, 0, 8);

    $casoId = isset($input['casoId']) && trim((string)$input['casoId']) !== '' ? substr(trim((string)$input['casoId']), 0, 64) : null;
    $numeroCaso = isset($input['numeroCaso']) && trim((string)$input['numeroCaso']) !== '' ? substr(trim((string)$input['numeroCaso']), 0, 64) : null;
    $numeroPRCC = isset($input['numeroPRCC']) && trim((string)$input['numeroPRCC']) !== '' ? substr(trim((string)$input['numeroPRCC']), 0, 64) : null;

    $coPeritoNombre = isset($input['coPeritoNombre']) && trim((string)$input['coPeritoNombre']) !== ''
        ? substr(trim((string)$input['coPeritoNombre']), 0, 200)
        : null;
    $coPeritoCiv = isset($input['coPeritoCiv']) && trim((string)$input['coPeritoCiv']) !== ''
        ? substr(trim((string)$input['coPeritoCiv']), 0, 64)
        : null;

    $modalidad = (string)($input['modalidadFirma'] ?? 'hibrida');
    if (!in_array($modalidad, ['adobe_electronica', 'manual_autografa', 'hibrida'], true)) {
        $modalidad = 'hibrida';
    }

    // Datos autoritativos del perito logueado en sesión PHP (no falsificables por el cliente)
    $peritoId = (string)$user['id'];
    $peritoNombre = trim(((string)($user['nombre'] ?? '')) . ' ' . ((string)($user['apellido'] ?? '')));
    if ($peritoNombre === '') {
        $peritoNombre = (string)($user['email'] ?? 'Perito Forense');
    }
    $peritoCi = (string)($user['ci'] ?? '');
    $peritoCiv = (string)($user['civ'] ?? '');
    $peritoInpre = (string)($user['inpre'] ?? '');
    $peritoCargo = (string)($user['cargo'] ?? 'Perito Informático Forense');
    $peritoOrganismo = (string)($user['organismo'] ?? 'Laboratorio Privado SHA256.US');
    $usuarioEmail = (string)($user['email'] ?? $peritoNombre);
    $ipEmision = substr((string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'), 0, 45);

    // Validar caso_id existente si se proporcionó para respetar FK
    if ($casoId !== null) {
        $chkCaso = $pdo->prepare('SELECT id, numero_caso, numero_prcc FROM casos WHERE id = :id LIMIT 1');
        $chkCaso->execute(['id' => $casoId]);
        $casoRow = $chkCaso->fetch();
        if ($casoRow) {
            if ($numeroCaso === null && !empty($casoRow['numero_caso'])) {
                $numeroCaso = (string)$casoRow['numero_caso'];
            }
            if ($numeroPRCC === null && !empty($casoRow['numero_prcc'])) {
                $numeroPRCC = (string)$casoRow['numero_prcc'];
            }
        } else {
            $casoId = null;
        }
    }

    $pdo->beginTransaction();

    try {
        $year = gmdate('Y');
        $prefix = "PLN-{$year}-";

        // Bloqueo de lectura para asignar correlativo único atómico
        $stmtSeq = $pdo->prepare('SELECT codigo_planilla FROM planillas_emitidas WHERE codigo_planilla LIKE :prefix ORDER BY id DESC LIMIT 1 FOR UPDATE');
        $stmtSeq->execute(['prefix' => $prefix . '%']);
        $lastCodeRow = $stmtSeq->fetch();

        $nextNum = 1;
        if ($lastCodeRow && preg_match('/^PLN-\d{4}-(\d+)$/', (string)$lastCodeRow['codigo_planilla'], $m)) {
            $nextNum = ((int)$m[1]) + 1;
        }
        $codigoPlanilla = sprintf('PLN-%s-%06d', $year, $nextNum);
        $emitidoEnUtc = gmdate('Y-m-d\TH:i:s\Z');

        // Leer último registro de auditoria con bloqueo FOR UPDATE
        $stmtLastAudit = $pdo->query('SELECT hash_actual, seq FROM auditoria ORDER BY seq DESC LIMIT 1 FOR UPDATE');
        $lastAuditRow = $stmtLastAudit->fetch();
        $hashAuditAnterior = $lastAuditRow ? (string)$lastAuditRow['hash_actual'] : Canonical::GENESIS_HASH;
        $seqAudit = $lastAuditRow ? ((int)$lastAuditRow['seq'] + 1) : 1;

        // Calcular Hash SHA-256 Canónico de Emisión (RFC 8785)
        $payloadEmision = [
            'casoId'            => $casoId,
            'codigoDoc'         => $codigoDoc,
            'codigoPlanilla'    => $codigoPlanilla,
            'coPeritoCiv'       => $coPeritoCiv,
            'coPeritoNombre'    => $coPeritoNombre,
            'emitidoEnUtc'      => $emitidoEnUtc,
            'faseIso'           => $faseIso,
            'hashAuditAnterior' => $hashAuditAnterior,
            'modalidadFirma'    => $modalidad,
            'numeroCaso'        => $numeroCaso,
            'numeroPRCC'        => $numeroPRCC,
            'peritoCiv'         => $peritoCiv,
            'peritoNombre'      => $peritoNombre,
            'peritoUsuarioId'   => $peritoId,
            'planillaSlug'      => $slug,
            'tituloPlanilla'    => $titulo,
        ];
        $hashEmision = Canonical::hash($payloadEmision);

        // Registrar asiento inmutable en `auditoria`
        $detalleAudit = "Emisión PDF Adobe {$codigoPlanilla} ({$codigoDoc}: {$titulo}) por {$peritoNombre} ({$peritoCiv}). Modalidad firma: {$modalidad}. SHA-256 emisión: {$hashEmision}";
        $eventoAudit = [
            'accion'       => 'EMISION_PDF_ADOBE',
            'casoId'       => $casoId,
            'detalle'      => $detalleAudit,
            'hashAnterior' => $hashAuditAnterior,
            'nivel'        => 'success',
            'seq'          => $seqAudit,
            'ts'           => $emitidoEnUtc,
            'usuario'      => $usuarioEmail,
        ];
        $hashAuditActual = Canonical::hash($eventoAudit);

        $stmtInsAudit = $pdo->prepare('
            INSERT INTO auditoria (seq, caso_id, usuario, accion, detalle, nivel, ts_utc, hash_anterior, hash_actual)
            VALUES (:seq, :caso_id, :usuario, :accion, :detalle, :nivel, :ts_utc, :hash_anterior, :hash_actual)
        ');
        $stmtInsAudit->execute([
            'seq'           => $seqAudit,
            'caso_id'       => $casoId,
            'usuario'       => $usuarioEmail,
            'accion'        => 'EMISION_PDF_ADOBE',
            'detalle'       => $detalleAudit,
            'nivel'         => 'success',
            'ts_utc'        => $emitidoEnUtc,
            'hash_anterior' => $hashAuditAnterior,
            'hash_actual'   => $hashAuditActual,
        ]);

        // Insertar registro en `planillas_emitidas`
        $stmtIns = $pdo->prepare('
            INSERT INTO planillas_emitidas (
                codigo_planilla, planilla_slug, codigo_doc, titulo_planilla, fase_iso,
                caso_id, numero_caso, numero_prcc,
                perito_usuario_id, perito_nombre, perito_ci, perito_civ, perito_inpre, perito_cargo, perito_organismo,
                co_perito_nombre, co_perito_civ, modalidad_firma, estado_firma,
                hash_emision_sha256, auditoria_seq, ip_emision, emitido_en_utc
            ) VALUES (
                :codigo_planilla, :planilla_slug, :codigo_doc, :titulo_planilla, :fase_iso,
                :caso_id, :numero_caso, :numero_prcc,
                :perito_usuario_id, :perito_nombre, :perito_ci, :perito_civ, :perito_inpre, :perito_cargo, :perito_organismo,
                :co_perito_nombre, :co_perito_civ, :modalidad_firma, "PENDIENTE_FIRMA",
                :hash_emision_sha256, :auditoria_seq, :ip_emision, :emitido_en_utc
            )
        ');
        $stmtIns->execute([
            'codigo_planilla'     => $codigoPlanilla,
            'planilla_slug'       => $slug,
            'codigo_doc'          => $codigoDoc,
            'titulo_planilla'     => $titulo,
            'fase_iso'            => $faseIso,
            'caso_id'             => $casoId,
            'numero_caso'         => $numeroCaso,
            'numero_prcc'         => $numeroPRCC,
            'perito_usuario_id'   => $peritoId,
            'perito_nombre'       => $peritoNombre,
            'perito_ci'           => $peritoCi,
            'perito_civ'          => $peritoCiv,
            'perito_inpre'        => $peritoInpre,
            'perito_cargo'        => $peritoCargo,
            'perito_organismo'    => $peritoOrganismo,
            'co_perito_nombre'    => $coPeritoNombre,
            'co_perito_civ'       => $coPeritoCiv,
            'modalidad_firma'     => $modalidad,
            'hash_emision_sha256' => $hashEmision,
            'auditoria_seq'       => $seqAudit,
            'ip_emision'          => $ipEmision,
            'emitido_en_utc'      => $emitidoEnUtc,
        ]);

        $newId = (int)$pdo->lastInsertId();
        $pdo->commit();

        $host = (string)($_SERVER['HTTP_HOST'] ?? 'sha256.us');
        $isLocal = str_contains($host, 'localhost') || str_contains($host, '127.0.0.1');
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
        $scheme = ($isHttps || !$isLocal) ? 'https' : 'http';
        $qrUrl = "{$scheme}://{$host}/verificar?codigo=" . urlencode($codigoPlanilla);

        $rowCreated = [
            'id'                     => $newId,
            'codigo_planilla'        => $codigoPlanilla,
            'planilla_slug'          => $slug,
            'codigo_doc'             => $codigoDoc,
            'titulo_planilla'        => $titulo,
            'fase_iso'               => $faseIso,
            'caso_id'                => $casoId,
            'numero_caso'            => $numeroCaso,
            'numero_prcc'            => $numeroPRCC,
            'perito_usuario_id'      => $peritoId,
            'perito_nombre'          => $peritoNombre,
            'perito_ci'              => $peritoCi,
            'perito_civ'             => $peritoCiv,
            'perito_inpre'           => $peritoInpre,
            'perito_cargo'           => $peritoCargo,
            'perito_organismo'       => $peritoOrganismo,
            'co_perito_nombre'       => $coPeritoNombre,
            'co_perito_civ'          => $coPeritoCiv,
            'modalidad_firma'        => $modalidad,
            'estado_firma'           => 'PENDIENTE_FIRMA',
            'firmada_en'             => null,
            'hash_emision_sha256'    => $hashEmision,
            'hash_pdf_sha256'        => null,
            'hash_pdf_firmado_sha256'=> null,
            'auditoria_seq'          => $seqAudit,
            'emitido_en_utc'         => $emitidoEnUtc,
        ];

        http_response_code(201);
        echo json_encode([
            'ok'       => true,
            'qrUrl'    => $qrUrl,
            'planilla' => formatPlanillaRow($rowCreated, $hashAuditActual),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (\Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[FCCO PlanillasEmitidas POST Error] ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Error interno al registrar la emisión de la planilla'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// ============================================================================
// PUT: Fijar Hash Binario PDF (Fase 2) o Certificar Firma de Peritos
// ============================================================================
if ($method === 'PUT') {
    $user = Session::requireUser();
    Session::requireCsrf();

    $input = json_decode((string)file_get_contents('php://input'), true) ?? [];
    $action = (string)($input['action'] ?? 'fijar_hash_pdf');
    $codigo = strtoupper(trim((string)($input['codigoPlanilla'] ?? '')));

    if (!preg_match('/^[A-Z0-9\-]{6,32}$/', $codigo)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Código de planilla inválido'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Acción 1: Fijar hash_pdf_sha256 binario (inmutable una vez fijado)
    if ($action === 'fijar_hash_pdf') {
        $hashPdf = strtolower(trim((string)($input['hashPdfSha256'] ?? '')));
        if (!preg_match('/^[a-f0-9]{64}$/', $hashPdf)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Hash SHA-256 de PDF inválido (debe tener 64 hexadecimales)'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare('
            UPDATE planillas_emitidas
            SET hash_pdf_sha256 = :hash_pdf
            WHERE codigo_planilla = :codigo AND hash_pdf_sha256 IS NULL
        ');
        $stmt->execute(['hash_pdf' => $hashPdf, 'codigo' => $codigo]);

        echo json_encode([
            'ok'            => true,
            'codigoPlanilla'=> $codigo,
            'hashPdfSha256' => $hashPdf,
            'actualizado'   => $stmt->rowCount() > 0,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Acción 2: Certificar Firma Electrónica (Adobe Acrobat) o Manuscrita
    if ($action === 'certificar_firma') {
        $estadoFirma = strtoupper(trim((string)($input['estadoFirma'] ?? '')));
        $permitidos = ['FIRMADA_ADOBE', 'FIRMADA_MANUAL', 'FIRMADA_HIBRIDA', 'REVOCADA'];
        if (!in_array($estadoFirma, $permitidos, true)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Estado de firma no permitido'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $hashFirmado = isset($input['hashPdfFirmadoSha256']) && trim((string)$input['hashPdfFirmadoSha256']) !== ''
            ? strtolower(trim((string)$input['hashPdfFirmadoSha256']))
            : null;
        if ($hashFirmado !== null && !preg_match('/^[a-f0-9]{64}$/', $hashFirmado)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Hash SHA-256 del PDF firmado inválido'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $pdo->beginTransaction();
        try {
            $stmtChk = $pdo->prepare('SELECT id, caso_id, estado_firma FROM planillas_emitidas WHERE codigo_planilla = :codigo LIMIT 1 FOR UPDATE');
            $stmtChk->execute(['codigo' => $codigo]);
            $row = $stmtChk->fetch();
            if (!$row) {
                $pdo->rollBack();
                http_response_code(404);
                echo json_encode(['ok' => false, 'error' => 'Planilla no encontrada'], JSON_UNESCAPED_UNICODE);
                exit;
            }

            $stmtUp = $pdo->prepare('
                UPDATE planillas_emitidas
                SET estado_firma = :estado_firma,
                    firmada_en = NOW(),
                    hash_pdf_firmado_sha256 = COALESCE(:hash_firmado, hash_pdf_firmado_sha256)
                WHERE codigo_planilla = :codigo
            ');
            $stmtUp->execute([
                'estado_firma' => $estadoFirma,
                'hash_firmado' => $hashFirmado,
                'codigo'       => $codigo,
            ]);

            // Registrar asiento inmutable en `auditoria`
            $stmtLastAudit = $pdo->query('SELECT hash_actual, seq FROM auditoria ORDER BY seq DESC LIMIT 1 FOR UPDATE');
            $lastAuditRow = $stmtLastAudit->fetch();
            $hashAuditAnterior = $lastAuditRow ? (string)$lastAuditRow['hash_actual'] : Canonical::GENESIS_HASH;
            $seqAudit = $lastAuditRow ? ((int)$lastAuditRow['seq'] + 1) : 1;
            $ahora = gmdate('Y-m-d\TH:i:s\Z');
            $usuarioEmail = (string)($user['email'] ?? 'perito@sha256.us');

            $detalle = "Certificación de firma en planilla {$codigo}: estado={$estadoFirma}" . ($hashFirmado ? " | SHA-256 firmado: {$hashFirmado}" : '');
            $eventoAudit = [
                'accion'       => 'CERTIFICACION_FIRMA_PLANILLA',
                'casoId'       => $row['caso_id'],
                'detalle'      => $detalle,
                'hashAnterior' => $hashAuditAnterior,
                'nivel'        => $estadoFirma === 'REVOCADA' ? 'warning' : 'success',
                'seq'          => $seqAudit,
                'ts'           => $ahora,
                'usuario'      => $usuarioEmail,
            ];
            $hashAuditActual = Canonical::hash($eventoAudit);

            $stmtInsAudit = $pdo->prepare('
                INSERT INTO auditoria (seq, caso_id, usuario, accion, detalle, nivel, ts_utc, hash_anterior, hash_actual)
                VALUES (:seq, :caso_id, :usuario, :accion, :detalle, :nivel, :ts_utc, :hash_anterior, :hash_actual)
            ');
            $stmtInsAudit->execute([
                'seq'           => $seqAudit,
                'caso_id'       => $row['caso_id'],
                'usuario'       => $usuarioEmail,
                'accion'        => 'CERTIFICACION_FIRMA_PLANILLA',
                'detalle'       => $detalle,
                'nivel'         => $estadoFirma === 'REVOCADA' ? 'warning' : 'success',
                'ts_utc'        => $ahora,
                'hash_anterior' => $hashAuditAnterior,
                'hash_actual'   => $hashAuditActual,
            ]);

            $pdo->commit();

            echo json_encode([
                'ok'                   => true,
                'codigoPlanilla'       => $codigo,
                'estadoFirma'          => $estadoFirma,
                'hashPdfFirmadoSha256' => $hashFirmado,
                'auditoriaSeq'         => $seqAudit,
            ], JSON_UNESCAPED_UNICODE);
            exit;
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('[FCCO PlanillasEmitidas PUT Error] ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'error' => 'Error interno al certificar firma'], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Acción PUT desconocida'], JSON_UNESCAPED_UNICODE);
    exit;
}

http_response_code(405);
echo json_encode(['ok' => false, 'error' => 'Método HTTP no permitido'], JSON_UNESCAPED_UNICODE);
exit;
