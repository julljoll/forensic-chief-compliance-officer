<?php
/**
 * SHA256.US — Servicio Compartido de Auditoría Inmutable (Cadena SHA-256 / RFC 8785)
 *
 * Registra eventos forenses y de seguridad de acceso (solicitud OTP, login autorizado por OTP o
 * enlace mágico, correo no autorizado, fallos de verificación y cierres de sesión) en la
 * tabla append-only `auditoria` preservando paridad 1:1 con `public/api/auditoria.php?verificar=1`.
 */

declare(strict_types=1);

namespace Sha256\Audit;

require_once __DIR__ . '/canonical.php';

use PDO;
use Sha256\Crypto\Canonical;

class AuditLog
{
    /**
     * Inserta un asiento encadenado SHA-256 en la tabla inmutable `auditoria`.
     * Respeta si ya existe una transacción PDO activa o abre una propia de forma atómica.
     *
     * @return array{seq: int, hashAnterior: string, hashActual: string, ts: string}
     */
    public static function append(
        PDO $pdo,
        string $usuario,
        string $accion,
        string $detalle,
        string $nivel = 'info',
        ?string $casoId = null
    ): array {
        $allowedLevels = ['info', 'warning', 'error', 'success'];
        if (!in_array($nivel, $allowedLevels, true)) {
            $nivel = 'info';
        }

        $cleanUsuario = substr(trim($usuario) !== '' ? trim($usuario) : 'sistema@sha256.us', 0, 150);
        $cleanAccion = substr(trim($accion), 0, 100);
        $cleanDetalle = trim($detalle);

        $startedTx = false;
        if (!$pdo->inTransaction()) {
            $pdo->beginTransaction();
            $startedTx = true;
        }

        try {
            $driver = (string)$pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            $lockClause = ($driver === 'mysql') ? ' FOR UPDATE' : '';

            $stmtLast = $pdo->query("SELECT hash_actual, seq FROM auditoria ORDER BY seq DESC LIMIT 1{$lockClause}");
            $lastRow = $stmtLast ? $stmtLast->fetch(PDO::FETCH_ASSOC) : false;

            $hashAnterior = $lastRow ? (string)$lastRow['hash_actual'] : Canonical::GENESIS_HASH;
            $seq = $lastRow ? ((int)$lastRow['seq'] + 1) : 1;
            $ts = gmdate('Y-m-d\TH:i:s\Z');

            $evento = [
                'accion'       => $cleanAccion,
                'casoId'       => $casoId,
                'detalle'      => $cleanDetalle,
                'hashAnterior' => $hashAnterior,
                'nivel'        => $nivel,
                'seq'          => $seq,
                'ts'           => $ts,
                'usuario'      => $cleanUsuario,
            ];
            $hashActual = Canonical::hash($evento);

            $stmtIns = $pdo->prepare('
                INSERT INTO auditoria (seq, caso_id, usuario, accion, detalle, nivel, ts_utc, hash_anterior, hash_actual)
                VALUES (:seq, :caso_id, :usuario, :accion, :detalle, :nivel, :ts_utc, :hash_anterior, :hash_actual)
            ');
            $stmtIns->execute([
                'seq'           => $seq,
                'caso_id'       => $casoId,
                'usuario'       => $cleanUsuario,
                'accion'        => $cleanAccion,
                'detalle'       => $cleanDetalle,
                'nivel'         => $nivel,
                'ts_utc'        => $ts,
                'hash_anterior' => $hashAnterior,
                'hash_actual'   => $hashActual,
            ]);

            if ($startedTx) {
                $pdo->commit();
            }

            return [
                'seq'          => $seq,
                'hashAnterior' => $hashAnterior,
                'hashActual'   => $hashActual,
                'ts'           => $ts,
            ];
        } catch (\Throwable $e) {
            if ($startedTx && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Versión segura que registra en auditoría sin interrumpir flujos de rechazo si hay fallo temporal de BD.
     */
    public static function appendSafe(
        PDO $pdo,
        string $usuario,
        string $accion,
        string $detalle,
        string $nivel = 'info',
        ?string $casoId = null
    ): ?array {
        try {
            return self::append($pdo, $usuario, $accion, $detalle, $nivel, $casoId);
        } catch (\Throwable $e) {
            error_log('[FCCO AuditLog Error] ' . $e->getMessage());
            return null;
        }
    }
}
