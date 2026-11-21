<?php
/**
 * SHA256.US — Gatekeeper Server-Side de Autenticación para cPanel / Apache
 * Impide el acceso y entrega de cualquier página HTML protegida a usuarios no autenticados.
 * Cumplimiento: OWASP ASVS v4.0.3 · NIST SP 800-63B · COPP Art. 187
 */

declare(strict_types=1);

require_once __DIR__ . '/api/lib/auth.php';

use Sha256\Auth\Session;

// 1. Verificar sesión activa de perito en PHP
$user = Session::getUser();
if (!$user) {
    // Si no está autenticado, redirigir inmediatamente a la página de login con 302
    header('Location: /?msg=sesion_requerida', true, 302);
    exit;
}

// 2. Usuario autenticado: resolver el archivo estático solicitado
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?? '';
$path = trim($uri, '/');

// Sanitización rigurosa de ruta para evitar Path Traversal
$cleanPath = str_replace(['..', "\0", '\\'], '', $path);

// Normalizar nombres de archivo
if ($cleanPath === 'planillas' || $cleanPath === 'planillas/index' || $cleanPath === 'planillas/index.html') {
    $targetFile = __DIR__ . '/planillas/index.html';
} else {
    if (!str_ends_with($cleanPath, '.html')) {
        $cleanPath .= '.html';
    }
    $targetFile = __DIR__ . '/' . $cleanPath;
}

// 3. Servir el archivo HTML si existe
if (file_exists($targetFile) && is_file($targetFile)) {
    header('Content-Type: text/html; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    readfile($targetFile);
    exit;
}

// Si el archivo físico no existe, emitir 404
http_response_code(404);
echo '<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>404 No Encontrado</title></head><body><h1>404 — Página no encontrada</h1><p><a href="/dashboard">Volver al Dashboard</a></p></body></html>';
exit;
