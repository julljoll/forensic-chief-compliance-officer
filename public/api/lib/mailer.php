<?php
/**
 * SHA256.US — Servicio Ligero de Envío de Correo en PHP Puro (cPanel mail() + SMTP TLS/SSL sin Composer)
 *
 * Envía los códigos OTP de 6 dígitos y enlaces mágicos de 1 clic con formato MIME multipart
 * (texto plano + HTML institucional USWDS) compatible con Gmail, Outlook y webmail cPanel.
 */

declare(strict_types=1);

namespace Sha256\Mail;

class Mailer
{
    /** @var callable|null */
    private static $testTransport = null;

    /**
     * Inyección de transporte de correo exclusiva para pruebas unitarias en PHP CLI.
     */
    public static function setTransportForTesting(?callable $transport): void
    {
        if (PHP_SAPI !== 'cli') {
            throw new \RuntimeException('setTransportForTesting solo está permitido en CLI');
        }
        self::$testTransport = $transport;
    }

    /**
     * Determina automáticamente si usar SMTP autenticado o mail() nativo de cPanel.
     */
    public static function resolveDriver(array $mailCfg): string
    {
        $driver = strtolower(trim((string)($mailCfg['driver'] ?? 'auto')));
        $hasSmtp = !empty($mailCfg['smtp_host'])
            && !empty($mailCfg['smtp_user'])
            && !empty($mailCfg['smtp_pass'])
            && !str_contains((string)$mailCfg['smtp_pass'], 'CLAVE_DE_LA_CUENTA');

        if ($driver === 'smtp') {
            return $hasSmtp ? 'smtp' : 'php_mail';
        }
        if ($driver === 'php_mail') {
            return 'php_mail';
        }
        return $hasSmtp ? 'smtp' : 'php_mail';
    }

    /**
     * Construye y envía el correo de acceso con código OTP de 6 dígitos + botón de Enlace Mágico.
     */
    public static function sendLoginOtp(
        array $mailCfg,
        string $toEmail,
        string $nombre,
        string $otpCode,
        string $magicUrl,
        int $ttlSeconds,
        string $ip
    ): bool {
        $minutes = max(1, (int)ceil($ttlSeconds / 60));
        $formattedCode = substr($otpCode, 0, 3) . ' ' . substr($otpCode, 3, 3);
        $safeName = htmlspecialchars($nombre !== '' ? $nombre : $toEmail, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $safeUrl = htmlspecialchars($magicUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $safeIp = htmlspecialchars($ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $tsUtc = gmdate('Y-m-d H:i:s') . ' UTC';

        $subject = "Código de acceso SHA256.US: {$formattedCode}";

        $textBody = implode("\r\n", [
            'SHA256.US — BÓVEDA PERICIAL FORENSE (FCCO)',
            '====================================================',
            "Hola {$nombre},",
            '',
            'Tu código de acceso de un solo uso (válido por ' . $minutes . ' minutos):',
            '',
            "    {$formattedCode}",
            '',
            'O ingresa directamente con 1 clic en este enlace mágico:',
            $magicUrl,
            '',
            "IP solicitante: {$ip}",
            "Fecha/Hora: {$tsUtc}",
            '',
            'Si no solicitaste este ingreso, ignora este mensaje: nadie puede entrar sin este código.',
            '====================================================',
        ]);

        $htmlBody = <<<HTML
<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Código de acceso SHA256.US</title></head>
<body style="margin:0;padding:24px;background:#F0F4F8;font-family:Arial,Helvetica,sans-serif;color:#1B2A4A;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;margin:0 auto;background:#FFFFFF;border:1px solid #CBD5E1;border-radius:6px;overflow:hidden;">
    <tr>
      <td style="background:#112E51;padding:18px 24px;color:#FFFFFF;">
        <div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;color:#D9A700;font-weight:bold;">SHA256.US · Bóveda Pericial</div>
        <div style="font-size:18px;font-weight:bold;margin-top:4px;">Código Seguro de Inicio de Sesión</div>
      </td>
    </tr>
    <tr>
      <td style="padding:24px;">
        <p style="margin:0 0 14px 0;font-size:14px;line-height:1.5;">Hola <strong>{$safeName}</strong>,</p>
        <p style="margin:0 0 16px 0;font-size:14px;line-height:1.5;">Introduce este código de <strong>6 dígitos</strong> en la pantalla de inicio de sesión (expira en <strong>{$minutes} minutos</strong> y es de un solo uso):</p>
        <div style="background:#F0F4F8;border:2px solid #005EA2;border-radius:6px;padding:18px;text-align:center;margin:0 0 20px 0;">
          <span style="font-family:'Courier New',Courier,monospace;font-size:32px;font-weight:bold;letter-spacing:6px;color:#112E51;">{$formattedCode}</span>
        </div>
        <p style="margin:0 0 14px 0;font-size:14px;line-height:1.5;text-align:center;">O ingresa al instante haciendo clic en el botón:</p>
        <div style="text-align:center;margin:0 0 22px 0;">
          <a href="{$safeUrl}" style="display:inline-block;background:#005EA2;color:#FFFFFF;text-decoration:none;font-weight:bold;font-size:14px;padding:12px 24px;border-radius:4px;">Ingresar en 1 Clic a SHA256.US</a>
        </div>
        <hr style="border:none;border-top:1px solid #E2E8F0;margin:20px 0;">
        <p style="margin:0;font-size:12px;color:#475569;line-height:1.5;">
          <strong>IP solicitante:</strong> {$safeIp}<br>
          <strong>Emisión:</strong> {$tsUtc}<br>
          Si no solicitaste este código, ignora este correo. Todo acceso queda asentado en auditoría SHA-256.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>
HTML;

        return self::sendMultipart($mailCfg, $toEmail, $subject, $textBody, $htmlBody);
    }

    /**
     * Envía un correo de prueba de entrega desde el panel /seguridad.
     */
    public static function sendTestEmail(array $mailCfg, string $toEmail, string $nombre, string $ip): bool
    {
        $driver = self::resolveDriver($mailCfg);
        $tsUtc = gmdate('Y-m-d H:i:s') . ' UTC';
        $subject = 'Verificación de Entrega de Correo — SHA256.US';
        $textBody = "Hola {$nombre},\r\n\r\nEste es un correo de prueba exitoso desde SHA256.US.\r\nCanal activo: {$driver}\r\nIP: {$ip}\r\nFecha: {$tsUtc}\r\n";
        $safeName = htmlspecialchars($nombre !== '' ? $nombre : $toEmail, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $htmlBody = "<p>Hola <strong>{$safeName}</strong>,</p><p>Tu canal de entrega de códigos de acceso de <strong>SHA256.US</strong> funciona correctamente.</p><p><strong>Canal:</strong> {$driver}<br><strong>IP:</strong> {$ip}<br><strong>Fecha:</strong> {$tsUtc}</p>";
        return self::sendMultipart($mailCfg, $toEmail, $subject, $textBody, $htmlBody);
    }

    /**
     * Construye el mensaje MIME multipart/alternative y lo envía por SMTP o mail() de cPanel.
     */
    public static function sendMultipart(
        array $mailCfg,
        string $toEmail,
        string $subject,
        string $textBody,
        string $htmlBody
    ): bool {
        $fromEmail = trim((string)($mailCfg['from_email'] ?? 'no-reply@sha256.us'));
        $fromName = trim((string)($mailCfg['from_name'] ?? 'SHA256.US — Bóveda Pericial'));

        if (self::$testTransport !== null) {
            return (bool)(self::$testTransport)([
                'to'      => $toEmail,
                'from'    => $fromEmail,
                'subject' => $subject,
                'text'    => $textBody,
                'html'    => $htmlBody,
                'driver'  => self::resolveDriver($mailCfg),
            ]);
        }

        $boundary = '==SHA256_B_' . bin2hex(random_bytes(12));
        $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
        $encodedFromName = '=?UTF-8?B?' . base64_encode($fromName) . '?=';

        $body = "--{$boundary}\r\n"
            . "Content-Type: text/plain; charset=UTF-8\r\n"
            . "Content-Transfer-Encoding: base64\r\n\r\n"
            . chunk_split(base64_encode($textBody)) . "\r\n"
            . "--{$boundary}\r\n"
            . "Content-Type: text/html; charset=UTF-8\r\n"
            . "Content-Transfer-Encoding: base64\r\n\r\n"
            . chunk_split(base64_encode($htmlBody)) . "\r\n"
            . "--{$boundary}--\r\n";

        $driver = self::resolveDriver($mailCfg);
        if ($driver === 'smtp') {
            $sent = self::sendViaSmtp($mailCfg, $fromEmail, $encodedFromName, $toEmail, $encodedSubject, $boundary, $body);
            if ($sent) {
                return true;
            }
            error_log('[FCCO Mailer] Fallo en SMTP autenticado; intentando fallback con mail() nativo de cPanel.');
        }

        return self::sendViaPhpMail($fromEmail, $encodedFromName, $toEmail, $encodedSubject, $boundary, $body);
    }

    private static function sendViaPhpMail(
        string $fromEmail,
        string $encodedFromName,
        string $toEmail,
        string $encodedSubject,
        string $boundary,
        string $body
    ): bool {
        $headers = [
            "From: {$encodedFromName} <{$fromEmail}>",
            "Reply-To: {$fromEmail}",
            'MIME-Version: 1.0',
            "Content-Type: multipart/alternative; boundary=\"{$boundary}\"",
            'X-Mailer: SHA256.US-FCCO',
        ];
        $headerStr = implode("\r\n", $headers);
        $extraParams = filter_var($fromEmail, FILTER_VALIDATE_EMAIL) ? "-f {$fromEmail}" : '';

        return @mail($toEmail, $encodedSubject, $body, $headerStr, $extraParams);
    }

    private static function sendViaSmtp(
        array $mailCfg,
        string $fromEmail,
        string $encodedFromName,
        string $toEmail,
        string $encodedSubject,
        string $boundary,
        string $body
    ): bool {
        $host = trim((string)($mailCfg['smtp_host'] ?? ''));
        $port = (int)($mailCfg['smtp_port'] ?? 465);
        $enc = strtolower(trim((string)($mailCfg['smtp_encryption'] ?? 'ssl')));
        $user = trim((string)($mailCfg['smtp_user'] ?? ''));
        $pass = (string)($mailCfg['smtp_pass'] ?? '');

        if ($host === '' || $user === '' || $pass === '') {
            return false;
        }

        $remote = ($enc === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port;
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ]);

        $fp = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) {
            error_log("[FCCO SMTP Connect Error] {$errno} {$errstr}");
            return false;
        }

        stream_set_timeout($fp, 15);

        try {
            if (!self::smtpExpect($fp, [220])) {
                return false;
            }
            $heloHost = preg_replace('/[^a-zA-Z0-9.\-]/', '', (string)($_SERVER['HTTP_HOST'] ?? 'sha256.us')) ?: 'sha256.us';
            self::smtpWrite($fp, "EHLO {$heloHost}");
            if (!self::smtpExpect($fp, [250])) {
                return false;
            }

            if ($enc === 'tls') {
                self::smtpWrite($fp, 'STARTTLS');
                if (!self::smtpExpect($fp, [220])) {
                    return false;
                }
                if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    return false;
                }
                self::smtpWrite($fp, "EHLO {$heloHost}");
                if (!self::smtpExpect($fp, [250])) {
                    return false;
                }
            }

            self::smtpWrite($fp, 'AUTH LOGIN');
            if (!self::smtpExpect($fp, [334])) {
                return false;
            }
            self::smtpWrite($fp, base64_encode($user));
            if (!self::smtpExpect($fp, [334])) {
                return false;
            }
            self::smtpWrite($fp, base64_encode($pass));
            if (!self::smtpExpect($fp, [235])) {
                return false;
            }

            self::smtpWrite($fp, "MAIL FROM:<{$fromEmail}>");
            if (!self::smtpExpect($fp, [250])) {
                return false;
            }
            self::smtpWrite($fp, "RCPT TO:<{$toEmail}>");
            if (!self::smtpExpect($fp, [250, 251])) {
                return false;
            }
            self::smtpWrite($fp, 'DATA');
            if (!self::smtpExpect($fp, [354])) {
                return false;
            }

            $msgHeaders = implode("\r\n", [
                'Date: ' . gmdate('D, d M Y H:i:s') . ' +0000',
                "From: {$encodedFromName} <{$fromEmail}>",
                "To: <{$toEmail}>",
                "Subject: {$encodedSubject}",
                'Message-ID: <' . bin2hex(random_bytes(16)) . '@' . $heloHost . '>',
                'MIME-Version: 1.0',
                "Content-Type: multipart/alternative; boundary=\"{$boundary}\"",
                'X-Mailer: SHA256.US-FCCO',
            ]);

            $fullMessage = $msgHeaders . "\r\n\r\n" . $body;
            // RFC 5321 dot-stuffing
            $stuffed = preg_replace('/^\./m', '..', $fullMessage) ?? $fullMessage;
            fwrite($fp, $stuffed . "\r\n.\r\n");

            if (!self::smtpExpect($fp, [250])) {
                return false;
            }

            self::smtpWrite($fp, 'QUIT');
            return true;
        } finally {
            fclose($fp);
        }
    }

    private static function smtpWrite($fp, string $cmd): void
    {
        fwrite($fp, $cmd . "\r\n");
    }

    /**
     * @param resource $fp
     * @param array<int, int> $validCodes
     */
    private static function smtpExpect($fp, array $validCodes): bool
    {
        $code = 0;
        while (($line = fgets($fp, 1024)) !== false) {
            if (strlen($line) >= 3 && ctype_digit(substr($line, 0, 3))) {
                $code = (int)substr($line, 0, 3);
            }
            if (strlen($line) < 4 || $line[3] !== '-') {
                break;
            }
        }
        return in_array($code, $validCodes, true);
    }
}
