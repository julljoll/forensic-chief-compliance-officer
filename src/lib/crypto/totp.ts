/**
 * SHA256.US — Módulo de Verificación TOTP (RFC 6238) para Google Authenticator
 * Compatible con navegadores web (Web Crypto API) y Node.js (crypto global).
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(b32: string): Uint8Array {
  const clean = b32.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    if (val === -1) continue;
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Genera un secreto criptográfico aleatorio en Base32 (20 bytes = 160 bits CSPRNG).
 */
export function generarSecretoBase32(byteLength: number = 20): string {
  const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
  const bytes = new Uint8Array(byteLength);
  cryptoObj.getRandomValues(bytes);
  return base32Encode(bytes);
}

/**
 * Construye la URI otpauth estándar para Google Authenticator.
 */
export function construirUriTotp(usuario: string, secretBase32: string, issuer: string = 'SHA256.US'): string {
  const cleanUser = encodeURIComponent(usuario.trim());
  const cleanIssuer = encodeURIComponent(issuer.trim());
  const cleanSecret = secretBase32.replace(/[\s=]/g, '').toUpperCase();
  return `otpauth://totp/${cleanIssuer}:${cleanUser}?secret=${cleanSecret}&issuer=${cleanIssuer}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Genera una lista de 8 códigos de recuperación de emergencia únicos (ej. 8 caracteres alfanuméricos).
 */
export function generarCodigosRecuperacion(cantidad: number = 8): string[] {
  const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Base32 legible sin confusiones O/0, I/1
  const codigos: string[] = [];

  for (let i = 0; i < cantidad; i++) {
    const bytes = new Uint8Array(8);
    cryptoObj.getRandomValues(bytes);
    let code = '';
    for (let j = 0; j < 8; j++) {
      code += charset[bytes[j] % charset.length];
    }
    codigos.push(code);
  }

  return codigos;
}

export async function generarTotpCode(secretBase32: string, timeStepSeconds: number = 30): Promise<string> {
  const counter = Math.floor(Date.now() / 1000 / timeStepSeconds);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(counter), false); // Big-Endian

  const keyBytes = base32Decode(secretBase32);

  const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
  const key = await cryptoObj.subtle.importKey(
    'raw',
    keyBytes as unknown as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await cryptoObj.subtle.sign('HMAC', key, buffer);
  const hmac = new Uint8Array(signature);

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

export async function verificarTotpCode(secretBase32: string, codigoUsuario: string, windowSteps: number = 1): Promise<boolean> {
  const code = (codigoUsuario || '').trim();
  if (code.length !== 6 || !/^\d{6}$/.test(code)) {
    return false;
  }

  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  const keyBytes = base32Decode(secretBase32);
  const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;

  const key = await cryptoObj.subtle.importKey(
    'raw',
    keyBytes as unknown as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  for (let offset = -windowSteps; offset <= windowSteps; offset++) {
    const counter = currentCounter + offset;
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setBigUint64(0, BigInt(counter), false);

    const signature = await cryptoObj.subtle.sign('HMAC', key, buffer);
    const hmac = new Uint8Array(signature);

    const off = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[off] & 0x7f) << 24) |
      ((hmac[off + 1] & 0xff) << 16) |
      ((hmac[off + 2] & 0xff) << 8) |
      (hmac[off + 3] & 0xff);

    const calc = (binary % 1000000).toString().padStart(6, '0');
    if (calc === code) {
      return true;
    }
  }

  return false;
}
