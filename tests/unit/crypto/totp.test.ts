import { describe, it, expect } from 'vitest';
import {
  base32Decode,
  base32Encode,
  generarSecretoBase32,
  construirUriTotp,
  generarCodigosRecuperacion,
  generarTotpCode,
  verificarTotpCode,
} from '../../../src/lib/crypto/totp';

describe('Módulo Criptográfico TOTP (RFC 6238 / RFC 4648)', () => {
  it('debe codificar y decodificar Base32 de forma simétrica', () => {
    const original = new TextEncoder().encode('Forensic Compliance Officer SHA256.US');
    const encoded = base32Encode(original);
    expect(typeof encoded).toBe('string');
    expect(encoded.length).toBeGreaterThan(0);

    const decoded = base32Decode(encoded);
    const restored = new TextDecoder().decode(decoded);
    expect(restored).toBe('Forensic Compliance Officer SHA256.US');
  });

  it('debe generar secreto Base32 criptográfico de 160 bits (32 caracteres)', () => {
    const secret = generarSecretoBase32(20);
    expect(secret).toHaveLength(32);
    expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);

    const decoded = base32Decode(secret);
    expect(decoded.byteLength).toBe(20);
  });

  it('debe construir la URI otpauth estándar para Google Authenticator', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const uri = construirUriTotp('perito@sha256.us', secret, 'SHA256.US');
    expect(uri).toContain('otpauth://totp/SHA256.US:perito%40sha256.us');
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(uri).toContain('issuer=SHA256.US');
    expect(uri).toContain('algorithm=SHA1');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });

  it('debe generar 8 códigos de recuperación de emergencia únicos', () => {
    const codigos = generarCodigosRecuperacion(8);
    expect(codigos).toHaveLength(8);
    const set = new Set(codigos);
    expect(set.size).toBe(8); // Todos únicos

    for (const c of codigos) {
      expect(c).toHaveLength(8);
      // No contiene caracteres confusos como O, 0, I, 1
      expect(/[0O1I]/.test(c)).toBe(false);
    }
  });

  it('debe generar y verificar códigos TOTP válidos en la ventana de 30 segundos', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const code = await generarTotpCode(secret);
    expect(code).toHaveLength(6);
    expect(/^\d{6}$/.test(code)).toBe(true);

    const valido = await verificarTotpCode(secret, code, 1);
    expect(valido).toBe(true);
  });

  it('debe rechazar códigos TOTP incorrectos, malformados o vacíos', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    expect(await verificarTotpCode(secret, '000000', 0)).toBe(false);
    expect(await verificarTotpCode(secret, '12345', 1)).toBe(false);
    expect(await verificarTotpCode(secret, 'abcdef', 1)).toBe(false);
    expect(await verificarTotpCode(secret, '', 1)).toBe(false);
  });
});
