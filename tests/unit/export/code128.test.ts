import { describe, it, expect } from 'vitest';
import { encodeCode128B, renderCode128Svg } from '../../../src/lib/export/code128';

describe('code128 — Codificador Vectorial ISO/IEC 15417 Code-128B', () => {
  it('BAR-01: Codifica PLN-2026-000042 con longitud modular exacta ISO 15417 ((n+2)*11 + 13)', () => {
    const code = 'PLN-2026-000042';
    const encoded = encodeCode128B(code);

    expect(encoded.text).toBe(code);
    // Start (11) + 15 chars (15*11) + Checksum (11) + Stop (13) = 17*11 + 13 = 200 módulos
    expect(encoded.totalModules).toBe((code.length + 2) * 11 + 13);
    expect(encoded.modules.startsWith('11010010000')).toBe(true); // START B = 211214
    expect(encoded.modules.endsWith('1100011101011')).toBe(true);  // STOP = 2331112
    expect(encoded.bars.length).toBeGreaterThan(20);
  });

  it('BAR-02: Calcula dígito verificador módulo 103 determinista', () => {
    const resA = encodeCode128B('PLN-2026-000001');
    const resB = encodeCode128B('PLN-2026-000002');
    expect(resA.checksum).toBeGreaterThanOrEqual(0);
    expect(resA.checksum).toBeLessThan(103);
    expect(resA.checksum).not.toBe(resB.checksum);
  });

  it('BAR-03: renderCode128Svg genera SVG rojo (#B50909) con rectángulos vectoriales', () => {
    const svg = renderCode128Svg('PLN-2026-000042', { color: '#B50909', height: 34 });
    expect(svg).toContain('<svg');
    expect(svg).toContain('fill="#B50909"');
    expect(svg).toContain('aria-label="Código de barras PLN-2026-000042"');
    expect(svg).toContain('<rect');
  });

  it('BAR-04: Rechaza entradas vacías sin caracteres ASCII imprimibles', () => {
    expect(() => encodeCode128B('   ')).toThrow();
  });
});
