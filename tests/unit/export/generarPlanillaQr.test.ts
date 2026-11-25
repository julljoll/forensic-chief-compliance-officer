import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  QR_FORENSIC_RED,
  generateRedQrSvg,
  estamparSelloQrEnDom,
} from '../../../src/lib/export/generarPlanillaQr';
import { renderCode128Svg } from '../../../src/lib/export/code128';

describe('generarPlanillaQr — Sello QR Rojo Nativo en las 13 Planillas Oficiales (Paridad 100%)', () => {
  it('QRN-01: generateRedQrSvg produce un SVG vectorial válido en color rojo forense #B50909', async () => {
    const svg = await generateRedQrSvg('https://sha256.us/verificar?codigo=PLN-2026-000001');
    expect(QR_FORENSIC_RED).toBe('#B50909');
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
    expect(svg.toUpperCase()).toContain('#B50909');
  });

  it('QRN-02: estamparSelloQrEnDom revela el sello QR rojo en PlanillaHeader y estampa el SHA-256 en PlanillaFooter', async () => {
    const root = document.createElement('div');
    root.innerHTML = `
      <div class="page">
        <div class="header-institution-row">
          <div class="header-right-cluster">
            <div class="header-control-box">FO-F0-01</div>
            <div class="header-qr-seal" data-qr-seal="1" data-hoja="1" hidden>
              <a class="header-qr-svg" data-qr-svg href="/verificar"></a>
              <div class="header-qr-meta">
                <span class="header-qr-badge">SHA256.US · QR</span>
                <strong class="header-qr-code" data-qr-code></strong>
                <div class="header-qr-bars" data-qr-bars></div>
              </div>
            </div>
          </div>
        </div>
        <footer class="canonical-footer">
          <span class="footer-crypto-hash" data-field="hashSHA256" data-qr-sha256=""></span>
        </footer>
      </div>
    `;

    const qrUrl = 'https://sha256.us/verificar?codigo=PLN-2026-000123';
    const hashTest = 'b'.repeat(64);
    const qrSvg = await generateRedQrSvg(qrUrl);
    const barcodeSvg = renderCode128Svg('PLN-2026-000123', { color: QR_FORENSIC_RED, height: 14 });

    const stamped = estamparSelloQrEnDom(root, {
      codigoPlanilla: 'PLN-2026-000123',
      qrUrl,
      hashEmisionSha256: hashTest,
      qrSvg,
      barcodeSvg,
      offlineDraft: false,
    });

    expect(stamped).toBe(1);

    const row = root.querySelector('.header-institution-row')!;
    expect(row.classList.contains('has-qr-seal')).toBe(true);

    const seal = root.querySelector<HTMLElement>('[data-qr-seal]')!;
    expect(seal.hidden).toBe(false);
    expect(seal.getAttribute('data-codigo-planilla')).toBe('PLN-2026-000123');

    const link = root.querySelector<HTMLAnchorElement>('[data-qr-svg]')!;
    expect(link.href).toBe(qrUrl);
    expect(link.innerHTML).toContain('<svg');

    const codeEl = root.querySelector<HTMLElement>('[data-qr-code]')!;
    expect(codeEl.textContent).toBe('PLN-2026-000123');

    const barsEl = root.querySelector<HTMLElement>('[data-qr-bars]')!;
    expect(barsEl.innerHTML).toContain('<svg');

    const hashEl = root.querySelector<HTMLElement>('[data-qr-sha256]')!;
    expect(hashEl.textContent).toContain(hashTest);
    expect(hashEl.textContent).toContain('PLN-2026-000123');
  });

  it('QRN-03: PlanillaHeader, PlanillaFooter y folio-aislado.css integran nativamente .header-qr-seal con impresión en rojo exacto #B50909', () => {
    const root = process.cwd();
    const headerSrc = fs.readFileSync(path.resolve(root, 'src/components/planillas/PlanillaHeader.astro'), 'utf8');
    const footerSrc = fs.readFileSync(path.resolve(root, 'src/components/planillas/PlanillaFooter.astro'), 'utf8');
    const cssSrc = fs.readFileSync(path.resolve(root, 'src/styles/folio-aislado.css'), 'utf8');

    expect(headerSrc).toContain('header-right-cluster');
    expect(headerSrc).toContain('header-qr-seal');
    expect(headerSrc).toContain('data-qr-seal="1"');
    expect(headerSrc).toContain('data-qr-svg');
    expect(headerSrc).toContain('data-qr-code');
    expect(headerSrc).toContain('data-qr-bars');

    expect(footerSrc).toContain('data-qr-sha256');

    expect(cssSrc).toContain('.header-qr-seal');
    expect(cssSrc).toContain('#B50909');
    expect(cssSrc).toContain('print-color-adjust: exact !important;');
  });

  it('QRN-04: PlanillasCatalogoView solo muestra Ver Formato y PrintToolbar deja exclusivamente el botón rojo Generar Planilla (QR + PDF)', () => {
    const root = process.cwd();
    const toolbarSrc = fs.readFileSync(path.resolve(root, 'src/components/layout/PrintToolbar.astro'), 'utf8');
    const layoutSrc = fs.readFileSync(path.resolve(root, 'src/layouts/PrintLayout.astro'), 'utf8');
    const catalogoSrc = fs.readFileSync(path.resolve(root, 'src/components/views/PlanillasCatalogoView.astro'), 'utf8');

    // En la barra superior del formato: solo el botón rojo Generar Planilla (QR + PDF) para emitir (sin Word, sin PDF Editable ni Imprimir simple)
    expect(toolbarSrc).toContain('id="btn-generar-planilla-qr"');
    expect(toolbarSrc).toContain('Generar Planilla (QR + PDF)');
    expect(toolbarSrc).toContain('id="banner-planilla-sellada"');
    expect(toolbarSrc).toContain('sprite.svg#verified_user');
    expect(toolbarSrc).not.toContain('id="btn-descargar-word"');
    expect(toolbarSrc).not.toContain('id="btn-descargar-pdf-editable"');
    expect(toolbarSrc).not.toContain('id="btn-imprimir-folio"');
    expect(toolbarSrc).not.toMatch(/[\u{1F300}-\u{1F9FF}]/u);

    expect(layoutSrc).toContain('generarPlanillaConQrNativo');
    expect(layoutSrc).toContain('banner-planilla-sellada');
    expect(layoutSrc).not.toContain('exportCurrentPlanillaToWordDocx');
    expect(layoutSrc).not.toContain('exportCurrentPlanillaToEditablePdf');

    // En las tarjetas del catálogo: únicamente el botón Ver Formato
    expect(catalogoSrc).toContain('Ver Formato');
    expect(catalogoSrc).toContain('link-abrir-planilla');
    expect(catalogoSrc).not.toContain('link-generar-planilla');
    expect(catalogoSrc).not.toContain('btn-descargar-docx');
    expect(catalogoSrc).not.toContain('btn-descargar-pdf-editable');
    expect(catalogoSrc).not.toMatch(/[\u{1F300}-\u{1F9FF}]/u);
  });
});
