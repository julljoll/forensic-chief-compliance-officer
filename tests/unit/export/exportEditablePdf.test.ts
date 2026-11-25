import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { PDFDocument } from 'pdf-lib';
import {
  generateEditablePdfFromElement,
  FOLIO_WIDTH_PT,
  FOLIO_HEIGHT_PT,
} from '../../../src/lib/export/exportEditablePdf';

describe('exportEditablePdf — Generador de Planillas en PDF Editable para Adobe Acrobat', () => {
  it('PDF-01: generateEditablePdfFromElement genera un PDF con dimensiones exactas Folio (216mm × 330mm)', async () => {
    const div = document.createElement('div');
    div.innerHTML = `
      <div class="folio-forense-aislado">
        <div class="page">
          <h1>Acta de Consentimiento</h1>
          <p>Diligencia pericial forense</p>
        </div>
      </div>
    `;

    const pdfBytes = await generateEditablePdfFromElement(div, 'Acta de Consentimiento', {
      numeroExpediente: 'EXP-2026-TEST-001',
      numeroPRCC: 'PRCC-2026-0001',
      peritoNombre: 'Perito Forense de Prueba',
    });

    expect(pdfBytes).toBeInstanceOf(Uint8Array);
    expect(pdfBytes.length).toBeGreaterThan(1000);

    const doc = await PDFDocument.load(pdfBytes);
    const pages = doc.getPages();
    expect(pages.length).toBe(1);

    const size = pages[0].getSize();
    expect(Math.round(size.width)).toBe(Math.round(FOLIO_WIDTH_PT));
    expect(Math.round(size.height)).toBe(Math.round(FOLIO_HEIGHT_PT));
  });

  it('PDF-02: El PDF contiene campos de formulario AcroForm editables para Adobe Acrobat', async () => {
    const div = document.createElement('div');
    div.innerHTML = '<div class="page"><div>Contenido de prueba</div></div>';

    const pdfBytes = await generateEditablePdfFromElement(div, 'Acta Pericial', {
      numeroExpediente: 'EXP-2026-0099',
      numeroPRCC: 'PRCC-2026-0099',
      peritoNombre: 'Ing. Perito Forense',
    });

    const doc = await PDFDocument.load(pdfBytes);
    const form = doc.getForm();
    const fields = form.getFields().map((f) => f.getName());

    expect(fields).toContain('NUMERO_EXPEDIENTE');
    expect(fields).toContain('NUMERO_PRCC');
    expect(fields).toContain('PERITO_RESPONSABLE');
    expect(fields).toContain('CONSIGNANTE_SOLICITANTE');
    expect(fields).toContain('OBSERVACIONES_PERICIALES');

    const expField = form.getTextField('NUMERO_EXPEDIENTE');
    expect(expField.getText()).toBe('EXP-2026-0099');
  });

  it('PDF-03: Registra campos nativos de Firma Electrónica Digital ISO 32000-1 (/FT /Sig) para Adobe Acrobat', async () => {
    const div = document.createElement('div');
    div.innerHTML = '<div class="page"><div>Contenido de firmas</div></div>';

    const pdfBytes = await generateEditablePdfFromElement(div, 'Acta con Firmas');
    const doc = await PDFDocument.load(pdfBytes);
    const form = doc.getForm();
    const fields = form.getFields();

    // Verificar que los campos de firma sean reconocidos como PDFSignature
    const sigFields = fields.filter((f) => f.constructor.name === 'PDFSignature');
    const sigNames = sigFields.map((f) => f.getName());

    expect(sigNames).toContain('FirmaDigital_PeritoPrincipal_DEFR');
    expect(sigNames).toContain('FirmaDigital_CoPerito_O_Consignante');
  });

  it('PDF-04: PrintToolbar.astro contiene el botón oficial para descarga en PDF Editable (Adobe)', () => {
    const toolbarPath = path.resolve(process.cwd(), 'src/components/layout/PrintToolbar.astro');
    const toolbarContent = fs.readFileSync(toolbarPath, 'utf8');

    expect(toolbarContent).toContain('id="btn-descargar-pdf-editable"');
    expect(toolbarContent).toContain('PDF Editable (Adobe)');
    expect(toolbarContent).toContain('sprite.svg#edit');
  });

  it('PDF-05: PlanillasCatalogoView.astro integra el botón de descarga PDF (Adobe) en cada tarjeta', () => {
    const catalogoPath = path.resolve(process.cwd(), 'src/components/views/PlanillasCatalogoView.astro');
    const catalogoContent = fs.readFileSync(catalogoPath, 'utf8');

    expect(catalogoContent).toContain('btn-descargar-pdf-editable');
    expect(catalogoContent).toContain('PDF (Adobe)');
    expect(catalogoContent).toContain('descargarPlanillaPdfEditablePorSlug');
  });
});
