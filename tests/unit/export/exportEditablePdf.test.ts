import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { PDFDocument } from 'pdf-lib';
import {
  generateEditablePdfFromElement,
  computeSha256HexFromBytes,
  FOLIO_WIDTH_PT,
  FOLIO_HEIGHT_PT,
  FORENSIC_RED_HEX,
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
      codigoPlanilla: 'PLN-2026-000001',
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
      codigoPlanilla: 'PLN-2026-000099',
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

    const pdfBytes = await generateEditablePdfFromElement(div, 'Acta con Firmas', {
      codigoPlanilla: 'PLN-2026-000042',
      modalidadFirma: 'adobe_electronica',
    });
    const doc = await PDFDocument.load(pdfBytes);
    const form = doc.getForm();
    const fields = form.getFields();

    // Verificar que los campos de firma sean reconocidos como PDFSignature
    const sigFields = fields.filter((f) => f.constructor.name === 'PDFSignature');
    const sigNames = sigFields.map((f) => f.getName());

    expect(sigNames).toContain('FirmaDigital_PeritoPrincipal_DEFR');
    expect(sigNames).toContain('FirmaDigital_CoPerito_O_Consignante');
  });

  it('PDF-04: PrintToolbar.astro mantiene únicamente el botón rojo Generar Planilla (QR + PDF) sin formas alternativas de exportación', () => {
    const toolbarPath = path.resolve(process.cwd(), 'src/components/layout/PrintToolbar.astro');
    const toolbarContent = fs.readFileSync(toolbarPath, 'utf8');

    expect(toolbarContent).toContain('id="btn-generar-planilla-qr"');
    expect(toolbarContent).toContain('Generar Planilla (QR + PDF)');
    expect(toolbarContent).not.toContain('id="btn-descargar-pdf-editable"');
    expect(toolbarContent).not.toContain('id="btn-descargar-word"');
    expect(toolbarContent).not.toContain('id="btn-imprimir-folio"');
  });

  it('PDF-05: PlanillasCatalogoView.astro deja únicamente el botón Ver Formato en cada tarjeta', () => {
    const catalogoPath = path.resolve(process.cwd(), 'src/components/views/PlanillasCatalogoView.astro');
    const catalogoContent = fs.readFileSync(catalogoPath, 'utf8');

    expect(catalogoContent).toContain('Ver Formato');
    expect(catalogoContent).not.toContain('btn-descargar-pdf-editable');
    expect(catalogoContent).not.toContain('btn-descargar-docx');
    expect(catalogoContent).not.toContain('link-generar-planilla');
  });

  it('PDF-06: Estampa el número único de planilla, SHA-256 y enlace QR Rojo en metadatos del PDF', async () => {
    const div = document.createElement('div');
    div.innerHTML = '<div class="page"><div>Planilla Hoja 1</div></div><div class="page"><div>Planilla Hoja 2</div></div>';

    const hashTest = 'a'.repeat(64);
    const pdfBytes = await generateEditablePdfFromElement(div, 'Dictamen Colegiado', {
      codigoPlanilla: 'PLN-2026-000077',
      hashEmisionSha256: hashTest,
      peritoNombre: 'Jull Joll',
      peritoCiv: 'CIV-299410',
      coPeritoNombre: 'SHA256 Adquisición',
      coPeritoCiv: 'CIV-310520',
      qrVerificationUrl: 'https://sha256.us/verificar?codigo=PLN-2026-000077',
      modalidadFirma: 'hibrida',
    });

    const doc = await PDFDocument.load(pdfBytes);
    expect(doc.getPages().length).toBe(2);
    expect(doc.getTitle()).toContain('PLN-2026-000077');
    expect(doc.getSubject()).toContain(hashTest);
    expect(FORENSIC_RED_HEX).toBe('#B50909');

    const shaBin = await computeSha256HexFromBytes(pdfBytes);
    expect(shaBin).toMatch(/^[a-f0-9]{64}$/);
  });

  it('PDF-07: Existen los módulos de Emisión Modal, Popup QR público y API cPanel de planillas emitidas', () => {
    const root = process.cwd();
    const modalSrc = fs.readFileSync(path.resolve(root, 'src/components/planillas/EmitirPdfAdobeModal.astro'), 'utf8');
    const popupSrc = fs.readFileSync(path.resolve(root, 'src/components/verificacion/VerificacionQrPopup.astro'), 'utf8');
    const pageSrc = fs.readFileSync(path.resolve(root, 'src/pages/verificar.astro'), 'utf8');
    const phpSrc = fs.readFileSync(path.resolve(root, 'public/api/planillas-emitidas.php'), 'utf8');

    expect(modalSrc).toContain('fccoOpenEmitirPdfModal');
    expect(modalSrc).toContain('adobe_electronica');
    expect(modalSrc).toContain('manual_autografa');
    expect(modalSrc).toContain('#b50909');

    expect(popupSrc).toContain('fccoOpenVerificacionQrPopup');
    expect(popupSrc).toContain('renderCode128Svg');
    expect(popupSrc).toContain('computeSha256HexFromBytes');

    expect(pageSrc).toContain('<VerificacionQrPopup autoOpen={true}');
    expect(pageSrc).toContain('Corroborar Autenticidad de Planilla Impresa o PDF');

    expect(phpSrc).toContain('Session::requireUser()');
    expect(phpSrc).toContain('Session::requireCsrf()');
    expect(phpSrc).toContain('Canonical::hash');
    expect(phpSrc).toContain('EMISION_PDF_ADOBE');
    expect(phpSrc).toContain('planillas_emitidas');
  });

  it('PDF-08: exportEditablePdf elimina html2canvas y preserva paridad 1:1 con Ver Formato (html-to-image + iframe CSS real + sello QR nativo)', () => {
    const engineSrc = fs.readFileSync(
      path.resolve(process.cwd(), 'src/lib/export/exportEditablePdf.ts'),
      'utf8'
    );

    // Nunca debe importar ni invocar html2canvas ni colapsar la altura 330mm
    expect(engineSrc).not.toMatch(/import\s+html2canvas|from\s+['"]html2canvas['"]/);
    expect(engineSrc).not.toContain("p.style.height = 'auto'");
    // Usa el motor nativo del navegador (html-to-image) + sello QR incrustado en DOM real
    expect(engineSrc).toContain("from 'html-to-image'");
    expect(engineSrc).toContain('toPng(');
    expect(engineSrc).toContain('estamparSelloQrEnDom');
    // Usa iframe aislado con folio-aislado.css real al descargar desde /planillas
    expect(engineSrc).toContain('loadPlanillaInStyledIframe');
    expect(engineSrc).toContain('render_pdf=1');
    // Mapeo dinámico de celdas reales y líneas de firma sin tapar huelleros
    expect(engineSrc).toContain('measurePageAcroFields');
    expect(engineSrc).toContain('measurePageSignatureBoxes');
  });
});
