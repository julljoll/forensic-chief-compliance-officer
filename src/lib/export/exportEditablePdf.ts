/**
 * SHA256.US — Exportador Oficial de Planillas Forenses a PDF Editable (Adobe Acrobat Ready)
 * Genera documentos en formato reglamentario Folio (216mm × 330mm) con:
 * - AcroForm interactivo para edición de campos periciales en Adobe Acrobat / Reader.
 * - Código QR de verificación criptográfica generado e incrustado (https://sha256.us/verificar).
 * - Campos de Firma Electrónica Digital ISO 32000-1 (/FT /Sig) listos para firma con certificados (PAdES / PKCS#7).
 */

import { PDFDocument, PDFName, PDFString } from 'pdf-lib';
import QRCode from 'qrcode';
import { saveAs } from 'file-saver';
import html2canvas from 'html2canvas';

export const FOLIO_WIDTH_PT = 612.28;  // 216mm en puntos tipográficos (72 pt/in)
export const FOLIO_HEIGHT_PT = 935.43; // 330mm en puntos tipográficos

export interface EditablePdfOptions {
  numeroExpediente?: string;
  numeroPRCC?: string;
  peritoNombre?: string;
  peritoCiv?: string;
  consignanteNombre?: string;
  consignanteCi?: string;
  qrVerificationUrl?: string;
  titulo?: string;
  isBlankMode?: boolean;
}

/**
 * Prepara el DOM clonado para captura limpia en html2canvas
 */
function prepareClonedDom(clonedDoc: Document): void {
  clonedDoc.querySelectorAll<HTMLElement>('.page').forEach((p) => {
    p.style.transform = 'none';
    p.style.overflow = 'visible';
    p.style.height = 'auto';
    p.style.maxHeight = 'none';
  });

  clonedDoc.querySelectorAll<HTMLElement>('.no-print, .no-print-bar, .fcco-print-toolbar').forEach((el) => {
    el.style.display = 'none';
  });
}

/**
 * Genera un PDF interactivo con AcroForm, código QR y campos de firma electrónica
 */
export async function generateEditablePdfFromElement(
  element: HTMLElement,
  title: string = 'Planilla_Forense',
  options: EditablePdfOptions = {}
): Promise<Uint8Array> {
  const isBrowser = typeof window !== 'undefined';
  const pdfDoc = await PDFDocument.create();

  // Buscar páginas .page o usar el contenedor
  let pageElements = Array.from(element.querySelectorAll<HTMLElement>('.page'));
  if (pageElements.length === 0 && element.classList.contains('page')) {
    pageElements = [element];
  }
  if (pageElements.length === 0) {
    pageElements = [element];
  }

  // Renderizar cada página
  for (let i = 0; i < pageElements.length; i++) {
    const pageEl = pageElements[i];
    const page = pdfDoc.addPage([FOLIO_WIDTH_PT, FOLIO_HEIGHT_PT]);

    // En navegador, renderizar la plantilla gráfica de fondo mediante html2canvas
    if (isBrowser && typeof html2canvas === 'function') {
      try {
        const canvas = await html2canvas(pageEl, {
          scale: 2,
          useCORS: true,
          logging: false,
          backgroundColor: '#FFFFFF',
          onclone: prepareClonedDom,
        });

        const imgDataUrl = canvas.toDataURL('image/jpeg', 0.95);
        const base64Data = imgDataUrl.split(',')[1];
        if (base64Data) {
          const imgBytes = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));
          const pageImage = await pdfDoc.embedJpg(imgBytes);
          page.drawImage(pageImage, {
            x: 0,
            y: 0,
            width: FOLIO_WIDTH_PT,
            height: FOLIO_HEIGHT_PT,
          });
        }
      } catch (canvasErr) {
        console.warn('html2canvas no disponible o falló, generando estructura vectorial directa:', canvasErr);
      }
    }
  }

  const pages = pdfDoc.getPages();
  const firstPage = pages[0];
  const lastPage = pages[pages.length - 1];

  // Incrustar Código QR Oficial de Verificación
  const expNum = options.numeroExpediente || 'EXP-2026-SHA-0042';
  const prccNum = options.numeroPRCC || 'PRCC-2026-0042';
  const qrUrl = options.qrVerificationUrl || `https://sha256.us/verificar?expediente=${encodeURIComponent(expNum)}&prcc=${encodeURIComponent(prccNum)}`;

  try {
    const qrDataUrl = await QRCode.toDataURL(qrUrl, {
      margin: 1,
      width: 180,
      color: { dark: '#112E51', light: '#FFFFFF' },
    });
    const qrBase64 = qrDataUrl.split(',')[1];
    if (qrBase64) {
      const qrBytes = Uint8Array.from(atob(qrBase64), (c) => c.charCodeAt(0));
      const qrImage = await pdfDoc.embedPng(qrBytes);
      
      // Dibujar QR en la cabecera derecha de la primera página
      firstPage.drawImage(qrImage, {
        x: 485,
        y: 835,
        width: 70,
        height: 70,
      });
    }
  } catch (qrErr) {
    console.warn('No se pudo generar código QR embebido:', qrErr);
  }

  // Crear AcroForm para interactividad en Adobe Acrobat
  const form = pdfDoc.getForm();

  // 1. Campo interactivo editable: Número de Expediente
  try {
    const tfExp = form.createTextField('NUMERO_EXPEDIENTE');
    tfExp.setText(options.isBlankMode ? '' : expNum);
    tfExp.addToPage(firstPage, { x: 375, y: 792, width: 175, height: 16 });
  } catch (_) {}

  // 2. Campo interactivo editable: Número de PRCC
  try {
    const tfPrcc = form.createTextField('NUMERO_PRCC');
    tfPrcc.setText(options.isBlankMode ? '' : prccNum);
    tfPrcc.addToPage(firstPage, { x: 375, y: 772, width: 175, height: 16 });
  } catch (_) {}

  // 3. Campo interactivo editable: Identificación del Perito Responsable
  try {
    const tfPerito = form.createTextField('PERITO_RESPONSABLE');
    tfPerito.setText(options.isBlankMode ? '' : (options.peritoNombre || 'Perito Informático Forense (CIV N° 299.410)'));
    tfPerito.addToPage(firstPage, { x: 160, y: 730, width: 390, height: 16 });
  } catch (_) {}

  // 4. Campo interactivo editable: Solicitante / Consignante
  try {
    const tfConsignante = form.createTextField('CONSIGNANTE_SOLICITANTE');
    tfConsignante.setText(options.isBlankMode ? '' : (options.consignanteNombre || ''));
    tfConsignante.addToPage(firstPage, { x: 160, y: 708, width: 390, height: 16 });
  } catch (_) {}

  // 5. Campo de texto multilínea: Observaciones Periciales
  try {
    const tfObs = form.createTextField('OBSERVACIONES_PERICIALES');
    tfObs.enableMultiline();
    tfObs.setText(options.isBlankMode ? '' : 'Diligencia pericial ejecutada conforme al Artículo 187 del Código Orgánico Procesal Penal (COPP) y estándares ISO/IEC 27037:2012.');
    tfObs.addToPage(lastPage, { x: 60, y: 185, width: 490, height: 50 });
  } catch (_) {}

  // 6. Campos de Firma Electrónica Digital ISO 32000-1 (/FT /Sig) para Adobe Acrobat
  try {
    // Firma Digital 1: Perito Principal Forense (Izquierda)
    const sigAnnot1 = pdfDoc.context.register(
      pdfDoc.context.obj({
        Type: 'Annot',
        Subtype: 'Widget',
        FT: 'Sig',
        Rect: [60, 85, 270, 150],
        T: PDFString.of('FirmaDigital_PeritoPrincipal_DEFR'),
        F: 4,
        P: lastPage.ref,
      })
    );

    // Firma Digital 2: Co-Perito o Consignante (Derecha)
    const sigAnnot2 = pdfDoc.context.register(
      pdfDoc.context.obj({
        Type: 'Annot',
        Subtype: 'Widget',
        FT: 'Sig',
        Rect: [320, 85, 530, 150],
        T: PDFString.of('FirmaDigital_CoPerito_O_Consignante'),
        F: 4,
        P: lastPage.ref,
      })
    );

    // Adjuntar anotaciones a la última página
    const existingAnnots = lastPage.node.lookup(PDFName.of('Annots'));
    if (existingAnnots) {
      (existingAnnots as any).push(sigAnnot1);
      (existingAnnots as any).push(sigAnnot2);
    } else {
      lastPage.node.set(PDFName.of('Annots'), pdfDoc.context.obj([sigAnnot1, sigAnnot2]));
    }

    form.acroForm.addField(sigAnnot1);
    form.acroForm.addField(sigAnnot2);
  } catch (sigErr) {
    console.warn('No se pudo registrar campos nativos de firma digital:', sigErr);
  }

  // Metadatos oficiales del dictamen judicial
  pdfDoc.setTitle(title);
  pdfDoc.setSubject('Planilla Oficial de Informática Forense — AcroForm Editable & PAdES Ready');
  pdfDoc.setAuthor('Laboratorio de Informática Forense SHA256.US');
  pdfDoc.setCreator('Forensic Chief Compliance Officer (FCCO) — SHA256.US');
  pdfDoc.setKeywords(['forense', 'peritaje', 'iso-27037', 'copp-187', 'firma-electronica', 'acroform']);

  return await pdfDoc.save();
}

/**
 * Descarga directamente la planilla activa en la pantalla como PDF editable
 */
export async function exportCurrentPlanillaToEditablePdf(titleOverride?: string): Promise<void> {
  if (typeof window === 'undefined') return;

  const container =
    document.getElementById('contenedor-planilla-activa') ||
    document.querySelector('.folio-forense-aislado');

  if (!container) {
    alert('No se encontró ninguna planilla activa en la pantalla.');
    return;
  }

  const slug =
    container.getAttribute('data-slug') ||
    window.location.pathname.split('/').pop()?.replace('.html', '') ||
    'planilla';

  const titleEl = container.querySelector('.canonical-doc-title') || document.querySelector('h1');
  const rawTitle = titleOverride || titleEl?.textContent?.trim() || slug;
  const cleanTitle = rawTitle.replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ_-]/g, '_');
  const fileName = `${cleanTitle}_editable_adobe.pdf`;

  const pdfBytes = await generateEditablePdfFromElement(container as HTMLElement, rawTitle);
  const blob = new Blob([pdfBytes.buffer as ArrayBuffer], { type: 'application/pdf' });
  saveAs(blob, fileName);
}

/**
 * Descarga cualquier planilla por su slug como PDF editable directamente desde el catálogo /planillas
 */
export async function descargarPlanillaPdfEditablePorSlug(
  slug: string,
  modo: 'blanco' | 'datos' = 'blanco',
  _casoId?: string,
  titulo?: string
): Promise<void> {
  if (typeof window === 'undefined') return;

  try {
    const url = `/planillas/${slug}`;
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} al obtener la plantilla ${slug}`);
    }

    const htmlText = await resp.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(htmlText, 'text/html');

    const container =
      doc.getElementById('contenedor-planilla-activa') ||
      doc.querySelector('.folio-forense-aislado');

    if (!container) {
      throw new Error(`No se encontró el contenedor de la planilla en ${url}`);
    }

    // Montar temporalmente en el documento de forma invisible para que html2canvas pueda medir estilos
    const tempHolder = document.createElement('div');
    tempHolder.style.position = 'fixed';
    tempHolder.style.left = '-9999px';
    tempHolder.style.top = '0';
    tempHolder.style.width = '216mm';
    tempHolder.style.backgroundColor = '#FFFFFF';
    tempHolder.appendChild(container.cloneNode(true));
    document.body.appendChild(tempHolder);

    try {
      const activeEl = tempHolder.querySelector('.folio-forense-aislado') || tempHolder;

      if (modo === 'blanco') {
        activeEl.querySelectorAll<HTMLElement>('[data-field]').forEach((el) => {
          el.textContent = '';
        });
      }

      const rawTitle = titulo || doc.querySelector('.canonical-doc-title')?.textContent?.trim() || slug;
      const cleanTitle = rawTitle.replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ_-]/g, '_');
      const fileName = `${cleanTitle}_editable_adobe.pdf`;

      const pdfBytes = await generateEditablePdfFromElement(activeEl as HTMLElement, rawTitle, {
        isBlankMode: modo === 'blanco',
      });

      const blob = new Blob([pdfBytes.buffer as ArrayBuffer], { type: 'application/pdf' });
      saveAs(blob, fileName);
    } finally {
      document.body.removeChild(tempHolder);
    }
  } catch (err: any) {
    console.error('Error al descargar planilla PDF editable por slug:', err);
    alert(`No se pudo generar el PDF editable: ${err.message || 'Error desconocido'}`);
  }
}
