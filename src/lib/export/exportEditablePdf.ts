/**
 * SHA256.US — Exportador de Planillas Forenses a PDF Editable (Adobe Acrobat Ready)
 *
 * Motor de Alta Fidelidad SIN html2canvas:
 * 1. Usa el motor nativo del navegador (`html-to-image` SVG foreignObject) sobre el documento
 *    renderizado con `folio-aislado.css` real (vía `<iframe>` aislado desde /planillas),
 *    eliminando la ruptura de `all: initial`, unidades `mm` y tablas `0.6pt` que causaba html2canvas.
 * 2. Estampa nativamente el Sello QR Rojo (`#B50909`) + Barras Code-128 + N° de Planilla dentro
 *    de `.header-qr-seal` (PlanillaHeader.astro) y el SHA-256 en PlanillaFooter.astro.
 * 3. Mapea dinámicamente (`getBoundingClientRect`) campos AcroForm transparentes sobre `[data-field]`,
 *    vínculo clicable `/Subtype /Link` sobre el QR rojo y firmas digitales `/FT /Sig` sobre `.sig-line-solid`.
 * 4. Sellado atómico en 2 fases contra cPanel MySQL (`planillas_emitidas` + `auditoria`).
 */

import { PDFDocument, PDFName, PDFString, StandardFonts, rgb } from 'pdf-lib';
import QRCode from 'qrcode';
import { saveAs } from 'file-saver';
import { toPng } from 'html-to-image';
import { encodeCode128B, renderCode128Svg } from './code128';
import { estamparSelloQrEnDom, generateRedQrSvg } from './generarPlanillaQr';
import { LOGO_PNG_BASE64 } from './logoBase64';
import { hashCanonical } from '../crypto/canonical';
import {
  phpApi,
  type ModalidadFirmaPlanilla,
  type PlanillaEmitidaDTO,
} from '../data/phpApi';

export const FOLIO_WIDTH_PT = 612.28;  // 216mm en puntos tipográficos (72 pt/in)
export const FOLIO_HEIGHT_PT = 935.43; // 330mm en puntos tipográficos
export const FORENSIC_RED_HEX = '#B50909';

const RED_RGB = rgb(0.71, 0.035, 0.035);       // #B50909 — Rojo Forense Oficial USWDS
const INK_RGB = rgb(0.106, 0.165, 0.29);       // #1B2A4A — Dark Ink USWDS
const WHITE_RGB = rgb(1, 1, 1);

export interface EditablePdfOptions {
  codigoPlanilla?: string;
  codigoDoc?: string;
  faseIso?: string;
  numeroExpediente?: string;
  numeroPRCC?: string;
  peritoNombre?: string;
  peritoCi?: string;
  peritoCiv?: string;
  peritoInpre?: string;
  peritoCargo?: string;
  peritoTelefono?: string;
  peritoDireccion?: string;
  coPeritoNombre?: string;
  coPeritoCiv?: string;
  consignanteNombre?: string;
  consignanteCi?: string;
  modalidadFirma?: ModalidadFirmaPlanilla;
  hashEmisionSha256?: string;
  emitidoEnUtc?: string;
  qrVerificationUrl?: string;
  qrColorHex?: string;
  titulo?: string;
  isBlankMode?: boolean;
  offlineDraft?: boolean;
}

export interface EmitirPdfParams {
  slug: string;
  codigoDoc?: string;
  tituloPlanilla?: string;
  faseIso?: string;
  casoId?: string | null;
  numeroCaso?: string | null;
  numeroPRCC?: string | null;
  coPeritoNombre?: string | null;
  coPeritoCiv?: string | null;
  modalidadFirma?: ModalidadFirmaPlanilla;
  isBlankMode?: boolean;
}

export interface EmitirPdfResult {
  planilla: PlanillaEmitidaDTO;
  qrUrl: string;
  hashPdfSha256: string;
  fileName: string;
  offlineDraft: boolean;
}

interface PdfRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface MappedFieldBox {
  name: string;
  dataField: string;
  rect: PdfRect;
  multiline?: boolean;
}

interface MappedSignatureBox {
  name: string;
  tooltip: string;
  rect: PdfRect;
}

/**
 * Calcula el hash SHA-256 hexadecimal (64 chars) de un arreglo binario Uint8Array
 */
export async function computeSha256HexFromBytes(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', copy.buffer);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Sanitiza texto para fuentes estándar WinAnsi (Helvetica/Courier en pdf-lib)
 */
function safePdfText(input: string): string {
  return input
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[–—]/g, '-')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/[^\x20-\xFF]/g, '')
    .trim();
}

/**
 * Espera a que fuentes web e imágenes dentro de un documento terminen de decodificar
 */
async function waitForDocumentAssets(doc: Document): Promise<void> {
  try {
    if (doc.fonts && doc.fonts.ready) {
      await doc.fonts.ready;
    }
  } catch {
    // continuar en entornos sin FontFaceSet
  }

  const imgs = Array.from(doc.querySelectorAll<HTMLImageElement>('img'));
  await Promise.all(
    imgs.map(async (img) => {
      try {
        if (!img.complete) {
          await new Promise<void>((resolve) => {
            const done = () => resolve();
            img.addEventListener('load', done, { once: true });
            img.addEventListener('error', done, { once: true });
            setTimeout(done, 1500);
          });
        }
        if (typeof img.decode === 'function') {
          await img.decode().catch(() => {});
        }
      } catch {
        // continuar
      }
    })
  );
}

/**
 * Convierte un DOMRect relativo a `.page` en coordenadas exactas PDF Folio (`612.28pt × 935.43pt`)
 */
function domRectToPdfRect(childRect: DOMRect, pageRect: DOMRect): PdfRect {
  const scaleX = FOLIO_WIDTH_PT / pageRect.width;
  const scaleY = FOLIO_HEIGHT_PT / pageRect.height;

  const relLeft = childRect.left - pageRect.left;
  const relTop = childRect.top - pageRect.top;

  return {
    x: relLeft * scaleX,
    y: FOLIO_HEIGHT_PT - (relTop + childRect.height) * scaleY,
    width: childRect.width * scaleX,
    height: childRect.height * scaleY,
  };
}

/**
 * Mide los campos `[data-field]` reales de una `.page` renderizada para mapear AcroForm 1:1
 */
function measurePageAcroFields(pageEl: HTMLElement, pageIndex: number): MappedFieldBox[] {
  const pageRect = pageEl.getBoundingClientRect();
  if (!pageRect || pageRect.width < 100 || pageRect.height < 100) {
    return [];
  }

  const results: MappedFieldBox[] = [];
  const usedNames = new Set<string>();
  const dataFieldEls = Array.from(pageEl.querySelectorAll<HTMLElement>('[data-field]'));

  for (const el of dataFieldEls) {
    const rawKey = (el.getAttribute('data-field') || '').trim();
    if (!rawKey || rawKey === 'hashSHA256') continue;

    const tdParent = el.closest('td');
    const sigRowParent = el.closest('.sig-data-row') as HTMLElement | null;

    let targetRect: DOMRect;
    if (sigRowParent) {
      const rowRect = sigRowParent.getBoundingClientRect();
      const labelEl = sigRowParent.querySelector('strong');
      const labelRight = labelEl ? labelEl.getBoundingClientRect().right + 4 : rowRect.left + 4;
      const availW = Math.max(20, rowRect.right - labelRight - 3);
      targetRect = new DOMRect(labelRight, rowRect.top + 1, availW, Math.max(12, rowRect.height - 2));
    } else if (tdParent) {
      const tdRect = tdParent.getBoundingClientRect();
      targetRect = new DOMRect(tdRect.left + 2, tdRect.top + 1, Math.max(20, tdRect.width - 4), Math.max(12, tdRect.height - 2));
    } else {
      targetRect = el.getBoundingClientRect();
    }

    if (targetRect.width < 12 || targetRect.height < 8) continue;

    const pdfRect = domRectToPdfRect(targetRect, pageRect);
    if (pdfRect.x < 10 || pdfRect.y < 20 || pdfRect.x + pdfRect.width > FOLIO_WIDTH_PT - 5) {
      continue;
    }

    const canonicalMap: Record<string, string> = {
      numeroCaso: 'NUMERO_EXPEDIENTE',
      numeroPRCC: 'NUMERO_PRCC',
      perito_nombre: 'PERITO_RESPONSABLE',
      solicitante_nombre: 'CONSIGNANTE_SOLICITANTE',
      observaciones: 'OBSERVACIONES_PERICIALES',
    };

    const baseName = canonicalMap[rawKey] || `CAMPO_${rawKey.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}`;
    let fieldName = baseName;
    if (usedNames.has(fieldName)) {
      fieldName = `${baseName}_P${pageIndex + 1}_${results.length + 1}`;
    }
    usedNames.add(fieldName);

    results.push({
      name: fieldName,
      dataField: rawKey,
      rect: {
        x: pdfRect.x + 1,
        y: pdfRect.y + 0.5,
        width: Math.max(18, pdfRect.width - 2),
        height: Math.max(9, Math.min(48, pdfRect.height - 1)),
      },
      multiline: pdfRect.height >= 26,
    });
  }

  return results;
}

/**
 * Mide las zonas reales de firma (`.sig-line-solid` dentro de `.sig-box`) sin tapar datos ni huelleros
 */
function measurePageSignatureBoxes(
  pageEl: HTMLElement,
  peritoSigLabel: string,
  coPeritoSigLabel: string
): MappedSignatureBox[] {
  const pageRect = pageEl.getBoundingClientRect();
  if (!pageRect || pageRect.width < 100 || pageRect.height < 100) {
    return [];
  }

  const sigBoxes = Array.from(pageEl.querySelectorAll<HTMLElement>('.canonical-signatures .sig-box'));
  if (sigBoxes.length === 0) return [];

  const mapped: MappedSignatureBox[] = [];

  sigBoxes.forEach((box, idx) => {
    const lineEl = box.querySelector<HTMLElement>('.sig-line-solid, .sig-line');
    if (!lineEl) return;

    const lineRect = lineEl.getBoundingClientRect();
    const boxRect = box.getBoundingClientRect();
    if (lineRect.width < 30) return;

    const rows = Array.from(box.querySelectorAll<HTMLElement>('.sig-data-row'));
    const lastRowBottom = rows.length > 0 ? rows[rows.length - 1].getBoundingClientRect().bottom : lineRect.top - 26;
    const topPx = Math.max(lastRowBottom + 1, lineRect.top - 28);
    const heightPx = Math.max(18, lineRect.bottom - topPx);

    const domSigArea = new DOMRect(
      Math.max(boxRect.left + 4, lineRect.left),
      topPx,
      Math.min(boxRect.width - 8, lineRect.width),
      heightPx
    );

    const pdfRect = domRectToPdfRect(domSigArea, pageRect);
    const finalName =
      sigBoxes.length === 2
        ? idx === 0
          ? 'FirmaDigital_CoPerito_O_Consignante'
          : 'FirmaDigital_PeritoPrincipal_DEFR'
        : idx === 0
          ? 'FirmaDigital_PeritoPrincipal_DEFR'
          : `FirmaDigital_Firmante_${idx + 1}`;

    mapped.push({
      name: finalName,
      tooltip:
        finalName === 'FirmaDigital_PeritoPrincipal_DEFR'
          ? `Haga clic para aplicar Firma Electronica Digital (Adobe Acrobat) — ${peritoSigLabel}`
          : `Haga clic para aplicar Firma Electronica Digital (Adobe Acrobat) — ${coPeritoSigLabel}`,
      rect: {
        x: pdfRect.x,
        y: pdfRect.y,
        width: Math.max(90, pdfRect.width),
        height: Math.max(16, Math.min(34, pdfRect.height)),
      },
    });
  });

  return mapped;
}

/**
 * Resuelve el valor inicial de un campo `[data-field]` a partir de las credenciales del perito/caso
 */
function resolveInitialFieldValue(dataField: string, options: EditablePdfOptions): string {
  switch (dataField) {
    case 'numeroCaso':
      return options.numeroExpediente ? safePdfText(options.numeroExpediente) : '';
    case 'numeroPRCC':
      return options.numeroPRCC ? safePdfText(options.numeroPRCC) : '';
    case 'perito_nombre':
      return options.peritoNombre ? safePdfText(options.peritoNombre) : '';
    case 'perito_cedula':
      return options.peritoCi ? safePdfText(options.peritoCi) : '';
    case 'perito_civ':
      return options.peritoCiv ? safePdfText(options.peritoCiv) : '';
    case 'perito_cargo':
      return options.peritoCargo ? safePdfText(options.peritoCargo) : '';
    case 'perito_telefono':
      return options.peritoTelefono ? safePdfText(options.peritoTelefono) : '';
    case 'perito_direccion':
      return options.peritoDireccion ? safePdfText(options.peritoDireccion) : '';
    case 'co_perito_nombre':
      return options.coPeritoNombre ? safePdfText(options.coPeritoNombre) : '';
    case 'co_perito_civ':
      return options.coPeritoCiv ? safePdfText(options.coPeritoCiv) : '';
    case 'solicitante_nombre':
      return options.consignanteNombre ? safePdfText(options.consignanteNombre) : '';
    case 'solicitante_cedula':
      return options.consignanteCi ? safePdfText(options.consignanteCi) : '';
    default:
      return '';
  }
}

/**
 * Dibuja un código de barras Code-128B vectorial directamente sobre una página PDF (respaldo sin DOM)
 */
function drawCode128OnPage(
  page: any,
  value: string,
  x: number,
  y: number,
  width: number,
  height: number,
  color = RED_RGB
): void {
  const encoded = encodeCode128B(value);
  const quietModules = 4;
  const totalWidthModules = encoded.totalModules + quietModules * 2;
  const moduleWidth = width / totalWidthModules;

  for (const bar of encoded.bars) {
    page.drawRectangle({
      x: x + (bar.x + quietModules) * moduleWidth,
      y,
      width: bar.w * moduleWidth,
      height,
      color,
    });
  }
}

/**
 * Adjunta una anotación de hipervínculo (/Subtype /Link) sobre el Sello QR Rojo
 */
function addQrUriLinkAnnotation(
  pdfDoc: PDFDocument,
  page: any,
  rect: [number, number, number, number],
  uri: string
): void {
  const linkAnnot = pdfDoc.context.register(
    pdfDoc.context.obj({
      Type: 'Annot',
      Subtype: 'Link',
      Rect: rect,
      Border: [0, 0, 0],
      A: {
        Type: 'Action',
        S: 'URI',
        URI: PDFString.of(uri),
      },
    })
  );

  const existingAnnots = page.node.lookup(PDFName.of('Annots'));
  if (existingAnnots && typeof (existingAnnots as any).push === 'function') {
    (existingAnnots as any).push(linkAnnot);
  } else {
    page.node.set(PDFName.of('Annots'), pdfDoc.context.obj([linkAnnot]));
  }
}

/**
 * Etiqueta legible para la modalidad de firma solicitada
 */
export function getModalidadFirmaLabel(modalidad: ModalidadFirmaPlanilla): string {
  switch (modalidad) {
    case 'adobe_electronica':
      return 'FIRMA ELECTRONICA DIGITAL ADOBE ACROBAT (PAdES / LMDFE ART. 16)';
    case 'manual_autografa':
      return 'FIRMA MANUSCRITA AUTOGRAFA + HUELLAS BILATERALES (COPP ART. 187)';
    case 'hibrida':
    default:
      return 'FIRMA ELECTRONICA ADOBE O MANUSCRITA + HUELLAS BILATERALES';
  }
}

/**
 * Genera un PDF Folio editable (216mm × 330mm) usando el motor nativo `html-to-image`
 * (sin html2canvas) con el Sello QR Rojo nativo en PlanillaHeader, AcroForm transparentes
 * y widgets de firma digital ISO 32000-1 (`/FT /Sig`) para Adobe Acrobat.
 */
export async function generateEditablePdfFromElement(
  element: HTMLElement,
  title: string = 'Planilla_Forense',
  options: EditablePdfOptions = {}
): Promise<Uint8Array> {
  const isBrowser = typeof window !== 'undefined';
  const ownerDoc = element.ownerDocument || (isBrowser ? document : null);
  const pdfDoc = await PDFDocument.create();

  const fontHelvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontHelveticaBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);
  const fontMonoBold = await pdfDoc.embedFont(StandardFonts.CourierBold);

  let pageElements = Array.from(element.querySelectorAll<HTMLElement>('.page'));
  if (pageElements.length === 0 && element.classList.contains('page')) {
    pageElements = [element];
  }
  if (pageElements.length === 0) {
    pageElements = [element];
  }

  const codigoPlanilla = (options.codigoPlanilla || 'PLN-2026-000001').toUpperCase();
  const expNum = options.numeroExpediente || '';
  const prccNum = options.numeroPRCC || '';
  const modalidadFirma: ModalidadFirmaPlanilla = options.modalidadFirma || 'hibrida';
  const qrColor = options.qrColorHex || FORENSIC_RED_HEX;
  const peritoNombre = options.peritoNombre || 'Perito Informatico Forense';
  const peritoCiv = options.peritoCiv || 'CIV-299410';
  const emitidoUtc = options.emitidoEnUtc || new Date().toISOString();

  const peritoSigLabel = safePdfText(`${peritoNombre} (${peritoCiv})`);
  const coPeritoSigLabel = options.coPeritoNombre
    ? safePdfText(`${options.coPeritoNombre}${options.coPeritoCiv ? ` (${options.coPeritoCiv})` : ''}`)
    : 'Co-Perito Revisor / Consignante';

  const hashEmision =
    options.hashEmisionSha256 ||
    (await hashCanonical({
      codigoPlanilla,
      emitidoUtc,
      modalidadFirma,
      numeroExpediente: expNum || null,
      peritoCiv,
      peritoNombre,
      titulo: title,
    }));

  const origin =
    typeof window !== 'undefined' && window.location?.origin?.startsWith('http')
      ? window.location.origin
      : 'https://sha256.us';
  const qrUrl =
    options.qrVerificationUrl ||
    `${origin}/verificar?codigo=${encodeURIComponent(codigoPlanilla)}`;

  // Estampar nativamente el Sello QR Rojo dentro de `.header-qr-seal` del propio formato si existe
  let stampedNativeHeaderQr = false;
  if (element.querySelector('[data-qr-seal]')) {
    try {
      const qrSvg = await generateRedQrSvg(qrUrl);
      const barcodeSvg = renderCode128Svg(codigoPlanilla, {
        color: qrColor,
        height: 14,
        quietZone: 4,
      });
      const count = estamparSelloQrEnDom(element, {
        codigoPlanilla,
        qrUrl,
        hashEmisionSha256: hashEmision,
        qrSvg,
        barcodeSvg,
        offlineDraft: options.offlineDraft,
      });
      stampedNativeHeaderQr = count > 0;
    } catch {
      stampedNativeHeaderQr = false;
    }
  }

  // Asegurar logotipo PNG embebido en data URI para renderizado SVG foreignObject 100% libre de CORS
  const originalLogoSrcs: Array<{ img: HTMLImageElement; src: string }> = [];
  element.querySelectorAll<HTMLImageElement>('img.header-logo').forEach((img) => {
    const prev = img.getAttribute('src') || '';
    if (prev && !prev.startsWith('data:')) {
      originalLogoSrcs.push({ img, src: prev });
      img.setAttribute('src', `data:image/png;base64,${LOGO_PNG_BASE64}`);
    }
  });

  if (ownerDoc) {
    await waitForDocumentAssets(ownerDoc);
  }

  const mappedFieldsByPage: MappedFieldBox[][] = [];
  const mappedSigsByPage: MappedSignatureBox[][] = [];
  let firstPageQrPdfRect: PdfRect | null = null;
  let capturedWithBrowserEngine = false;

  try {
    for (let i = 0; i < pageElements.length; i++) {
      const pageEl = pageElements[i];
      mappedFieldsByPage.push(measurePageAcroFields(pageEl, i));
      mappedSigsByPage.push(measurePageSignatureBoxes(pageEl, peritoSigLabel, coPeritoSigLabel));

      const pageRect = pageEl.getBoundingClientRect();
      if (i === 0 && pageRect.width > 100 && pageRect.height > 100) {
        const qrSealEl = pageEl.querySelector<HTMLElement>('[data-qr-seal]');
        if (qrSealEl && !qrSealEl.hidden) {
          const qrRect = qrSealEl.getBoundingClientRect();
          if (qrRect.width > 20 && qrRect.height > 20) {
            firstPageQrPdfRect = domRectToPdfRect(qrRect, pageRect);
          }
        }
      }

      const page = pdfDoc.addPage([FOLIO_WIDTH_PT, FOLIO_HEIGHT_PT]);

      if (isBrowser && pageRect.width > 100 && pageRect.height > 100) {
        try {
          // Captura con motor nativo del navegador (html-to-image), preservando exactamente 216mm×330mm
          const pngDataUrl = await toPng(pageEl, {
            pixelRatio: 2,
            backgroundColor: '#FFFFFF',
            cacheBust: false,
            skipAutoScale: true,
            width: Math.round(pageRect.width),
            height: Math.round(pageRect.height),
            style: {
              margin: '0',
              border: 'none',
              boxShadow: 'none',
              transform: 'none',
              width: '216mm',
              height: '330mm',
              padding: '15mm 15mm 15mm 30mm',
              boxSizing: 'border-box',
              overflow: 'hidden',
              background: '#FFFFFF',
            },
            filter: (node) => {
              if (node instanceof HTMLElement) {
                if (
                  node.classList.contains('no-print') ||
                  node.classList.contains('no-print-bar') ||
                  node.classList.contains('fcco-print-toolbar')
                ) {
                  return false;
                }
              }
              return true;
            },
          });

          const base64Data = pngDataUrl.split(',')[1];
          if (base64Data) {
            const imgBytes = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));
            const pageImage = await pdfDoc.embedPng(imgBytes);
            page.drawImage(pageImage, {
              x: 0,
              y: 0,
              width: FOLIO_WIDTH_PT,
              height: FOLIO_HEIGHT_PT,
            });
            capturedWithBrowserEngine = true;
          }
        } catch (captureErr) {
          console.warn('Captura nativa html-to-image no disponible en este entorno:', captureErr);
        }
      }
    }
  } finally {
    // Restaurar src original de logos en la página viva
    for (const item of originalLogoSrcs) {
      item.img.setAttribute('src', item.src);
    }
  }

  const pages = pdfDoc.getPages();
  const firstPage = pages[0];
  const lastPage = pages[pages.length - 1];

  // Si se capturó el QR nativo dentro del Header, solo agregamos el hipervínculo clicable sobre su rect exacto.
  // Si no hubo captura visual (ej. pruebas unitarias en Node/happy-dom), dibujamos el sello vectorial en pdf-lib.
  if (capturedWithBrowserEngine && stampedNativeHeaderQr && firstPageQrPdfRect) {
    addQrUriLinkAnnotation(
      pdfDoc,
      firstPage,
      [
        firstPageQrPdfRect.x,
        firstPageQrPdfRect.y,
        firstPageQrPdfRect.x + firstPageQrPdfRect.width,
        firstPageQrPdfRect.y + firstPageQrPdfRect.height,
      ],
      qrUrl
    );
  } else {
    const stampW = 148;
    const stampH = 68;
    const stampX = FOLIO_WIDTH_PT - stampW - 14;
    const stampY = FOLIO_HEIGHT_PT - stampH - 12;

    firstPage.drawRectangle({
      x: stampX,
      y: stampY,
      width: stampW,
      height: stampH,
      color: WHITE_RGB,
      borderColor: RED_RGB,
      borderWidth: 1.25,
    });

    const topBarH = 11;
    firstPage.drawRectangle({
      x: stampX,
      y: stampY + stampH - topBarH,
      width: stampW,
      height: topBarH,
      color: RED_RGB,
    });
    firstPage.drawText(safePdfText(options.offlineDraft ? 'BORRADOR LOCAL' : 'VERIFICACION QR · SHA256.US'), {
      x: stampX + 6,
      y: stampY + stampH - 8.2,
      size: 5.5,
      font: fontHelveticaBold,
      color: WHITE_RGB,
    });

    try {
      const qrDataUrl = await QRCode.toDataURL(qrUrl, {
        errorCorrectionLevel: 'Q',
        margin: 1,
        width: 240,
        color: { dark: qrColor, light: '#FFFFFF' },
      });
      const qrBase64 = qrDataUrl.split(',')[1];
      if (qrBase64) {
        const qrBytes = Uint8Array.from(atob(qrBase64), (c) => c.charCodeAt(0));
        const qrImage = await pdfDoc.embedPng(qrBytes);
        firstPage.drawImage(qrImage, { x: stampX + 3, y: stampY + 3, width: 51, height: 51 });
        addQrUriLinkAnnotation(pdfDoc, firstPage, [stampX, stampY, stampX + stampW, stampY + stampH], qrUrl);
      }
    } catch {
      // continuar
    }

    const infoX = stampX + 58;
    const infoW = stampW - 62;
    firstPage.drawText('N° PLANILLA OFICIAL:', { x: infoX, y: stampY + 47, size: 4.8, font: fontHelveticaBold, color: INK_RGB });
    firstPage.drawText(safePdfText(codigoPlanilla), { x: infoX, y: stampY + 38.5, size: 7, font: fontMonoBold, color: RED_RGB });
    try {
      drawCode128OnPage(firstPage, codigoPlanilla, infoX, stampY + 19, infoW, 17, RED_RGB);
    } catch {
      // continuar
    }
    firstPage.drawText(`SHA256:${hashEmision.slice(0, 8)}..${hashEmision.slice(-6)}`, {
      x: infoX,
      y: stampY + 11.5,
      size: 4.7,
      font: fontMono,
      color: INK_RGB,
    });
  }

  // Campos AcroForm transparentes sobre celdas reales
  const form = pdfDoc.getForm();
  let totalDomFieldsCreated = 0;

  for (let i = 0; i < pages.length; i++) {
    const pg = pages[i];
    const pageFields = mappedFieldsByPage[i] || [];

    for (const f of pageFields) {
      try {
        const tf = form.createTextField(f.name);
        if (f.multiline) tf.enableMultiline();
        const initialVal = resolveInitialFieldValue(f.dataField, options);
        if (initialVal) tf.setText(initialVal);
        tf.addToPage(pg, {
          x: f.rect.x,
          y: f.rect.y,
          width: f.rect.width,
          height: f.rect.height,
          borderWidth: 0,
          font: fontHelvetica,
        });
        totalDomFieldsCreated++;
      } catch {
        // continuar
      }
    }
  }

  if (totalDomFieldsCreated === 0) {
    const fallbackSpecs: Array<{
      name: string;
      val: string;
      pg: any;
      rect: PdfRect;
      multiline?: boolean;
    }> = [
      { name: 'NUMERO_EXPEDIENTE', val: expNum, pg: firstPage, rect: { x: 185, y: 785, width: 145, height: 14 } },
      { name: 'NUMERO_PRCC', val: prccNum, pg: firstPage, rect: { x: 185, y: 766, width: 145, height: 14 } },
      { name: 'PERITO_RESPONSABLE', val: safePdfText(`${peritoNombre} (${peritoCiv})`), pg: firstPage, rect: { x: 185, y: 747, width: 250, height: 14 } },
      { name: 'CONSIGNANTE_SOLICITANTE', val: options.consignanteNombre ? safePdfText(options.consignanteNombre) : '', pg: firstPage, rect: { x: 185, y: 728, width: 250, height: 14 } },
      { name: 'OBSERVACIONES_PERICIALES', val: '', pg: lastPage, rect: { x: 85, y: 210, width: 470, height: 36 }, multiline: true },
    ];

    for (const spec of fallbackSpecs) {
      try {
        const tf = form.createTextField(spec.name);
        if (spec.multiline) tf.enableMultiline();
        if (spec.val) tf.setText(spec.val);
        tf.addToPage(spec.pg, {
          x: spec.rect.x,
          y: spec.rect.y,
          width: spec.rect.width,
          height: spec.rect.height,
          borderWidth: 0,
          font: fontHelvetica,
        });
      } catch {
        // continuar
      }
    }
  }

  // Widgets nativos de Firma Electrónica Digital ISO 32000-1 (/FT /Sig) sobre las líneas de firma reales
  let totalSigWidgets = 0;

  const registerSignatureWidget = (pg: any, sig: MappedSignatureBox) => {
    const sigAnnot = pdfDoc.context.register(
      pdfDoc.context.obj({
        Type: 'Annot',
        Subtype: 'Widget',
        FT: 'Sig',
        Rect: [sig.rect.x, sig.rect.y, sig.rect.x + sig.rect.width, sig.rect.y + sig.rect.height],
        T: PDFString.of(sig.name),
        TU: PDFString.of(sig.tooltip),
        F: 4,
        P: pg.ref,
      })
    );

    const existingAnnots = pg.node.lookup(PDFName.of('Annots'));
    if (existingAnnots && typeof (existingAnnots as any).push === 'function') {
      (existingAnnots as any).push(sigAnnot);
    } else {
      pg.node.set(PDFName.of('Annots'), pdfDoc.context.obj([sigAnnot]));
    }

    form.acroForm.addField(sigAnnot);
    totalSigWidgets++;
  };

  try {
    for (let i = 0; i < pages.length; i++) {
      for (const sig of mappedSigsByPage[i] || []) {
        registerSignatureWidget(pages[i], sig);
      }
    }

    if (totalSigWidgets === 0) {
      registerSignatureWidget(lastPage, {
        name: 'FirmaDigital_CoPerito_O_Consignante',
        tooltip: `Haga clic para firmar electronicamente — ${coPeritoSigLabel}`,
        rect: { x: 88, y: 128, width: 215, height: 26 },
      });
      registerSignatureWidget(lastPage, {
        name: 'FirmaDigital_PeritoPrincipal_DEFR',
        tooltip: `Haga clic para firmar electronicamente — ${peritoSigLabel}`,
        rect: { x: 340, y: 128, width: 215, height: 26 },
      });
    }
  } catch (sigErr) {
    console.warn('No se pudieron registrar los campos nativos de firma digital:', sigErr);
  }

  pdfDoc.setTitle(`${codigoPlanilla} - ${title}`);
  pdfDoc.setSubject(
    `Planilla Oficial SHA256.US | ID: ${codigoPlanilla} | SHA-256: ${hashEmision} | Adobe PAdES Ready`
  );
  pdfDoc.setAuthor(`${peritoNombre} (${peritoCiv}) - Laboratorio SHA256.US`);
  pdfDoc.setCreator('Forensic Chief Compliance Officer (FCCO) — SHA256.US');
  pdfDoc.setKeywords([
    codigoPlanilla,
    hashEmision,
    'forense',
    'iso-27037',
    'copp-187',
    'firma-electronica',
    'qr-verificacion',
  ]);

  return await pdfDoc.save();
}

function readCachedSessionUser() {
  if (typeof window !== 'undefined') {
    try {
      const raw = sessionStorage.getItem('fcco_auth_user');
      if (raw) {
        const u = JSON.parse(raw);
        const fullName = [u.nombre, u.apellido].filter(Boolean).join(' ') || u.email || 'Perito Forense';
        return {
          id: String(u.id || 'local-user'),
          nombre: fullName,
          ci: String(u.ci || ''),
          civ: String(u.civ || 'CIV-299410'),
          inpre: String(u.inpre || ''),
          cargo: String(u.cargo || 'Perito Informático Forense'),
          organismo: String(u.organismo || 'Laboratorio Privado SHA256.US'),
          telefono: String(u.telefono || ''),
          direccion: String(u.direccion || ''),
        };
      }
    } catch {
      // continuar
    }
  }
  return {
    id: 'local-user',
    nombre: 'Jull Joll',
    ci: 'V-18.999.001',
    civ: 'CIV-299410',
    inpre: 'INPRE-184920',
    cargo: 'Perito Analizador de Datos Forenses',
    organismo: 'Laboratorio Privado SHA256.US',
    telefono: '',
    direccion: '',
  };
}

/**
 * Orquestador completo de Emisión en 2 Fases (cPanel MySQL + PDF con html-to-image + Hash Binario)
 */
export async function emitAndExportElementToEditablePdf(
  element: HTMLElement,
  params: EmitirPdfParams
): Promise<EmitirPdfResult> {
  const slug = params.slug || 'planilla';
  const codigoDoc = params.codigoDoc || 'FO-FOR-01';
  const tituloPlanilla = params.tituloPlanilla || slug;
  const faseIso = params.faseIso || 'F0';
  const modalidadFirma: ModalidadFirmaPlanilla = params.modalidadFirma || 'hibrida';

  const cachedUser = readCachedSessionUser();

  let planillaEmitida: PlanillaEmitidaDTO;
  let qrUrl: string;
  let offlineDraft = false;

  const apiRes = await phpApi.emitirPlanilla({
    planillaSlug: slug,
    codigoDoc,
    tituloPlanilla,
    faseIso,
    casoId: params.casoId || null,
    numeroCaso: params.numeroCaso || null,
    numeroPRCC: params.numeroPRCC || null,
    coPeritoNombre: params.coPeritoNombre || null,
    coPeritoCiv: params.coPeritoCiv || null,
    modalidadFirma,
  });

  if (apiRes.ok && apiRes.data?.planilla) {
    planillaEmitida = apiRes.data.planilla;
    qrUrl =
      apiRes.data.qrUrl ||
      `${window.location.origin}/verificar?codigo=${encodeURIComponent(planillaEmitida.codigoPlanilla)}`;
  } else {
    offlineDraft = true;
    const nowUtc = new Date().toISOString();
    const localCode = `LOCAL-${new Date().getFullYear()}-${String(Date.now()).slice(-6)}`;
    const localHash = await hashCanonical({
      codigoDoc,
      codigoPlanilla: localCode,
      emitidoEnUtc: nowUtc,
      modalidadFirma,
      peritoCiv: cachedUser.civ,
      peritoNombre: cachedUser.nombre,
      planillaSlug: slug,
      tituloPlanilla,
    });

    planillaEmitida = {
      codigoPlanilla: localCode,
      planillaSlug: slug,
      codigoDoc,
      tituloPlanilla,
      faseIso,
      casoId: params.casoId || null,
      numeroCaso: params.numeroCaso || null,
      numeroPRCC: params.numeroPRCC || null,
      perito: {
        usuarioId: cachedUser.id,
        nombre: cachedUser.nombre,
        ci: cachedUser.ci,
        civ: cachedUser.civ,
        inpre: cachedUser.inpre,
        cargo: cachedUser.cargo,
        organismo: cachedUser.organismo,
      },
      coPerito: params.coPeritoNombre
        ? { nombre: params.coPeritoNombre, civ: params.coPeritoCiv || '' }
        : null,
      modalidadFirma,
      estadoFirma: 'PENDIENTE_FIRMA',
      firmadaEn: null,
      hashEmisionSha256: localHash,
      hashPdfSha256: null,
      hashPdfFirmadoSha256: null,
      auditoriaSeq: null,
      auditoriaHash: null,
      emitidoEnUtc: nowUtc,
      offlineDraft: true,
    };

    const origin =
      typeof window !== 'undefined' && window.location?.origin?.startsWith('http')
        ? window.location.origin
        : 'https://sha256.us';
    qrUrl = `${origin}/verificar?codigo=${encodeURIComponent(localCode)}`;
  }

  const pdfBytes = await generateEditablePdfFromElement(element, tituloPlanilla, {
    codigoPlanilla: planillaEmitida.codigoPlanilla,
    codigoDoc: planillaEmitida.codigoDoc,
    faseIso: planillaEmitida.faseIso,
    numeroExpediente: planillaEmitida.numeroCaso || params.numeroCaso || undefined,
    numeroPRCC: planillaEmitida.numeroPRCC || params.numeroPRCC || undefined,
    peritoNombre: planillaEmitida.perito.nombre,
    peritoCi: planillaEmitida.perito.ci,
    peritoCiv: planillaEmitida.perito.civ,
    peritoInpre: planillaEmitida.perito.inpre,
    peritoCargo: planillaEmitida.perito.cargo,
    peritoTelefono: cachedUser.telefono,
    peritoDireccion: cachedUser.direccion,
    coPeritoNombre: planillaEmitida.coPerito?.nombre,
    coPeritoCiv: planillaEmitida.coPerito?.civ,
    modalidadFirma: planillaEmitida.modalidadFirma,
    hashEmisionSha256: planillaEmitida.hashEmisionSha256,
    emitidoEnUtc: planillaEmitida.emitidoEnUtc,
    qrVerificationUrl: qrUrl,
    qrColorHex: FORENSIC_RED_HEX,
    isBlankMode: params.isBlankMode ?? true,
    offlineDraft,
  });

  const hashPdfSha256 = await computeSha256HexFromBytes(pdfBytes);
  planillaEmitida.hashPdfSha256 = hashPdfSha256;

  if (!offlineDraft) {
    await phpApi.fijarHashPdfPlanilla(planillaEmitida.codigoPlanilla, hashPdfSha256).catch((err) => {
      console.warn('No se pudo confirmar hash_pdf_sha256 en servidor:', err);
    });
  } else if (typeof window !== 'undefined') {
    try {
      const storeKey = 'fcco_planillas_emitidas_local';
      const existing: Record<string, PlanillaEmitidaDTO> = JSON.parse(
        localStorage.getItem(storeKey) || '{}'
      );
      existing[planillaEmitida.codigoPlanilla] = planillaEmitida;
      localStorage.setItem(storeKey, JSON.stringify(existing));
    } catch {
      // ignorar
    }
  }

  const cleanTitle = tituloPlanilla.replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ_-]/g, '_').slice(0, 60);
  const fileName = `${planillaEmitida.codigoPlanilla}_${cleanTitle}_adobe.pdf`;

  const blob = new Blob([pdfBytes.buffer as ArrayBuffer], { type: 'application/pdf' });
  saveAs(blob, fileName);

  return {
    planilla: planillaEmitida,
    qrUrl,
    hashPdfSha256,
    fileName,
    offlineDraft,
  };
}

/**
 * Carga la planilla oficial en un <iframe> aislado con su CSS real `folio-aislado.css`
 */
async function loadPlanillaInStyledIframe(
  slug: string,
  modo: 'blanco' | 'datos'
): Promise<{ iframe: HTMLIFrameElement; container: HTMLElement; doc: Document }> {
  return new Promise((resolve, reject) => {
    const iframe = document.createElement('iframe');
    iframe.setAttribute('aria-hidden', 'true');
    iframe.style.position = 'fixed';
    iframe.style.left = '-10000px';
    iframe.style.top = '0';
    iframe.style.width = '1000px';
    iframe.style.height = '1500px';
    iframe.style.border = '0';
    iframe.style.opacity = '0';
    iframe.style.pointerEvents = 'none';
    iframe.style.backgroundColor = '#FFFFFF';
    iframe.src = `/planillas/${encodeURIComponent(slug)}?modo=${encodeURIComponent(modo)}&render_pdf=1`;

    const timeoutId = setTimeout(() => {
      iframe.remove();
      reject(new Error(`Tiempo de espera agotado al cargar el formato visual de ${slug}`));
    }, 15000);

    iframe.onload = async () => {
      try {
        clearTimeout(timeoutId);
        const iframeDoc = iframe.contentDocument;
        if (!iframeDoc) {
          iframe.remove();
          reject(new Error('No se pudo acceder al documento renderizado de la planilla'));
          return;
        }

        iframeDoc.documentElement.classList.remove('fcco-auth-loading');
        iframeDoc.getElementById('fcco-auth-cloak')?.remove();
        await waitForDocumentAssets(iframeDoc);
        await new Promise((r) => setTimeout(r, 120));

        const container =
          iframeDoc.getElementById('contenedor-planilla-activa') ||
          iframeDoc.querySelector<HTMLElement>('.folio-forense-aislado');

        if (!container) {
          iframe.remove();
          reject(new Error(`No se encontró .folio-forense-aislado en /planillas/${slug}`));
          return;
        }

        resolve({ iframe, container, doc: iframeDoc });
      } catch (err) {
        iframe.remove();
        reject(err);
      }
    };

    iframe.onerror = () => {
      clearTimeout(timeoutId);
      iframe.remove();
      reject(new Error(`Error de red al cargar /planillas/${slug}`));
    };

    document.body.appendChild(iframe);
  });
}

export async function exportCurrentPlanillaToEditablePdf(
  titleOverride?: string,
  extraParams: Partial<EmitirPdfParams> = {}
): Promise<EmitirPdfResult | undefined> {
  if (typeof window === 'undefined') return undefined;

  const container =
    document.getElementById('contenedor-planilla-activa') ||
    document.querySelector('.folio-forense-aislado');

  if (!container) {
    alert('No se encontró ninguna planilla activa en la pantalla.');
    return undefined;
  }

  const slug =
    extraParams.slug ||
    container.getAttribute('data-slug') ||
    window.location.pathname.split('/').pop()?.replace('.html', '') ||
    'planilla';

  const titleEl = container.querySelector('.canonical-doc-title') || document.querySelector('h1');
  const codeEl = container.querySelector('.control-box-val');
  const rawTitle = titleOverride || extraParams.tituloPlanilla || titleEl?.textContent?.trim() || slug;
  const codigoDoc = extraParams.codigoDoc || codeEl?.textContent?.trim() || 'FO-FOR-01';

  return emitAndExportElementToEditablePdf(container as HTMLElement, {
    slug,
    codigoDoc,
    tituloPlanilla: rawTitle,
    faseIso: extraParams.faseIso || 'F0',
    casoId: extraParams.casoId ?? null,
    numeroCaso: extraParams.numeroCaso ?? null,
    numeroPRCC: extraParams.numeroPRCC ?? null,
    coPeritoNombre: extraParams.coPeritoNombre ?? null,
    coPeritoCiv: extraParams.coPeritoCiv ?? null,
    modalidadFirma: extraParams.modalidadFirma || 'hibrida',
    isBlankMode: extraParams.isBlankMode ?? true,
  });
}

export async function descargarPlanillaPdfEditablePorSlug(
  slug: string,
  modo: 'blanco' | 'datos' = 'blanco',
  casoId?: string | null,
  titulo?: string,
  extraParams: Partial<EmitirPdfParams> = {}
): Promise<EmitirPdfResult | undefined> {
  if (typeof window === 'undefined') return undefined;

  let loadedIframe: HTMLIFrameElement | null = null;
  try {
    const { iframe, container, doc } = await loadPlanillaInStyledIframe(slug, modo);
    loadedIframe = iframe;

    if (modo === 'blanco') {
      container.querySelectorAll<HTMLElement>('[data-field]').forEach((el) => {
        el.textContent = '';
      });
    }

    const rawTitle =
      titulo ||
      extraParams.tituloPlanilla ||
      doc.querySelector('.canonical-doc-title')?.textContent?.trim() ||
      slug;
    const codigoDoc =
      extraParams.codigoDoc ||
      doc.querySelector('.control-box-val')?.textContent?.trim() ||
      'FO-FOR-01';

    return await emitAndExportElementToEditablePdf(container, {
      slug,
      codigoDoc,
      tituloPlanilla: rawTitle,
      faseIso: extraParams.faseIso || 'F0',
      casoId: casoId ?? extraParams.casoId ?? null,
      numeroCaso: extraParams.numeroCaso ?? null,
      numeroPRCC: extraParams.numeroPRCC ?? null,
      coPeritoNombre: extraParams.coPeritoNombre ?? null,
      coPeritoCiv: extraParams.coPeritoCiv ?? null,
      modalidadFirma: extraParams.modalidadFirma || 'hibrida',
      isBlankMode: modo === 'blanco',
    });
  } catch (err: any) {
    console.error('Error al descargar planilla PDF editable por slug:', err);
    alert(`No se pudo generar el PDF editable: ${err.message || 'Error desconocido'}`);
    return undefined;
  } finally {
    if (loadedIframe && loadedIframe.parentNode) {
      loadedIframe.parentNode.removeChild(loadedIframe);
    }
  }
}
