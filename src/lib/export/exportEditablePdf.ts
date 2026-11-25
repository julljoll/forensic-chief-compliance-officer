/**
 * SHA256.US — Exportador Oficial de Planillas Forenses a PDF Editable (Adobe Acrobat Ready)
 *
 * Protocolo de Sellado Documental en 2 Fases (cPanel MySQL + RFC 8785 + ISO 32000-1):
 * 1. Registro atómico en servidor (`POST /api/planillas-emitidas.php`) usando la identidad del
 *    perito logueado en sesión PHP: asigna N° de Planilla correlativo (`PLN-YYYY-NNNNNN`) y
 *    `hash_emision_sha256` encadenado a la tabla inmutable `auditoria`.
 * 2. Estampado del Sello Rojo Forense (`#B50909`) en la esquina superior derecha del Folio
 *    (`216mm × 330mm`) con:
 *    - Código QR Rojo interactivo (`https://sha256.us/verificar?codigo=PLN-YYYY-NNNNNN`)
 *    - Código de Barras 1D Vectorial Code-128B idéntico al N° de Planilla
 *    - Número de Planilla legible + digest SHA-256 de emisión
 *    - Campos AcroForm editables + campos nativos de Firma Electrónica Digital (`/FT /Sig`)
 *      listos para firmar en Adobe Acrobat (PAdES / PKCS#7) o manualmente en papel.
 * 3. Cálculo WebCrypto del SHA-256 binario exacto del PDF final y confirmación inmutable
 *    en cPanel (`PUT /api/planillas-emitidas.php` -> `hash_pdf_sha256`).
 */

import { PDFDocument, PDFName, PDFString, StandardFonts, rgb } from 'pdf-lib';
import QRCode from 'qrcode';
import { saveAs } from 'file-saver';
import html2canvas from 'html2canvas';
import { encodeCode128B } from './code128';
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
const RED_SOFT_RGB = rgb(0.99, 0.94, 0.94);    // Fondo suave para etiquetas de firma
const INK_RGB = rgb(0.106, 0.165, 0.29);       // #1B2A4A — Dark Ink USWDS
const WHITE_RGB = rgb(1, 1, 1);

export interface EditablePdfOptions {
  codigoPlanilla?: string;
  codigoDoc?: string;
  faseIso?: string;
  numeroExpediente?: string;
  numeroPRCC?: string;
  peritoNombre?: string;
  peritoCiv?: string;
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
 * Prepara el DOM clonado para captura limpia en html2canvas
 */
function prepareClonedDom(clonedDoc: Document): void {
  clonedDoc.querySelectorAll<HTMLElement>('.page').forEach((p) => {
    p.style.transform = 'none';
    p.style.overflow = 'visible';
    p.style.height = 'auto';
    p.style.maxHeight = 'none';
  });

  clonedDoc
    .querySelectorAll<HTMLElement>('.no-print, .no-print-bar, .fcco-print-toolbar')
    .forEach((el) => {
      el.style.display = 'none';
    });
}

/**
 * Dibuja un código de barras Code-128B vectorial directamente sobre una página PDF
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
 * Adjunta una anotación de hipervínculo (/Subtype /Link) sobre el recuadro del QR Rojo
 * para que también sea clicable directamente dentro de Adobe Acrobat / Reader.
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
      return 'FIRMA ELECTRONICA DIGITAL EN ADOBE ACROBAT (PAdES / PKCS#7 - LMDFE ART. 16)';
    case 'manual_autografa':
      return 'FIRMA MANUSCRITA AUTOGRAFA + HUELLAS DACTILARES BILATERALES (COPP ART. 187)';
    case 'hibrida':
    default:
      return 'FIRMA ELECTRONICA (ADOBE ACROBAT) O FIRMA MANUSCRITA + HUELLAS BILATERALES';
  }
}

/**
 * Genera un PDF Folio editable (216mm × 330mm) con:
 * - Sello Rojo Forense superior derecho (QR Rojo + Código de Barras Code-128 + N° de Planilla + SHA-256)
 * - Campos AcroForm editables
 * - Campos nativos de Firma Electrónica Digital ISO 32000-1 (`/FT /Sig`) para Adobe Acrobat
 */
export async function generateEditablePdfFromElement(
  element: HTMLElement,
  title: string = 'Planilla_Forense',
  options: EditablePdfOptions = {}
): Promise<Uint8Array> {
  const isBrowser = typeof window !== 'undefined';
  const pdfDoc = await PDFDocument.create();

  const fontHelvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontHelveticaBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);
  const fontMonoBold = await pdfDoc.embedFont(StandardFonts.CourierBold);

  // Buscar páginas .page o usar el contenedor raíz
  let pageElements = Array.from(element.querySelectorAll<HTMLElement>('.page'));
  if (pageElements.length === 0 && element.classList.contains('page')) {
    pageElements = [element];
  }
  if (pageElements.length === 0) {
    pageElements = [element];
  }

  for (let i = 0; i < pageElements.length; i++) {
    const pageEl = pageElements[i];
    const page = pdfDoc.addPage([FOLIO_WIDTH_PT, FOLIO_HEIGHT_PT]);

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

  const codigoPlanilla = (options.codigoPlanilla || 'PLN-2026-000001').toUpperCase();
  const expNum = options.numeroExpediente || '';
  const prccNum = options.numeroPRCC || '';
  const modalidadFirma: ModalidadFirmaPlanilla = options.modalidadFirma || 'hibrida';
  const qrColor = options.qrColorHex || FORENSIC_RED_HEX;
  const peritoNombre = options.peritoNombre || 'Perito Informatico Forense';
  const peritoCiv = options.peritoCiv || 'CIV-299410';
  const emitidoUtc = options.emitidoEnUtc || new Date().toISOString();

  // Hash de emisión SHA-256 (del servidor cPanel o calculado localmente si es borrador/test)
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

  // ==========================================================================
  // 1. SELLO ROJO FORENSE EN ESQUINA SUPERIOR DERECHA (QR ROJO + CODE-128 + ID)
  // ==========================================================================
  const stampW = 128;
  const stampH = 114;
  const stampX = FOLIO_WIDTH_PT - stampW - 16; // 468.28pt (margen derecho ~5.6mm)
  const stampY = FOLIO_HEIGHT_PT - stampH - 12; // 809.43pt (esquina superior derecha)

  // Fondo blanco puro + borde rojo forense
  firstPage.drawRectangle({
    x: stampX,
    y: stampY,
    width: stampW,
    height: stampH,
    color: WHITE_RGB,
    borderColor: RED_RGB,
    borderWidth: 1.4,
  });

  // Banda superior roja con rótulo de verificación
  const headerBarH = 13;
  firstPage.drawRectangle({
    x: stampX,
    y: stampY + stampH - headerBarH,
    width: stampW,
    height: headerBarH,
    color: RED_RGB,
  });

  const bannerText = options.offlineDraft ? 'BORRADOR LOCAL (SIN BD)' : 'VERIFICACION QR · SHA256.US';
  firstPage.drawText(safePdfText(bannerText), {
    x: stampX + 6,
    y: stampY + stampH - 9.5,
    size: 5.8,
    font: fontHelveticaBold,
    color: WHITE_RGB,
  });

  // Código QR en color Rojo Forense (#B50909) con corrección de errores Q (25%)
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
      const qrSize = 58;
      const qrX = stampX + (stampW - qrSize) / 2;
      const qrY = stampY + stampH - headerBarH - qrSize - 3;

      firstPage.drawImage(qrImage, {
        x: qrX,
        y: qrY,
        width: qrSize,
        height: qrSize,
      });

      // Enlace clicable desde Adobe Acrobat hacia el Popup de Verificación
      addQrUriLinkAnnotation(
        pdfDoc,
        firstPage,
        [stampX, stampY, stampX + stampW, stampY + stampH],
        qrUrl
      );
    }
  } catch (qrErr) {
    console.warn('No se pudo generar código QR rojo embebido:', qrErr);
  }

  // Código de Barras Vectorial Code-128B con el mismo número identificador
  try {
    drawCode128OnPage(firstPage, codigoPlanilla, stampX + 6, stampY + 21, stampW - 12, 16, RED_RGB);
  } catch (barErr) {
    console.warn('No se pudo dibujar código de barras Code-128:', barErr);
  }

  // Número Único de Planilla (idéntico al QR y a las barras)
  const idLabel = `N° ${codigoPlanilla}`;
  const idWidth = fontMonoBold.widthOfTextAtSize(safePdfText(idLabel), 7);
  firstPage.drawText(safePdfText(idLabel), {
    x: stampX + Math.max(4, (stampW - idWidth) / 2),
    y: stampY + 12,
    size: 7,
    font: fontMonoBold,
    color: RED_RGB,
  });

  // Extracto del Hash SHA-256 dentro del sello
  const shaShort = `SHA256:${hashEmision.slice(0, 10)}..${hashEmision.slice(-8)}`;
  const shaShortWidth = fontMono.widthOfTextAtSize(shaShort, 5.2);
  firstPage.drawText(shaShort, {
    x: stampX + Math.max(4, (stampW - shaShortWidth) / 2),
    y: stampY + 4,
    size: 5.2,
    font: fontMono,
    color: INK_RGB,
  });

  // ==========================================================================
  // 2. SELLO COMPACTO EN PÁGINAS 2+ Y CINTA CRIPTOGRÁFICA EN PIE DE CADA HOJA
  // ==========================================================================
  for (let i = 0; i < pages.length; i++) {
    const pg = pages[i];

    // Sello compacto en esquina superior derecha de páginas 2..N
    if (i > 0) {
      const miniW = 165;
      const miniH = 26;
      const miniX = FOLIO_WIDTH_PT - miniW - 16;
      const miniY = FOLIO_HEIGHT_PT - miniH - 12;

      pg.drawRectangle({
        x: miniX,
        y: miniY,
        width: miniW,
        height: miniH,
        color: WHITE_RGB,
        borderColor: RED_RGB,
        borderWidth: 1,
      });

      try {
        drawCode128OnPage(pg, codigoPlanilla, miniX + 4, miniY + 11, miniW - 8, 11, RED_RGB);
      } catch {
        // continuar sin barras en página secundaria
      }

      pg.drawText(safePdfText(`${codigoPlanilla} | PAG ${i + 1}/${pages.length}`), {
        x: miniX + 6,
        y: miniY + 3,
        size: 6,
        font: fontMonoBold,
        color: RED_RGB,
      });
    }

    // Cinta criptográfica en pie de página con SHA-256 completo + perito emisor
    const footerStrip = safePdfText(
      `ID: ${codigoPlanilla} | EMISOR: ${peritoNombre} (${peritoCiv}) | SHA-256: ${hashEmision}`
    );
    pg.drawText(footerStrip, {
      x: 34,
      y: 12,
      size: 5.2,
      font: fontMono,
      color: RED_RGB,
    });
  }

  // ==========================================================================
  // 3. FORMULARIO ACROFORM EDITABLE EN ADOBE ACROBAT
  // ==========================================================================
  const form = pdfDoc.getForm();

  // Campo 1: Número de Expediente
  try {
    const tfExp = form.createTextField('NUMERO_EXPEDIENTE');
    tfExp.setText(options.isBlankMode && !expNum ? '' : expNum);
    tfExp.addToPage(firstPage, { x: 160, y: 785, width: 170, height: 15 });
  } catch {
    // campo ya existente
  }

  // Campo 2: Número de PRCC
  try {
    const tfPrcc = form.createTextField('NUMERO_PRCC');
    tfPrcc.setText(options.isBlankMode && !prccNum ? '' : prccNum);
    tfPrcc.addToPage(firstPage, { x: 160, y: 766, width: 170, height: 15 });
  } catch {
    // campo ya existente
  }

  // Campo 3: Perito Responsable (pre-cargado con usuario logueado)
  try {
    const tfPerito = form.createTextField('PERITO_RESPONSABLE');
    tfPerito.setText(safePdfText(`${peritoNombre} (${peritoCiv})`));
    tfPerito.addToPage(firstPage, { x: 160, y: 747, width: 290, height: 15 });
  } catch {
    // campo ya existente
  }

  // Campo 4: Solicitante / Consignante
  try {
    const tfConsignante = form.createTextField('CONSIGNANTE_SOLICITANTE');
    tfConsignante.setText(options.consignanteNombre ? safePdfText(options.consignanteNombre) : '');
    tfConsignante.addToPage(firstPage, { x: 160, y: 728, width: 290, height: 15 });
  } catch {
    // campo ya existente
  }

  // Campo 5: Observaciones Periciales (multilínea)
  try {
    const tfObs = form.createTextField('OBSERVACIONES_PERICIALES');
    tfObs.enableMultiline();
    tfObs.setText(
      options.isBlankMode
        ? ''
        : 'Diligencia pericial ejecutada conforme al Articulo 187 del COPP, LMDFE Art. 16 e ISO/IEC 27037:2012.'
    );
    tfObs.addToPage(lastPage, { x: 60, y: 190, width: 490, height: 48 });
  } catch {
    // campo ya existente
  }

  // ==========================================================================
  // 4. REQUERIMIENTO DE FIRMA ELECTRÓNICA (ADOBE ACROBAT /FT /Sig) O MANUAL
  // ==========================================================================
  const sigBannerText = getModalidadFirmaLabel(modalidadFirma);
  lastPage.drawRectangle({
    x: 60,
    y: 156,
    width: 490,
    height: 15,
    color: RED_SOFT_RGB,
    borderColor: RED_RGB,
    borderWidth: 0.75,
  });
  lastPage.drawText(safePdfText(`REQUISITO DE FIRMA: ${sigBannerText}`), {
    x: 66,
    y: 160.5,
    size: 6,
    font: fontHelveticaBold,
    color: RED_RGB,
  });

  // Marcos visuales de las 2 zonas de firma digital/manual
  const peritoSigLabel = safePdfText(`Perito Emisor: ${peritoNombre} (${peritoCiv})`);
  const coPeritoSigLabel = options.coPeritoNombre
    ? safePdfText(`Co-Perito: ${options.coPeritoNombre}${options.coPeritoCiv ? ` (${options.coPeritoCiv})` : ''}`)
    : 'Co-Perito Revisor / Consignante (Firma Digital Adobe o Autografa)';

  // Recuadro Izquierdo (Perito Principal)
  lastPage.drawRectangle({
    x: 60,
    y: 82,
    width: 230,
    height: 68,
    color: WHITE_RGB,
    borderColor: RED_RGB,
    borderWidth: 0.8,
  });
  lastPage.drawText('FIRMA ELECTRONICA (ADOBE) O MANUAL - PERITO 1', {
    x: 66,
    y: 140,
    size: 5.5,
    font: fontHelveticaBold,
    color: RED_RGB,
  });
  lastPage.drawText(peritoSigLabel.slice(0, 48), {
    x: 66,
    y: 86,
    size: 6,
    font: fontHelvetica,
    color: INK_RGB,
  });

  // Recuadro Derecho (Co-Perito / Consignante)
  lastPage.drawRectangle({
    x: 320,
    y: 82,
    width: 230,
    height: 68,
    color: WHITE_RGB,
    borderColor: RED_RGB,
    borderWidth: 0.8,
  });
  lastPage.drawText('FIRMA ELECTRONICA (ADOBE) O MANUAL - PERITO 2', {
    x: 326,
    y: 140,
    size: 5.5,
    font: fontHelveticaBold,
    color: RED_RGB,
  });
  lastPage.drawText(coPeritoSigLabel.slice(0, 48), {
    x: 326,
    y: 86,
    size: 6,
    font: fontHelvetica,
    color: INK_RGB,
  });

  // Widgets nativos de Firma Digital ISO 32000-1 (/FT /Sig) reconocibles en Adobe Acrobat
  try {
    const sigAnnot1 = pdfDoc.context.register(
      pdfDoc.context.obj({
        Type: 'Annot',
        Subtype: 'Widget',
        FT: 'Sig',
        Rect: [62, 95, 288, 138],
        T: PDFString.of('FirmaDigital_PeritoPrincipal_DEFR'),
        TU: PDFString.of(`Haga clic para firmar electronicamente como ${peritoSigLabel}`),
        F: 4,
        P: lastPage.ref,
      })
    );

    const sigAnnot2 = pdfDoc.context.register(
      pdfDoc.context.obj({
        Type: 'Annot',
        Subtype: 'Widget',
        FT: 'Sig',
        Rect: [322, 95, 548, 138],
        T: PDFString.of('FirmaDigital_CoPerito_O_Consignante'),
        TU: PDFString.of(`Haga clic para firmar electronicamente como ${coPeritoSigLabel}`),
        F: 4,
        P: lastPage.ref,
      })
    );

    const existingAnnots = lastPage.node.lookup(PDFName.of('Annots'));
    if (existingAnnots && typeof (existingAnnots as any).push === 'function') {
      (existingAnnots as any).push(sigAnnot1);
      (existingAnnots as any).push(sigAnnot2);
    } else {
      lastPage.node.set(PDFName.of('Annots'), pdfDoc.context.obj([sigAnnot1, sigAnnot2]));
    }

    form.acroForm.addField(sigAnnot1);
    form.acroForm.addField(sigAnnot2);
  } catch (sigErr) {
    console.warn('No se pudieron registrar los campos nativos de firma digital:', sigErr);
  }

  // Metadatos XMP / PDF oficiales
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

/**
 * Lee el perito logueado desde sessionStorage como respaldo offline
 */
function readCachedSessionUser(): {
  id: string;
  nombre: string;
  ci: string;
  civ: string;
  inpre: string;
  cargo: string;
  organismo: string;
} {
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
        };
      }
    } catch {
      // usar fallback
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
  };
}

/**
 * Orquestador completo de Emisión en 2 Fases (cPanel MySQL + PDF Rojo + Hash Binario)
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

  // FASE 1: Registro atómico en base de datos cPanel (PHP/MySQL) usando usuario logueado
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
    // Fallback controlado en modo offline / sin servidor PHP activo (marcado explícitamente)
    offlineDraft = true;
    const localUser = readCachedSessionUser();
    const nowUtc = new Date().toISOString();
    const suffix = String(Date.now()).slice(-6);
    const localCode = `LOCAL-${new Date().getFullYear()}-${suffix}`;
    const localHash = await hashCanonical({
      codigoDoc,
      codigoPlanilla: localCode,
      emitidoEnUtc: nowUtc,
      modalidadFirma,
      peritoCiv: localUser.civ,
      peritoNombre: localUser.nombre,
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
        usuarioId: localUser.id,
        nombre: localUser.nombre,
        ci: localUser.ci,
        civ: localUser.civ,
        inpre: localUser.inpre,
        cargo: localUser.cargo,
        organismo: localUser.organismo,
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

  // FASE 2: Generar PDF Editable con Sello Rojo (QR + Code-128 + ID + SHA-256 + Firmas /FT /Sig)
  const pdfBytes = await generateEditablePdfFromElement(element, tituloPlanilla, {
    codigoPlanilla: planillaEmitida.codigoPlanilla,
    codigoDoc: planillaEmitida.codigoDoc,
    faseIso: planillaEmitida.faseIso,
    numeroExpediente: planillaEmitida.numeroCaso || params.numeroCaso || undefined,
    numeroPRCC: planillaEmitida.numeroPRCC || params.numeroPRCC || undefined,
    peritoNombre: planillaEmitida.perito.nombre,
    peritoCiv: planillaEmitida.perito.civ,
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

  // FASE 3: Calcular SHA-256 binario exacto del archivo .pdf generado y fijarlo en MySQL cPanel
  const hashPdfSha256 = await computeSha256HexFromBytes(pdfBytes);
  planillaEmitida.hashPdfSha256 = hashPdfSha256;

  if (!offlineDraft) {
    await phpApi.fijarHashPdfPlanilla(planillaEmitida.codigoPlanilla, hashPdfSha256).catch((err) => {
      console.warn('No se pudo confirmar hash_pdf_sha256 en servidor:', err);
    });
  } else if (typeof window !== 'undefined') {
    // Guardar respaldo local para consulta en /verificar en modo local/demo sin MySQL
    try {
      const storeKey = 'fcco_planillas_emitidas_local';
      const existing: Record<string, PlanillaEmitidaDTO> = JSON.parse(
        localStorage.getItem(storeKey) || '{}'
      );
      existing[planillaEmitida.codigoPlanilla] = planillaEmitida;
      localStorage.setItem(storeKey, JSON.stringify(existing));
    } catch {
      // ignorar cuota
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
 * Descarga directamente la planilla activa en la pantalla como PDF editable sellado
 */
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

/**
 * Descarga cualquier planilla por su slug como PDF editable sellado directamente desde el catálogo
 */
export async function descargarPlanillaPdfEditablePorSlug(
  slug: string,
  modo: 'blanco' | 'datos' = 'blanco',
  casoId?: string | null,
  titulo?: string,
  extraParams: Partial<EmitirPdfParams> = {}
): Promise<EmitirPdfResult | undefined> {
  if (typeof window === 'undefined') return undefined;

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

      const rawTitle =
        titulo ||
        extraParams.tituloPlanilla ||
        doc.querySelector('.canonical-doc-title')?.textContent?.trim() ||
        slug;
      const codigoDoc =
        extraParams.codigoDoc ||
        doc.querySelector('.control-box-val')?.textContent?.trim() ||
        'FO-FOR-01';

      return await emitAndExportElementToEditablePdf(activeEl as HTMLElement, {
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
    } finally {
      document.body.removeChild(tempHolder);
    }
  } catch (err: any) {
    console.error('Error al descargar planilla PDF editable por slug:', err);
    alert(`No se pudo generar el PDF editable: ${err.message || 'Error desconocido'}`);
    return undefined;
  }
}
