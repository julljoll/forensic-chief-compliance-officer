/**
 * SHA256.US — Motor Nativo de Emisión y Estampado de Sello QR Rojo en las 13 Planillas Oficiales
 *
 * Garantiza 100% de fidelidad visual frente a "Ver Formato" (SIN html2canvas):
 * 1. Registra atómicamente la emisión en MySQL cPanel (`POST /api/planillas-emitidas.php`) usando
 *    las credenciales actualizadas del perito logueado en sesión PHP (`/perfil`).
 * 2. Genera el Código QR Vectorial SVG en Rojo Forense (`#B50909`) + Barras Code-128 Vectoriales.
 * 3. Incrusta el sello nativamente en `.header-qr-seal` (esquina superior derecha de PlanillaHeader)
 *    y el hash SHA-256 en PlanillaFooter, preservando intactas las medidas exactas Folio 216mm×330mm.
 * 4. Permite guardar directamente como PDF Vectorial nativo del navegador (`window.print()`).
 */

import QRCode from 'qrcode';
import { renderCode128Svg } from './code128';
import { hashCanonical } from '../crypto/canonical';
import {
  phpApi,
  type ModalidadFirmaPlanilla,
  type PlanillaEmitidaDTO,
} from '../data/phpApi';

export const QR_FORENSIC_RED = '#B50909';

export interface SelloQrDomPayload {
  codigoPlanilla: string;
  qrUrl: string;
  hashEmisionSha256: string;
  qrSvg: string;
  barcodeSvg: string;
  offlineDraft?: boolean;
}

export interface GenerarPlanillaQrOptions {
  slug?: string;
  codigoDoc?: string;
  tituloPlanilla?: string;
  faseIso?: string;
  casoId?: string | null;
  numeroCaso?: string | null;
  numeroPRCC?: string | null;
  coPeritoNombre?: string | null;
  coPeritoCiv?: string | null;
  modalidadFirma?: ModalidadFirmaPlanilla;
  autoPrint?: boolean;
}

export interface GenerarPlanillaQrResult {
  planilla: PlanillaEmitidaDTO;
  qrUrl: string;
  qrSvg: string;
  barcodeSvg: string;
  offlineDraft: boolean;
}

/**
 * Genera el SVG vectorial del Código QR en color rojo forense `#B50909`
 */
export async function generateRedQrSvg(url: string): Promise<string> {
  return QRCode.toString(url, {
    type: 'svg',
    errorCorrectionLevel: 'Q',
    margin: 1,
    color: {
      dark: QR_FORENSIC_RED,
      light: '#FFFFFF',
    },
  });
}

/**
 * Estampa nativamente el Sello QR Rojo, Barras Code-128, N° de Planilla y SHA-256
 * dentro del DOM real de la planilla oficial (PlanillaHeader + PlanillaFooter).
 */
export function estamparSelloQrEnDom(root: ParentNode, payload: SelloQrDomPayload): number {
  let stampedCount = 0;

  root.querySelectorAll<HTMLElement>('.header-institution-row').forEach((row) => {
    row.classList.add('has-qr-seal');
  });

  root.querySelectorAll<HTMLElement>('[data-qr-seal]').forEach((seal) => {
    seal.hidden = false;
    seal.setAttribute('data-codigo-planilla', payload.codigoPlanilla);

    const svgHolder = seal.querySelector<HTMLAnchorElement>('[data-qr-svg]');
    if (svgHolder) {
      svgHolder.innerHTML = payload.qrSvg;
      svgHolder.href = payload.qrUrl;
    }

    const codeEl = seal.querySelector<HTMLElement>('[data-qr-code]');
    if (codeEl) {
      codeEl.textContent = payload.codigoPlanilla;
    }

    const badgeEl = seal.querySelector<HTMLElement>('.header-qr-badge');
    if (badgeEl) {
      badgeEl.textContent = payload.offlineDraft ? 'BORRADOR LOCAL' : 'SHA256.US · QR';
    }

    const barsEl = seal.querySelector<HTMLElement>('[data-qr-bars]');
    if (barsEl) {
      barsEl.innerHTML = payload.barcodeSvg;
    }

    stampedCount++;
  });

  // Rellenar el Sello Criptográfico SHA-256 oficial en el pie de cada hoja (PlanillaFooter)
  root.querySelectorAll<HTMLElement>('[data-qr-sha256]').forEach((hashEl) => {
    hashEl.textContent = `${payload.hashEmisionSha256} | ID: ${payload.codigoPlanilla}`;
  });

  return stampedCount;
}

/**
 * Lee el perito logueado desde sessionStorage como respaldo offline
 */
function readSessionUserFallback() {
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
  };
}

/**
 * Registra la emisión en cPanel MySQL (1 clic), incrusta el QR Rojo nativo en la planilla activa
 * y opcionalmente abre el diálogo nativo de Guardar como PDF / Imprimir vectorial (100% exacto).
 */
export async function generarPlanillaConQrNativo(
  opts: GenerarPlanillaQrOptions = {}
): Promise<GenerarPlanillaQrResult> {
  const container =
    document.getElementById('contenedor-planilla-activa') ||
    document.querySelector<HTMLElement>('.folio-forense-aislado') ||
    document.body;

  const slug =
    opts.slug ||
    container.getAttribute('data-slug') ||
    window.location.pathname.split('/').pop()?.replace('.html', '') ||
    'planilla';

  const tituloPlanilla =
    opts.tituloPlanilla ||
    container.querySelector('.canonical-doc-title')?.textContent?.trim() ||
    document.title ||
    slug;

  const codigoDoc =
    opts.codigoDoc ||
    container.querySelector('.control-box-val')?.textContent?.trim() ||
    'FO-FOR-01';

  const faseMatch = codigoDoc.match(/F[0-5]/i);
  const faseIso = opts.faseIso || (faseMatch ? faseMatch[0].toUpperCase() : 'F0');
  const modalidadFirma: ModalidadFirmaPlanilla = opts.modalidadFirma || 'hibrida';

  // 1. Registrar en base de datos cPanel (MySQL planillas_emitidas + auditoria)
  let planilla: PlanillaEmitidaDTO;
  let qrUrl: string;
  let offlineDraft = false;

  const apiRes = await phpApi.emitirPlanilla({
    planillaSlug: slug,
    codigoDoc,
    tituloPlanilla,
    faseIso,
    casoId: opts.casoId ?? null,
    numeroCaso: opts.numeroCaso ?? null,
    numeroPRCC: opts.numeroPRCC ?? null,
    coPeritoNombre: opts.coPeritoNombre ?? null,
    coPeritoCiv: opts.coPeritoCiv ?? null,
    modalidadFirma,
  });

  if (apiRes.ok && apiRes.data?.planilla) {
    planilla = apiRes.data.planilla;
    qrUrl =
      apiRes.data.qrUrl ||
      `${window.location.origin}/verificar?codigo=${encodeURIComponent(planilla.codigoPlanilla)}`;
  } else {
    offlineDraft = true;
    const localUser = readSessionUserFallback();
    const nowUtc = new Date().toISOString();
    const localCode = `LOCAL-${new Date().getFullYear()}-${String(Date.now()).slice(-6)}`;
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

    planilla = {
      codigoPlanilla: localCode,
      planillaSlug: slug,
      codigoDoc,
      tituloPlanilla,
      faseIso,
      casoId: opts.casoId ?? null,
      numeroCaso: opts.numeroCaso ?? null,
      numeroPRCC: opts.numeroPRCC ?? null,
      perito: {
        usuarioId: localUser.id,
        nombre: localUser.nombre,
        ci: localUser.ci,
        civ: localUser.civ,
        inpre: localUser.inpre,
        cargo: localUser.cargo,
        organismo: localUser.organismo,
      },
      coPerito: opts.coPeritoNombre
        ? { nombre: opts.coPeritoNombre, civ: opts.coPeritoCiv || '' }
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

    const origin = window.location?.origin?.startsWith('http')
      ? window.location.origin
      : 'https://sha256.us';
    qrUrl = `${origin}/verificar?codigo=${encodeURIComponent(localCode)}`;

    try {
      const storeKey = 'fcco_planillas_emitidas_local';
      const existing: Record<string, PlanillaEmitidaDTO> = JSON.parse(
        localStorage.getItem(storeKey) || '{}'
      );
      existing[localCode] = planilla;
      localStorage.setItem(storeKey, JSON.stringify(existing));
    } catch {
      // ignorar cuota
    }
  }

  // 2. Generar QR Rojo Vectorial SVG + Barras Code-128 Vectoriales SVG
  const [qrSvg, barcodeSvg] = await Promise.all([
    generateRedQrSvg(qrUrl),
    Promise.resolve(
      renderCode128Svg(planilla.codigoPlanilla, {
        color: QR_FORENSIC_RED,
        height: 14,
        quietZone: 4,
      })
    ),
  ]);

  // 3. Incrustar nativamente en el formato real de la planilla (PlanillaHeader + PlanillaFooter)
  estamparSelloQrEnDom(container, {
    codigoPlanilla: planilla.codigoPlanilla,
    qrUrl,
    hashEmisionSha256: planilla.hashEmisionSha256,
    qrSvg,
    barcodeSvg,
    offlineDraft,
  });

  // 4. Ajustar document.title para que "Guardar como PDF" sugiera el nombre oficial con código
  const cleanTitle = tituloPlanilla.replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑ_-]/g, '_').slice(0, 60);
  document.title = `${planilla.codigoPlanilla}_${cleanTitle}`;

  // 5. Esperar 1 frame de pintado y abrir diálogo nativo Guardar PDF / Imprimir vectorial
  if (opts.autoPrint) {
    setTimeout(() => {
      window.print();
    }, 280);
  }

  return {
    planilla,
    qrUrl,
    qrSvg,
    barcodeSvg,
    offlineDraft,
  };
}
