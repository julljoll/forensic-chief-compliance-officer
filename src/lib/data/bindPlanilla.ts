/**
 * SHA256.US — Data Binder para Planillas Oficiales en Astro.
 * Gestiona el modo 'blanco' (para impresión limpia y llenado manual a bolígrafo)
 * y el modo 'datos' (rellena con los datos reales del expediente pericial).
 */

import { phpApi } from './phpApi';
import type { CasoCMS } from '../domain/types';

export async function bindPlanilla(_planillaId: string): Promise<CasoCMS | undefined> {
  if (typeof window === 'undefined') return undefined;

  const urlParams = new URLSearchParams(window.location.search);
  const casoId = urlParams.get('casoId') || urlParams.get('id');
  const modo = urlParams.get('modo') || (casoId ? 'datos' : 'blanco');

  // Modo Blanco: No cargar datos ficticios, asegurar campos limpios para escritura a mano
  if (modo === 'blanco') {
    const elements = document.querySelectorAll<HTMLElement>('[data-field]');
    elements.forEach((el) => {
      const current = el.textContent?.trim() || '';
      if (current.startsWith('[') && current.endsWith(']')) {
        el.textContent = '';
      }
    });
    return undefined;
  }

  // Modo Datos: Cargar el caso solicitado desde MySQL / IndexedDB (o el primer caso activo si no se pasó casoId)
  let caso: CasoCMS | undefined;
  if (casoId) {
    caso = await phpApi.obtenerCaso(casoId);
  } else {
    const lista = await phpApi.listarCasos();
    caso = lista[0];
  }

  // Normalizar alias entre esquema MySQL y campos de planillas
  const c: Record<string, any> = { ...(caso || {}) };
  c.numeroCaso = c.numeroCaso || c.numero_caso || c.expediente || 'MP-01-2026-WA';
  c.numero_prcc = c.numero_prcc || c.numeroPRCC || 'PRCC-2026-001';
  c.solicitante_nombre = c.solicitante_nombre || c.consignanteNombre || 'Insp. Jefe Luis Ortega';
  c.solicitante_cedula = c.solicitante_cedula || c.consignanteCedula || 'V-12.345.678';
  c.solicitante_telefono = c.solicitante_telefono || c.consignanteTelefono || '+58 412-5551234';
  c.solicitante_direccion = c.solicitante_direccion || c.consignanteDireccion || 'Sede Central / Domicilio Procesal';
  c.dispositivo_marca = c.dispositivo_marca || c.evidenciaMarca || c.discoduro_marca || 'Samsung';
  c.dispositivo_modelo = c.dispositivo_modelo || c.evidenciaModelo || c.discoduro_modelo || 'Galaxy A54';
  c.dispositivo_color = c.dispositivo_color || c.evidenciaColor || 'Negro Phantom';
  c.dispositivo_imei = c.dispositivo_imei || c.evidenciaSerial || c.discoduro_serial || '354928110948271';
  c.evidencia_tipo = c.evidenciaTipo || 'Teléfono Inteligente (Smartphone)';
  c.dispositivo_descripcion = `${c.evidencia_tipo} · ${c.dispositivo_marca} ${c.dispositivo_modelo} (${c.dispositivo_color})`.trim();
  c.dispositivo_estado_fisico = c.dispositivo_estado_fisico || c.evidenciaEstado || 'Operativo, pantalla y carcasa íntegras, sin daño físico aparente';
  c.peritoLider = c.peritoLider || c.peritoLiderNombre || 'Jull Joll (Perito Principal)';
  c.perito_cedula = c.perito_cedula || c.peritoLiderCedula || 'V-18.999.001';
  c.perito_civ = c.perito_civ || c.peritoLiderCiv || 'CIV-299410';
  c.perito_inpre = c.perito_inpre || 'INPRE-184920';
  c.perito_cargo = c.perito_cargo || 'Perito Informático Forense';
  c.co_perito_nombre = c.co_perito_nombre || c.perito_coadyuvante || 'Ing. SHA256 Adquisición';
  c.co_perito_cedula = c.co_perito_cedula || c.perito_coadyuvante_cedula || 'V-15.816.003';
  c.co_perito_civ = c.co_perito_civ || 'CIV-310520 · INPRE-201450';
  c.co_perito_cargo = c.co_perito_cargo || 'Perito Informático Forense (Co-Perito Colegiado)';
  c.despachoFiscal = c.despachoFiscal || c.fiscaliaTribunal || c.fiscal || 'Fiscalía / Tribunal de la Causa';
  c.organismoOrdenante = c.organismoOrdenante || 'Laboratorio de Informática Forense SHA256.US';
  c.bolsa_faraday_numero = c.bolsa_faraday_numero || 'FARADAY-2026-001';
  c.precinto_numero = c.precinto_numero || 'PREC-2026-991';
  c.hashSHA256 = c.hashSHA256 || c.hash_sha256 || 'b5f2a3e8c9d1047f6a2d3e8c9b5f1e2d7a4c0f3b8e5d2a9c6b3f0e7d1a2c3b4e';

  // 1. Llenar todos los elementos con [data-field]
  const elements = document.querySelectorAll<HTMLElement>('[data-field]');
  elements.forEach((el) => {
    const field = el.getAttribute('data-field') || '';
    const fallback = el.getAttribute('data-default') || '';
    const val = c[field] !== undefined && c[field] !== null && c[field] !== '' ? c[field] : fallback;

    if (val !== undefined && val !== '') {
      el.textContent = String(val);
      el.classList.remove('linea-manual');
    }

    if (el.isContentEditable && caso && field) {
      el.addEventListener('blur', async () => {
        const nuevoTexto = el.textContent?.trim() || '';
        (caso as any)[field] = nuevoTexto;
        await phpApi.guardarCaso(caso!);
      });
    }
  });

  // 2. Poblar elementos con [data-default] que no tienen data-field específico
  document.querySelectorAll<HTMLElement>('[data-default]:not([data-field])').forEach((el) => {
    const defVal = el.getAttribute('data-default');
    if (defVal) {
      el.textContent = defVal;
      el.classList.remove('linea-manual');
    }
  });

  return caso;
}

