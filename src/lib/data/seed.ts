/**
 * SHA256.US — Datos semilla derivados exclusivamente de la Fuente Única RAG:
 * RAG/Informacion_docling_rag/Informatica/
 */
import type { CasoCMS, Normativa } from '../domain/types';
import { RAG_INFORMATICA_CATALOG } from '../../data/ragInformaticaCatalog';

// ─── Normativas del RAG (100% vinculadas a RAG/Informacion_docling_rag/Informatica/) ───

export const NORMATIVAS_INICIALES: Normativa[] = RAG_INFORMATICA_CATALOG.map((doc) => ({
  id: doc.id,
  codigo: doc.codigo,
  tipo: doc.tipo,
  nombre: doc.nombreOficial,
  descripcion: doc.descripcion,
  version: doc.version,
  fechaVigencia: doc.fechaPublicacion || 'Vigente',
  urlReferencia: doc.archivoRag,
  hashPdfSha256: doc.hashPdfSha256,
  articulos: doc.articulosClave,
  activa: true,
}));

export const MOCK_CASOS: CasoCMS[] = [
  {
    id: 'caso-mock-1',
    tipoProyecto: 'forense_whatsapp',
    numeroCaso: 'MP-01-2026-WA',
    expediente: 'EXP-45920-2026',
    titulo: 'Extracción Forense - Caso Extorsión Telefónica',
    descripcion: 'Investigación pericial de mensajería instantánea en dispositivo móvil Android consignado. Adquisición lógica con AVILLA Forensics / ADB, parseo de msgstore.db con ALEAPP y análisis de notas de voz .opus.',
    estado: 'analisis',
    prioridad: 'alta',
    fechaCreacion: '2026-07-19T08:00:00.000Z',
    fechaUltimaActualizacion: '2026-07-19T09:30:00.000Z',
    peritoLider: '',
    fiscal: 'Dr. Alberto Silva (Fiscalía 12º del M.P. Estado Lara)',
    compliance: 'Conforme',
    despachoFiscal: 'Fiscalía 12º del Ministerio Público',
    organismoOrdenante: 'CICPC Delegación Quíbor',
    normativasAplicadas: ['n1', 'n4', 'n6', 'n7'],
    fasesCompletadas: 4,
    totalFases: 6,
    porcentajeCompletado: 67,
    totalEvidencias: 1,
    nivelCumplimientoGeneral: 'conforme',
    etiquetas: ['Android', 'WhatsApp', 'Consignación'],
    notas: 'Dispositivo embalado bajo cadena de custodia respetando MUCC-2017 e ISO/IEC 27037.',
    dispositivo_marca: 'Samsung',
    dispositivo_modelo: 'Galaxy A54',
    dispositivo_imei: '354928110948271',
    dispositivo_imei2: '354928110948272',
    dispositivo_sim_card: 'Movistar 4G',
    dispositivo_numero_tel: '+58 412-5551234',
    dispositivo_estado_fisico: 'Excelente estado, enciende correctamente.',
    dispositivo_modo_aislamiento: 'Modo Avión y bolsa Faraday',
    dispositivo_danos_visibles: 'Ninguno',
    dispositivo_bateria_estado: '85%',
    dispositivo_pantalla_estado: 'Operativa',
    solicitante_nombre: 'Insp. Jefe Luis Ortega',
    solicitante_cedula: 'V-12.345.678',
    steps: {
      wp_step1: { estado: 'completado', fechaInicio: '2026-07-19T08:05:00.000Z', fechaCompletado: '2026-07-19T08:15:00.000Z', responsable: '', observaciones: 'Se recibió y se levantaron actas preliminares.' },
      wp_step2: { estado: 'completado', fechaInicio: '2026-07-19T08:20:00.000Z', fechaCompletado: '2026-07-19T08:30:00.000Z', responsable: '', observaciones: 'Planilla PRCC completada y firmada.' },
      wp_step3: { estado: 'completado', fechaInicio: '2026-07-19T08:35:00.000Z', fechaCompletado: '2026-07-19T09:00:00.000Z', responsable: '', observaciones: 'Adquisición forense con AVILLA Forensics y cálculo de hash SHA-256.' },
      wp_step4: { estado: 'completado', fechaInicio: '2026-07-19T09:05:00.000Z', fechaCompletado: '2026-07-19T09:15:00.000Z', responsable: '', observaciones: 'Dispositivo sellado en bolsa Faraday y guardado en bóveda.' },
      wp_step5: { estado: 'disponible' }
    }
  }
];
