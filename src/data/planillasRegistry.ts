/**
 * planillasRegistry.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Registro Unificado y Dinámico de las 13 Planillas Oficiales SHA256.US
 * Verificado exclusivamente contra RAG/Informacion_docling_rag/Informatica/.
 */

export interface PlanillaSectionDef {
  numero: string;
  titulo: string;
  descripcion: string;
  camposCount?: number;
}

export interface PlanillaRegistryDef {
  id: string;
  codigo: string;
  codigoFolio: string;
  slug: string;
  faseIso: 'F0' | 'F1' | 'F2' | 'F3' | 'F4' | 'F5';
  nombreOficial: string;
  subtitulo: string;
  etapaLegal: string;
  normativas: string[];
  archivosRag: string[];
  sections: PlanillaSectionDef[];
}

const BASE = 'RAG/Informacion_docling_rag/Informatica';

export const PLANILLAS_REGISTRY: Record<string, PlanillaRegistryDef> = {
  'acta-consentimiento': {
    id: 'acta-consentimiento',
    codigo: 'FO-SHA256-ACT-002',
    codigoFolio: 'FO-F0-01',
    slug: 'acta-consentimiento',
    faseIso: 'F0',
    nombreOficial: 'ACTA DE CONSENTIMIENTO INFORMADO Y AUTORIZACIÓN DE ACCESO',
    subtitulo: 'AUTORIZACIÓN EXPRESA POR CONSIGNACIÓN, HÁBEAS DATA Y EXCLUSIÓN DE ANTIJURIDICIDAD',
    etapaLegal: 'FASE F0: Apertura y Legitimación',
    normativas: ['CRBV Arts. 28, 48 y 60', 'LEDCI Arts. 20–22', 'LPPC Art. 2', 'ISO/IEC 27037 §5.2'],
    archivosRag: [
      `${BASE}/Ley Especial de Delitos informáticos (2001). Publicado en Gaceta Oficial Nº 37.313 .md`,
      `${BASE}/ley-sobre-proteccion-a-la-privacidad-de-las-comunicaciones.md`,
      `${BASE}/ISO IEC 27037-2012.md`,
      `${BASE}/Normativas SUSCERTE Forense Digital y Firma Electronica.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'DECLARACIÓN DE LEGITIMACIÓN, TITULARIDAD Y CALIDAD DE INTERLOCUTOR', descripcion: 'Acreditación del consignante titular o interlocutor directo.', camposCount: 4 },
      { numero: '2.0', titulo: 'AUTORIZACIÓN EXPRESA DE ADQUISICIÓN FORENSE POR CONSIGNACIÓN', descripcion: 'Identificación del dispositivo/medio, taxonomía y alcance técnico.', camposCount: 5 },
      { numero: '3.0', titulo: 'EXCLUSIÓN DE ANTIJURIDICIDAD Y PRIVACIDAD DE COMUNICACIONES', descripcion: 'Consentimiento libre e informado conforme a LEDCI Arts. 20–21 y CRBV Art. 60.', camposCount: 2 },
      { numero: '4.0', titulo: 'EXENCIÓN DE RESPONSABILIDAD TÉCNICA', descripcion: 'Alcance sobre datos preexistentes al momento de la consignación.', camposCount: 1 },
      { numero: '5.0', titulo: 'CIERRE LEGAL: FIRMAS Y HUELLAS DACTILARES BILATERALES', descripcion: 'Firma autógrafa y huellas dactilares (Pulgar Izq. y Der.) de consignante y perito.', camposCount: 4 },
    ],
  },

  'acta-entrevista': {
    id: 'acta-entrevista',
    codigo: 'FO-SHA256-ACT-004',
    codigoFolio: 'FO-F0-02',
    slug: 'acta-entrevista',
    faseIso: 'F0',
    nombreOficial: 'ACTA DE ENTREVISTA TÉCNICO-PERICIAL AL CONSIGNANTE',
    subtitulo: 'FIJACIÓN DE DECLARACIONES, CREDENCIALES DE ACCESO Y CONTEXTO BAJO JURAMENTO',
    etapaLegal: 'FASE F0: Apertura y Legitimación',
    normativas: ['MUCC-2017', 'CRBV Art. 49 ord. 5°', 'CP Arts. 243 y 246', 'ISO/IEC 27042'],
    archivosRag: [
      `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      `${BASE}/ISO-IEC 27042 2015.md`,
      `${BASE}/el peritaje informático.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'IDENTIFICACIÓN DEL CONSIGNANTE Y NOTIFICACIÓN CONSTITUCIONAL', descripcion: 'Datos de identidad y garantía contra la autoincriminación (CRBV Art. 49 ord. 5°).', camposCount: 5 },
      { numero: '2.0', titulo: 'CUESTIONARIO TÉCNICO DIRIGIDO A LA EXTRACCIÓN Y VALIDACIÓN JUDICIAL', descripcion: 'Objeto pericial, credenciales, rango cronológico e integridad previa.', camposCount: 5 },
      { numero: '3.0', titulo: 'DECLARACIÓN DE VERACIDAD Y CONFORMIDAD LEGAL', descripcion: 'Declaración bajo fe de juramento (CP Arts. 243 y 246).', camposCount: 1 },
      { numero: '4.0', titulo: 'CIERRE LEGAL: FIRMAS Y HUELLAS DACTILARES', descripcion: 'Firma y dactiloscopía bilateral de entrevistado y perito.', camposCount: 4 },
    ],
  },

  'acta-obtencion': {
    id: 'acta-obtencion',
    codigo: 'FO-SHA256-ACT-001',
    codigoFolio: 'FO-F1-03',
    slug: 'acta-obtencion',
    faseIso: 'F1',
    nombreOficial: 'ACTA DE OBTENCIÓN POR CONSIGNACIÓN Y PRESERVACIÓN',
    subtitulo: 'RECEPCIÓN FÍSICA, FIJACIÓN 360°, AISLAMIENTO FARADAY Y PRECINTADO NUMERADO',
    etapaLegal: 'FASE F1: Identificación y Recolección',
    normativas: ['MUCC-2017 Fase 1', 'COPP Art. 187', 'ISO/IEC 27037 §5.4.2 / §5.4.3', 'NIST SP 800-101'],
    archivosRag: [
      `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      `${BASE}/ISO IEC 27037-2012.md`,
      `${BASE}/Guidelines on Mobile Device-NIST Special Publication 800-101.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'DATOS DEL ACTO DE CONSIGNACIÓN Y PRESERVACIÓN', descripcion: 'Sede de recepción, fecha y hora.', camposCount: 2 },
      { numero: '2.0', titulo: 'IDENTIFICACIÓN COMPLETA DEL CONSIGNANTE', descripcion: 'Nombres, C.I./RIF, teléfono y dirección.', camposCount: 4 },
      { numero: '3.0', titulo: 'IDENTIFICACIÓN TÉCNICA DEL DISPOSITIVO MÓVIL Y MEDIO DIGITAL', descripcion: 'Taxonomía, marca, modelo, IMEI/serial y estado físico.', camposCount: 6 },
      { numero: '4.0', titulo: 'OBJETO DEL ENCARGO: ADQUISICIÓN FORENSE POR CONSIGNACIÓN', descripcion: 'Delimitación técnica de pruebas y fines judiciales.', camposCount: 2 },
      { numero: '5.0', titulo: 'MEDIDAS DE PRESERVACIÓN, EMBALAJE Y AISLAMIENTO ELECTROMAGNÉTICO', descripcion: 'Bolsa Faraday, precinto numerado, modo avión y fijación 360°.', camposCount: 6 },
      { numero: '6.0', titulo: 'DECLARACIÓN JURADA DE CONSIGNACIÓN Y APERTURA DE CADENA', descripcion: 'Entrega física formal y apertura de Planilla PRCC.', camposCount: 1 },
      { numero: '7.0', titulo: 'CIERRE LEGAL: FIRMAS Y HUELLAS DACTILARES', descripcion: 'Suscripción bilateral consignante-perito receptor.', camposCount: 4 },
    ],
  },

  'prcc': {
    id: 'prcc',
    codigo: 'FO-SHA256-PRCC-001',
    codigoFolio: 'FO-F1-04',
    slug: 'planilla-prcc',
    faseIso: 'F1',
    nombreOficial: 'PLANILLA DE REGISTRO DE CADENA DE CUSTODIA (PRCC)',
    subtitulo: 'REGISTRO INMUTABLE DE TRAZABILIDAD, TRASPASOS Y CUSTODIA DE EVIDENCIA DIGITAL',
    etapaLegal: 'FASE F1/F2: Cadena de Custodia Continua',
    normativas: ['MUCC-2017 §I–V', 'COPP Art. 187', 'LMDFE Art. 7', 'ISO/IEC 27037 §6.1'],
    archivosRag: [
      `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      `${BASE}/ISO IEC 27037-2012.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'DATOS GENERALES DE LA CAUSA Y DESPACHO INSTRUCTOR', descripcion: 'N° Causa, N° PRCC, oficio, despacho y sede.', camposCount: 6 },
      { numero: '2.0', titulo: 'FORMAS DE OBTENCIÓN DE LA EVIDENCIA (MUCC-2017)', descripcion: 'Técnica, Aseguramiento, Consignación y Derivación.', camposCount: 4 },
      { numero: '3.0', titulo: 'OPERARIOS ACTUANTES EN LA OBTENCIÓN Y PRESERVACIÓN', descripcion: 'Fijación fotográfica 360° y recepción/embalaje Faraday.', camposCount: 4 },
      { numero: '4.0', titulo: 'DESCRIPCIÓN DETALLADA DE LA EVIDENCIA Y HASH SHA-256', descripcion: 'Soporte físico, contenedor lógico, precinto y hash SHA-256.', camposCount: 4 },
      { numero: '5.0', titulo: 'REGISTRO CRONOLÓGICO DE TRANSFERENCIAS DE CUSTODIA', descripcion: 'Matriz de entregas, recepciones, motivos y estado del precinto.', camposCount: 6 },
    ],
  },

  'acta-desprecintado': {
    id: 'acta-desprecintado',
    codigo: 'FO-SHA256-ACT-003',
    codigoFolio: 'FO-F2-05',
    slug: 'acta-desprecintado',
    faseIso: 'F2',
    nombreOficial: 'ACTA DE DESPRECINTADO Y ADQUISICIÓN LÓGICA EN LABORATORIO',
    subtitulo: 'APERTURA CONTROLADA, EXTRACCIÓN CON HERRAMIENTA VALIDADA, HASH SHA-256 Y REEMBALAJE',
    etapaLegal: 'FASE F2: Adquisición y Preservación',
    normativas: ['ISO/IEC 27037 §5.4.4 / §7.1.3', 'NIST SP 800-101 / 800-86', 'MUCC-2017 Fase Laboratorio', 'LMDFE Art. 7'],
    archivosRag: [
      `${BASE}/ISO IEC 27037-2012.md`,
      `${BASE}/Guidelines on Mobile Device-NIST Special Publication 800-101.md`,
      `${BASE}/NIST SP 800-86_ingles.md`,
      `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'DATOS DE APERTURA Y MEDIO CONTROLADO DE LABORATORIO', descripcion: 'Área pericial aislada, fecha y hora.', camposCount: 2 },
      { numero: '2.0', titulo: 'TRAZABILIDAD DE PRECINTOS: INICIAL Y REEMBALAJE', descripcion: 'Verificación de indemnidad del precinto roto y nuevo precinto asignado.', camposCount: 4 },
      { numero: '3.0', titulo: 'ADQUISICIÓN LÓGICA / BIT-A-BIT FORENSE Y CÁLCULO DE HASH', descripcion: 'Modalidad, herramienta validada (CENIF), hash SHA-256 y verificación MATCH.', camposCount: 5 },
      { numero: '4.0', titulo: 'CONSTANCIA DE REEMBALAJE Y RESGUARDO', descripcion: 'Reembalaje del soporte original tras la extracción.', camposCount: 1 },
      { numero: '5.0', titulo: 'CIERRE LEGAL: FIRMAS COLEGIADAS DE PERITO EXTRACTOR Y CO-PERITO', descripcion: 'Suscripción bilateral de control de calidad en laboratorio.', camposCount: 4 },
    ],
  },

  'informe-audio-sonic': {
    id: 'informe-audio-sonic',
    codigo: 'FO-SHA256-AUD-002',
    codigoFolio: 'FO-F3-06',
    slug: 'planilla-audio-sonic',
    faseIso: 'F3',
    nombreOficial: 'PLANILLA DE ANÁLISIS FORENSE DE AUDIO Y ESPECTROGRAMA',
    subtitulo: 'ANÁLISIS ESPECTROGRÁFICO FFT, DECODIFICACIÓN OPUS 48 KHZ, FORMANTES Y TRAZA ENF',
    etapaLegal: 'FASE F3: Análisis e Interpretación',
    normativas: ['ISO/IEC 27042 §7–8', 'LMDFE Arts. 4 y 7', 'LPPC Art. 2', 'CENIF G.O. 39.847'],
    archivosRag: [
      `${BASE}/ISO-IEC 27042 2015.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
      `${BASE}/ley-sobre-proteccion-a-la-privacidad-de-las-comunicaciones.md`,
      `${BASE}/Creación del CENIF (2012). Centro Nacional de Informática Forense. Publicado en Gaceta Oficial N° 39.847 de fecha 20 de enero..md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'IDENTIFICACIÓN DE LA NOTA DE VOZ / ARCHIVO DE AUDIO Y HASH SHA-256', descripcion: 'Nombre de archivo, hash SHA-256 y herramienta Sonic Visualiser / Praat.', camposCount: 3 },
      { numero: '2.0', titulo: 'ESPECIFICACIONES TÉCNICAS ACÚSTICAS Y METADATOS DE TRANSMISIÓN', descripcion: 'Frecuencia, canales, profundidad, duración, códec y contenedor.', camposCount: 6 },
      { numero: '3.0', titulo: 'COTEJO ESPECTROGRÁFICO, CONTINUIDAD Y DETECCIÓN ANTI-DEEPFAKE', descripcion: 'Noise floor, formantes F1–F4, detección de edición y traza ENF 60 Hz.', camposCount: 4 },
      { numero: '4.0', titulo: 'CONCLUSIONES DEL PERITAJE DE AUDIO', descripcion: 'Valoración de autenticidad e integridad como mensaje de datos (LMDFE Art. 7).', camposCount: 1 },
      { numero: '5.0', titulo: 'CIERRE LEGAL: FIRMAS COLEGIADAS DE DOS PERITOS', descripcion: 'Co-perito en acústica y perito principal.', camposCount: 4 },
    ],
  },

  'informe_audio_sonic': {
    id: 'informe-audio-sonic',
    codigo: 'FO-SHA256-AUD-002',
    codigoFolio: 'FO-F3-06',
    slug: 'planilla-audio-sonic',
    faseIso: 'F3',
    nombreOficial: 'PLANILLA DE ANÁLISIS FORENSE DE AUDIO Y ESPECTROGRAMA',
    subtitulo: 'ANÁLISIS ESPECTROGRÁFICO FFT, DECODIFICACIÓN OPUS 48 KHZ, FORMANTES Y TRAZA ENF',
    etapaLegal: 'FASE F3: Análisis e Interpretación',
    normativas: ['ISO/IEC 27042 §7–8', 'LMDFE Arts. 4 y 7', 'LPPC Art. 2', 'CENIF G.O. 39.847'],
    archivosRag: [
      `${BASE}/ISO-IEC 27042 2015.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'IDENTIFICACIÓN DE LA NOTA DE VOZ / ARCHIVO DE AUDIO Y HASH SHA-256', descripcion: 'Nombre de archivo, hash SHA-256 y herramienta validada.', camposCount: 3 },
      { numero: '2.0', titulo: 'ESPECIFICACIONES TÉCNICAS ACÚSTICAS', descripcion: 'Parámetros técnicos del flujo de audio.', camposCount: 6 },
      { numero: '3.0', titulo: 'COTEJO ESPECTROGRÁFICO Y CONTINUIDAD', descripcion: 'Piso de ruido, formantes y verificación de edición.', camposCount: 4 },
      { numero: '4.0', titulo: 'CONCLUSIONES DEL PERITAJE DE AUDIO', descripcion: 'Veredicto técnico-científico.', camposCount: 1 },
      { numero: '5.0', titulo: 'CIERRE LEGAL COLEGIADO', descripcion: 'Firmas bilaterales y huellas dactilares.', camposCount: 4 },
    ],
  },

  'planilla-evaluacion-ux': {
    id: 'planilla-evaluacion-ux',
    codigo: 'FO-SHA256-EVA-001',
    codigoFolio: 'FO-F3-07',
    slug: 'planilla-evaluacion-ux',
    faseIso: 'F3',
    nombreOficial: 'PLANILLA DE EVALUACIÓN DE INTERFAZ UX Y CALIDAD DE SOFTWARE',
    subtitulo: 'COTEJO HEURÍSTICO DE CAPTURAS DE PANTALLA Y REDES SOCIALES VS REGISTROS SQLITE / LOGS',
    etapaLegal: 'FASE F3: Análisis e Interpretación',
    normativas: ['ISO/IEC 27042 §8', 'LMDFE Art. 4', 'AVILLA-FORENSICS'],
    archivosRag: [
      `${BASE}/ISO-IEC 27042 2015.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
      `${BASE}/analisis forense en android con avilla forensics.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'APLICACIÓN, RED SOCIAL Y ENTORNO DE EJECUCIÓN', descripcion: 'Software, plataforma y versión analizada.', camposCount: 2 },
      { numero: '2.0', titulo: 'MATRIZ DE COTEJO FORENSE: INTERFAZ VS SQLITE / LOGS', descripcion: 'Timestamps, estados de envío, JID, detección de simulación y no repudio.', camposCount: 5 },
      { numero: '3.0', titulo: 'DICTAMEN DE CONFORMIDAD DE SOFTWARE', descripcion: 'Correspondencia fidedigna entre interfaz visual y registros crudos.', camposCount: 1 },
      { numero: '4.0', titulo: 'CIERRE LEGAL: FIRMAS COLEGIADAS DE DOS PERITOS', descripcion: 'Firmas y huellas dactilares bilaterales.', camposCount: 4 },
    ],
  },

  'acta-dictamen': {
    id: 'acta-dictamen',
    codigo: 'FO-SHA256-DIC-000',
    codigoFolio: 'FO-F4-08',
    slug: 'acta-dictamen',
    faseIso: 'F4',
    nombreOficial: 'DICTAMEN PERICIAL OFICIAL DE INFORMÁTICA FORENSE',
    subtitulo: 'INFORME CIENTÍFICO MOTIVADO COLEGIADO POR DOS PERITOS PARA TRIBUNALES',
    etapaLegal: 'FASE F4: Informe Pericial y Dictamen',
    normativas: ['COPP Arts. 187, 223–225', 'LMDFE Arts. 4 y 7', 'CENIF G.O. 39.847', 'ISO/IEC 27037 / 27042', 'UNE 197010'],
    archivosRag: [
      `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      `${BASE}/ISO-IEC 27042 2015.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
      `${BASE}/Creación del CENIF (2012). Centro Nacional de Informática Forense. Publicado en Gaceta Oficial N° 39.847 de fecha 20 de enero..md`,
      `${BASE}/borrador para lista de leyes-bibliografias.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'MARCO NORMATIVO Y FUNDAMENTACIÓN JURÍDICA', descripcion: 'COPP, LMDFE, CENIF, NIST e ISO/IEC.', camposCount: 4 },
      { numero: '2.0', titulo: 'INDIVIDUALIZACIÓN DE LA EVIDENCIA CONSIGNADA Y HASH SHA-256', descripcion: 'Dispositivo/medio, PRCC, precinto, artefactos y verificación MATCH.', camposCount: 5 },
      { numero: '3.0', titulo: 'METODOLOGÍA FORENSE Y PROCEDIMIENTO TÉCNICO APLICADO', descripcion: 'Adquisición verificada y análisis sobre copia de trabajo.', camposCount: 2 },
      { numero: '4.0', titulo: 'HALLAZGOS PERICIALES', descripcion: 'Resultados técnicos sobre mensajería, imágenes, audios y medios.', camposCount: 2 },
      { numero: '5.0', titulo: 'DICTAMEN MOTIVADO Y JURAMENTO DE LEY', descripcion: 'Conclusiones unánimes y firma colegiada de dos peritos (COPP Art. 223).', camposCount: 4 },
    ],
  },

  'dictamen-imagenes': {
    id: 'dictamen-imagenes',
    codigo: 'FO-SHA256-DIC-001',
    codigoFolio: 'FO-F4-09',
    slug: 'dictamen-imagenes',
    faseIso: 'F4',
    nombreOficial: 'DICTAMEN PERICIAL ESPECIALIZADO EN ANÁLISIS DE IMÁGENES',
    subtitulo: 'ANÁLISIS DE METADATOS EXIF, ERROR LEVEL ANALYSIS (ELA) E INTEGRIDAD DE PÍXELES',
    etapaLegal: 'FASE F4: Informe Pericial y Dictamen',
    normativas: ['COPP Arts. 223–225', 'LMDFE Arts. 4 y 7', 'ISO/IEC 27042'],
    archivosRag: [
      `${BASE}/ISO-IEC 27042 2015.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
      `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'MOTIVO Y DESCRIPCIÓN DEL OBJETO PERITADO (COPP ART. 225.1)', descripcion: 'Archivo de imagen/captura, hash SHA-256 y resolución.', camposCount: 3 },
      { numero: '2.0', titulo: 'OPERACIONES TÉCNICAS: ANÁLISIS EXIF Y METADATOS (COPP ART. 225.2)', descripcion: 'Sensor de captura, fecha original, GPS y ausencia de software de edición.', camposCount: 4 },
      { numero: '3.0', titulo: 'OPERACIONES TÉCNICAS: ANÁLISIS ELA Y PÍXELES', descripcion: 'Uniformidad de compresión y descarte de fotomontaje.', camposCount: 2 },
      { numero: '4.0', titulo: 'CONCLUSIONES Y DICTAMEN MOTIVADO (COPP ART. 225.3)', descripcion: 'Dictamen colegiado sobre autenticidad e integridad.', camposCount: 4 },
    ],
  },

  'dictamen-audios': {
    id: 'dictamen-audios',
    codigo: 'FO-SHA256-DIC-002',
    codigoFolio: 'FO-F4-10',
    slug: 'dictamen-audios',
    faseIso: 'F4',
    nombreOficial: 'DICTAMEN PERICIAL DE AUTENTICIDAD DE AUDIOS DIGITALES',
    subtitulo: 'ESPECTROGRAMA FFT, FORMANTES VOCÁLICOS, CONTINUIDAD OPUS Y REPRODUCIBILIDAD',
    etapaLegal: 'FASE F4: Informe Pericial y Dictamen',
    normativas: ['COPP Arts. 223–225', 'LMDFE Arts. 4 y 7', 'ISO/IEC 27042', 'CENIF G.O. 39.847'],
    archivosRag: [
      `${BASE}/ISO-IEC 27042 2015.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
      `${BASE}/Creación del CENIF (2012). Centro Nacional de Informática Forense. Publicado en Gaceta Oficial N° 39.847 de fecha 20 de enero..md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'MOTIVO Y ESPECIFICACIÓN TÉCNICA DEL OBJETO PERITADO (COPP ART. 225.1)', descripcion: 'Archivo de audio, hash SHA-256 y formato/frecuencia.', camposCount: 3 },
      { numero: '2.0', titulo: 'OPERACIONES TÉCNICAS: ESPECTROGRAMA FFT Y FORMANTES (COPP ART. 225.2)', descripcion: 'Formantes F1–F3, piso de ruido, traza ENF y análisis vocal.', camposCount: 4 },
      { numero: '3.0', titulo: 'RESULTADOS PARTICULARES Y REPRODUCIBILIDAD CIENTÍFICA', descripcion: 'Coherencia de la señal acústica sin cortes ni clonación sintética.', camposCount: 2 },
      { numero: '4.0', titulo: 'CONCLUSIONES Y DICTAMEN MOTIVADO (COPP ART. 225.3)', descripcion: 'Dictamen colegiado por dos peritos.', camposCount: 4 },
    ],
  },

  'entrega-resultados': {
    id: 'entrega-resultados',
    codigo: 'FO-SHA256-ACT-006',
    codigoFolio: 'FO-F5-11',
    slug: 'acta-entrega-resultados',
    faseIso: 'F5',
    nombreOficial: 'ACTA DE DISPOSICIÓN FINAL Y DEVOLUCIÓN DE EVIDENCIAS',
    subtitulo: 'ENTREGA DE DICTAMEN OFICIAL, COPIA MASTER Y DEVOLUCIÓN DEL MEDIO CONSIGNADO',
    etapaLegal: 'FASE F5: Entrega, Disposición y Sanitización',
    normativas: ['MUCC-2017 Disposición Final', 'COPP Art. 187', 'ISO/IEC 27037'],
    archivosRag: [
      `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      `${BASE}/ISO IEC 27037-2012.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'DATOS DEL ACTO DE DISPOSICIÓN FINAL Y DESTINO LEGAL', descripcion: '4 modalidades reglamentarias MUCC-2017 de disposición final.', camposCount: 4 },
      { numero: '2.0', titulo: 'IDENTIFICACIÓN DEL CONSIGNANTE RECEPTOR DE EVIDENCIAS', descripcion: 'Nombre, C.I. y carácter jurídico del receptor.', camposCount: 3 },
      { numero: '3.0', titulo: 'RELACIÓN DE DOCUMENTOS, DISPOSITIVOS Y COPIAS MASTER ENTREGADAS', descripcion: 'Dictamen, copia digital sellada, dispositivo devuelto y hash de cierre.', camposCount: 4 },
      { numero: '4.0', titulo: 'DECLARACIÓN DE RECEPCIÓN Y CONFORMIDAD', descripcion: 'Cierre de cadena de custodia sin observaciones.', camposCount: 1 },
      { numero: '5.0', titulo: 'CIERRE LEGAL: FIRMAS Y HUELLAS DACTILARES', descripcion: 'Suscripción bilateral de entrega y recepción conforme.', camposCount: 4 },
    ],
  },

  'acta-sanitizacion': {
    id: 'acta-sanitizacion',
    codigo: 'FO-SHA256-ACT-005',
    codigoFolio: 'FO-F5-12',
    slug: 'acta-sanitizacion',
    faseIso: 'F5',
    nombreOficial: 'ACTA DE SANITIZACIÓN CRIPTOGRÁFICA Y BORRADO SEGURO',
    subtitulo: 'PURGA IRREVERSIBLE DE COPIAS DE TRABAJO TEMPORALES EN LABORATORIO',
    etapaLegal: 'FASE F5: Entrega, Disposición y Sanitización',
    normativas: ['ISO/IEC 27001 / 27002 A.8.10', 'LEDCI Arts. 20 y 22', 'CRBV Art. 60'],
    archivosRag: [
      `${BASE}/ISO-27001_2022_NOEDER.md`,
      `${BASE}/ISO 27002_2022 ES.md`,
      `${BASE}/Ley Especial de Delitos informáticos (2001). Publicado en Gaceta Oficial Nº 37.313 .md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'VOLÚMENES TEMPORALES Y COPIAS LÓGICAS DE TRABAJO A SANITIZAR', descripcion: 'Volumen, serial de partición y hash SHA-256 previo.', camposCount: 3 },
      { numero: '2.0', titulo: 'PROTOCOLO DE DESTRUCCIÓN LÓGICA', descripcion: 'Nivel de purga, sobrescritura, utilidad empleada y verificación de no remanencia.', camposCount: 4 },
      { numero: '3.0', titulo: 'AUDITORÍA DE NO RETENCIÓN Y DEBER DE CONFIDENCIALIDAD', descripcion: 'Cumplimiento de LEDCI Arts. 20 y 22.', camposCount: 1 },
      { numero: '4.0', titulo: 'FE DE JURAMENTO Y CIERRE COLEGIADO', descripcion: 'Firmas de perito responsable y auditor de cumplimiento.', camposCount: 4 },
    ],
  },

  'acta-auditoria-timeline': {
    id: 'acta-auditoria-timeline',
    codigo: 'FO-SHA256-ACT-007',
    codigoFolio: 'FO-F5-13',
    slug: 'acta-auditoria-timeline',
    faseIso: 'F5',
    nombreOficial: 'ACTA DE AUDITORÍA Y TRAZABILIDAD CRIPTOGRÁFICA',
    subtitulo: 'HISTORIAL INMUTABLE DE EVENTOS CON CADENA DE HASHES CONCATENADOS SHA-256',
    etapaLegal: 'FASE F5: Entrega, Disposición y Sanitización',
    normativas: ['ISO/IEC 27037', 'ISO/IEC 27002 A.8.15', 'LMDFE Arts. 4, 7 y 16', 'UNE 71505'],
    archivosRag: [
      `${BASE}/ISO IEC 27037-2012.md`,
      `${BASE}/ISO 27002_2022 ES.md`,
      `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
      `${BASE}/Normativas SUSCERTE Forense Digital y Firma Electronica.md`,
    ],
    sections: [
      { numero: '1.0', titulo: 'ESTADO DE INTEGRIDAD DE LA CADENA DE BLOQUES FORENSE', descripcion: 'Expediente asignado, total de fases y verificación Hash-Chain.', camposCount: 3 },
      { numero: '2.0', titulo: 'REGISTRO CRONOLÓGICO DE EVENTOS Y CADENA DE HASHES SHA-256', descripcion: 'Secuencia cronológica F0–F5 con hashes sellados.', camposCount: 6 },
      { numero: '3.0', titulo: 'CERTIFICACIÓN DE NO REPUDIO Y CONTINUIDAD CRIPTOGRÁFICA', descripcion: 'Garantía matemática de inmutabilidad (RFC 8785 · LMDFE Art. 7).', camposCount: 1 },
      { numero: '4.0', titulo: 'FE PÚBLICA DE AUDITORÍA Y CIERRE COLEGIADO', descripcion: 'Firmas de perito auditor y oficial de cumplimiento.', camposCount: 4 },
    ],
  },
};

export function getPlanillaRegistry(id: string): PlanillaRegistryDef {
  const normalizedId = id.toLowerCase().trim();
  if (PLANILLAS_REGISTRY[normalizedId]) {
    return PLANILLAS_REGISTRY[normalizedId];
  }
  if (normalizedId === 'planilla-prcc') {
    return PLANILLAS_REGISTRY['prcc'];
  }
  if (normalizedId === 'acta-entrega-resultados') {
    return PLANILLAS_REGISTRY['entrega-resultados'];
  }
  if (normalizedId.includes('sonic') || (normalizedId.includes('audio') && normalizedId.includes('informe'))) {
    return PLANILLAS_REGISTRY['informe-audio-sonic'];
  }
  if (normalizedId.includes('evaluacion') || normalizedId.includes('ux')) {
    return PLANILLAS_REGISTRY['planilla-evaluacion-ux'];
  }
  if (normalizedId.includes('dictamen') && normalizedId.includes('audio')) {
    return PLANILLAS_REGISTRY['dictamen-audios'];
  }
  if (normalizedId.includes('dictamen') && normalizedId.includes('imagen')) {
    return PLANILLAS_REGISTRY['dictamen-imagenes'];
  }
  if (normalizedId.includes('dictamen')) {
    return PLANILLAS_REGISTRY['dictamen-imagenes'];
  }

  return {
    id: normalizedId,
    codigo: 'FO-SHA256-GEN-000',
    codigoFolio: 'FO-GEN-00',
    slug: normalizedId,
    faseIso: 'F0',
    nombreOficial: `PLANILLA FORENSE — ${normalizedId.toUpperCase()}`,
    subtitulo: 'DOCUMENTO PROBATORIO OFICIAL EN LABORATORIO SHA256.US',
    etapaLegal: 'CADENA DE CUSTODIA & COMPLIANCE',
    normativas: ['MUCC-2017', 'ISO/IEC 27037:2012', 'COPP Art. 187'],
    archivosRag: [`${BASE}/ISO IEC 27037-2012.md`],
    sections: [
      { numero: '1.0', titulo: 'DATOS GENERALES DEL CASO Y ACTUACIÓN', descripcion: 'Identificación del expediente y fecha de actuación.' },
      { numero: '2.0', titulo: 'DESCRIPCIÓN DE EVIDENCIA Y REGISTRO TÉCNICO', descripcion: 'Propiedades del elemento bajo peritaje.' },
      { numero: '3.0', titulo: 'REGISTRO DE CUSTODIA Y CERTIFICACIÓN', descripcion: 'Firmas de responsabilidad e inmutabilidad SHA-256.' },
    ],
  };
}
