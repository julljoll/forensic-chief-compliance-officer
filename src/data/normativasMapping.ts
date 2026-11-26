// Mapeo técnico-normativo verificado exclusivamente contra RAG/Informacion_docling_rag/Informatica/

export interface NormativaRAGItem {
  codigo: string;
  nombre: string;
  ambito: 'Internacional' | 'Nacional (Venezuela)' | 'Técnico / RFC';
  descripcion: string;
  articuloRelevante: string;
  cumplimientoRequerido: string;
  archivoRag: string;
}

export interface EvidenciaNormativaGroup {
  categoriaId: 'movil' | 'computadora' | 'usb' | 'dvd_imagen';
  tituloCategoria: string;
  icono: string;
  normativas: NormativaRAGItem[];
}

const BASE = 'RAG/Informacion_docling_rag/Informatica';

export const NORMATIVAS_RAG_MAPPING: Record<string, EvidenciaNormativaGroup> = {
  movil: {
    categoriaId: 'movil',
    tituloCategoria: 'Teléfonos Móviles, Mensajería y Dispositivos Celulares',
    icono: 'Smartphone',
    normativas: [
      {
        codigo: 'ISO/IEC 27037:2012',
        nombre: 'Directrices para Identificación, Recolección, Adquisición y Preservación de Evidencia Digital',
        ambito: 'Internacional',
        descripcion: 'Define el aislamiento electromagnético (Bolsa Faraday / Modo Avión) y preservación antes de la adquisición.',
        articuloRelevante: '§5.4.2–5.4.4 y §7.1.3 - Manejo y adquisición de dispositivos digitales',
        cumplimientoRequerido: 'Fijación fotográfica 360°, modo avión activado, bolsa Faraday y bloqueo de conexiones.',
        archivoRag: `${BASE}/ISO IEC 27037-2012.md`,
      },
      {
        codigo: 'NIST SP 800-101 Rev. 1',
        nombre: 'Guidelines on Mobile Device Forensics',
        ambito: 'Internacional',
        descripcion: 'Protocolo de extracción lógica/física en dispositivos móviles, parseo de bases SQLite y preservación de SIM.',
        articuloRelevante: 'Preservación RF y niveles de adquisición lógica/física',
        cumplimientoRequerido: 'Extracción verificada con hash SHA-256 sobre copia de trabajo.',
        archivoRag: `${BASE}/Guidelines on Mobile Device-NIST Special Publication 800-101.md`,
      },
      {
        codigo: 'MUCC-2017',
        nombre: 'Manual Único de Cadena de Custodia de Evidencias Físicas',
        ambito: 'Nacional (Venezuela)',
        descripcion: 'Regula la modalidad de Consignación, embalaje, precintado numerado y registro continuo en Planilla PRCC.',
        articuloRelevante: 'Fase Inicial y Fase de Laboratorio - Registro obligatorio en PRCC',
        cumplimientoRequerido: 'Planilla PRCC abierta con firmas bilaterales e impresiones dactilares.',
        archivoRag: `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      },
      {
        codigo: 'LEDI-2001 (G.O. N° 37.313)',
        nombre: 'Ley Especial contra los Delitos Informáticos',
        ambito: 'Nacional (Venezuela)',
        descripcion: 'Protege la privacidad de la data y de las comunicaciones personales.',
        articuloRelevante: 'Arts. 20, 21 y 22 (Privacidad de la data, comunicaciones y no revelación)',
        cumplimientoRequerido: 'Consentimiento informado expreso del titular o interlocutor legítimo consignante.',
        archivoRag: `${BASE}/Ley Especial de Delitos informáticos (2001). Publicado en Gaceta Oficial Nº 37.313 .md`,
      },
      {
        codigo: 'LMDFE (G.O. N° 37.148)',
        nombre: 'Decreto-Ley sobre Mensajes de Datos y Firmas Electrónicas',
        ambito: 'Nacional (Venezuela)',
        descripcion: 'Reconoce eficacia probatoria y valor de original a mensajes de datos y archivos multimedia íntegros.',
        articuloRelevante: 'Arts. 4 y 7 - Eficacia probatoria e integridad inalterada',
        cumplimientoRequerido: 'Cálculo y verificación del hash SHA-256 de bases msgstore.db y adjuntos.',
        archivoRag: `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
      },
      {
        codigo: 'RFC 3227',
        nombre: 'Guidelines for Evidence Collection and Archiving',
        ambito: 'Técnico / RFC',
        descripcion: 'Prioriza el orden de volatilidad y el registro cronológico de toda recolección digital.',
        articuloRelevante: 'Orden de Volatilidad (datos volátiles antes de persistentes)',
        cumplimientoRequerido: 'Documentación secuencial de estado antes de manipular el dispositivo.',
        archivoRag: `${BASE}/RFC 3227 (2002).md`,
      },
    ],
  },
  computadora: {
    categoriaId: 'computadora',
    tituloCategoria: 'Análisis de Computadoras, Servidores y Discos Duros',
    icono: 'HardDrive',
    normativas: [
      {
        codigo: 'NIST SP 800-86',
        nombre: 'Guide to Integrating Forensic Techniques into Incident Response',
        ambito: 'Internacional',
        descripcion: 'Estándar para recolección, clonación bit-a-bit y examen de sistemas de archivos y logs.',
        articuloRelevante: '§3 Media Forensics & Bit-Stream Acquisition',
        cumplimientoRequerido: 'Adquisición bit-a-bit con validación de hash SHA-256.',
        archivoRag: `${BASE}/NIST SP 800-86_ingles.md`,
      },
      {
        codigo: 'ISO/IEC 27042:2015',
        nombre: 'Directrices para el Análisis e Interpretación de Evidencia Digital',
        ambito: 'Internacional',
        descripcion: 'Establece criterios de repetibilidad y reproducibilidad en el análisis de logs, sistemas y metadatos.',
        articuloRelevante: '§7–9 Análisis reproducible sobre copia de trabajo',
        cumplimientoRequerido: 'Análisis exclusivo sobre copia de trabajo sin modificar el medio original.',
        archivoRag: `${BASE}/ISO-IEC 27042 2015.md`,
      },
      {
        codigo: 'ACPO-v5',
        nombre: 'ACPO Good Practice Guide for Digital Evidence v5',
        ambito: 'Internacional',
        descripcion: '4 Principios: no alterar datos originales, competencia del analista, auditoría completa y cumplimiento legal.',
        articuloRelevante: 'Principios 1 y 3 - Preservación original y pista de auditoría',
        cumplimientoRequerido: 'Intervención exclusiva sobre copias bit-a-bit y registro completo.',
        archivoRag: `${BASE}/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.md`,
      },
      {
        codigo: 'MUCC-2017 · COPP Art. 225',
        nombre: 'Manual Único de Cadena de Custodia y Reglas del Dictamen Pericial',
        ambito: 'Nacional (Venezuela)',
        descripcion: 'Regula la cadena de custodia en laboratorio y la estructura motivada del dictamen pericial.',
        articuloRelevante: 'MUCC-2017 Fase de Laboratorio · COPP Arts. 187, 223–225',
        cumplimientoRequerido: 'Acta de Desprecintado y Dictamen Oficial colegiado por dos peritos.',
        archivoRag: `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      },
    ],
  },
  usb: {
    categoriaId: 'usb',
    tituloCategoria: 'Medios Extraíbles (USB, Tarjetas SD, Pen Drives)',
    icono: 'Database',
    normativas: [
      {
        codigo: 'ISO/IEC 27037:2012 §7.1.3',
        nombre: 'Bloqueo de Escritura en Medios Removibles',
        ambito: 'Internacional',
        descripcion: 'Exige el empleo de bloqueadores de escritura por hardware o software (Write-Blockers) al adquirir medios.',
        articuloRelevante: '§5.4.4 y §7.1.3.3 - Adquisición sin alteración del medio origen',
        cumplimientoRequerido: 'Conexión mediante write-blocker certificado y verificación de hash MATCH.',
        archivoRag: `${BASE}/ISO IEC 27037-2012.md`,
      },
      {
        codigo: 'MUCC-2017 (Embalaje)',
        nombre: 'Rotulado y Precintado de Evidencia Digital',
        ambito: 'Nacional (Venezuela)',
        descripcion: 'Embalaje individual con precinto de seguridad numerado y registro en Planilla PRCC.',
        articuloRelevante: 'Fase Inicial - Embalaje, Rotulación y PRCC',
        cumplimientoRequerido: 'Asignación de N° PRCC, precinto numerado e identificación física.',
        archivoRag: `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
      },
      {
        codigo: 'CENIF (G.O. N° 39.847) · ISO/IEC 27042:2015',
        nombre: 'Idoneidad de Técnicas y Herramientas Forenses Validadas',
        ambito: 'Nacional (Venezuela)',
        descripcion: 'Exige el uso de técnicas y herramientas forenses ampliamente probadas y aceptadas que no alteren el medio.',
        articuloRelevante: 'CENIF G.O. N° 39.847 · ISO/IEC 27042 §7.3',
        cumplimientoRequerido: 'Registro de herramienta validada y versión empleada en la adquisición y análisis.',
        archivoRag: `${BASE}/Creación del CENIF (2012). Centro Nacional de Informática Forense. Publicado en Gaceta Oficial N° 39.847 de fecha 20 de enero..md`,
      },
    ],
  },
  dvd_imagen: {
    categoriaId: 'dvd_imagen',
    tituloCategoria: 'DVD / Medios Ópticos / Imágenes Forenses (.E01 / .DD / .RAW)',
    icono: 'Disc',
    normativas: [
      {
        codigo: 'ISO/IEC 27042:2015',
        nombre: 'Validación e Inalterabilidad de Imágenes Forenses',
        ambito: 'Internacional',
        descripcion: 'Norma la preservación e interpretación reproducible sobre imágenes forenses verificadas.',
        articuloRelevante: '§7–8 Integridad y repetibilidad de copias de trabajo',
        cumplimientoRequerido: 'Verificación del hash SHA-256 de la imagen contra el registro en actas.',
        archivoRag: `${BASE}/ISO-IEC 27042 2015.md`,
      },
      {
        codigo: 'NIST SP 800-86',
        nombre: 'Verificación de Integridad mediante Hash Criptográfico',
        ambito: 'Internacional',
        descripcion: 'Comparación exacta del digest SHA-256 entre el medio original y la imagen adquirida.',
        articuloRelevante: '§3.1.2 Verificación de copia bit-a-bit',
        cumplimientoRequerido: 'Coincidencia MATCH de 64 caracteres hexadecimales SHA-256.',
        archivoRag: `${BASE}/NIST SP 800-86_ingles.md`,
      },
      {
        codigo: 'ISO/IEC 27001:2022 · ISO/IEC 27002:2022',
        nombre: 'Controles de Resguardo Físico y Supresión Segura',
        ambito: 'Internacional',
        descripcion: 'Custodia controlada en bóveda y supresión segura de copias temporales tras finalizar el peritaje.',
        articuloRelevante: 'A.8.10 Supresión de información y A.8.15 Logs de auditoría',
        cumplimientoRequerido: 'Resguardo en bóveda de evidencias y sanitización certificada en F5.',
        archivoRag: `${BASE}/ISO 27002_2022 ES.md`,
      },
    ],
  },
};
