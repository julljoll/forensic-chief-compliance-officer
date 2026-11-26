// Etapas verificadas exclusivamente contra RAG/Informacion_docling_rag/Informatica/

export interface EtapaNormativa {
  id: string;
  nombre: string;
  descripcion: string;
  archivoRag?: string;
  subetapas?: { id: string; nombre: string; descripcion: string }[];
}

export interface NormativaConEtapas {
  normativaId: string;
  codigo: string;
  archivoRag: string;
  etapas: EtapaNormativa[];
}

const BASE = 'RAG/Informacion_docling_rag/Informatica';

export const NORMATIVAS_ETAPAS: NormativaConEtapas[] = [
  {
    normativaId: 'n1',
    codigo: 'ISO/IEC 27037:2012',
    archivoRag: `${BASE}/ISO IEC 27037-2012.md`,
    etapas: [
      { id: 'n1__identificacion', nombre: '1. Identificación (§5.4.2)', descripcion: 'Reconocer potenciales fuentes de evidencia digital y fijar su estado inicial.' },
      { id: 'n1__recopilacion', nombre: '2. Recolección (§5.4.3)', descripcion: 'Aislar y recolectar dispositivos físicos o medios digitales con embalaje seguro.' },
      { id: 'n1__adquisicion', nombre: '3. Adquisición (§5.4.4)', descripcion: 'Obtener copia forense verificable mediante hash criptográfico SHA-256.' },
      { id: 'n1__preservacion', nombre: '4. Preservación (§5.4.5)', descripcion: 'Mantener la integridad de la evidencia y la cadena de custodia sin alteraciones.' },
    ],
  },
  {
    normativaId: 'n2',
    codigo: 'ISO/IEC 27042:2015',
    archivoRag: `${BASE}/ISO-IEC 27042 2015.md`,
    etapas: [
      { id: 'n2__preparacion', nombre: '1. Preparación del Análisis', descripcion: 'Verificar precintos, confirmar hash de copia de trabajo y cotejar PRCC.' },
      { id: 'n2__examen', nombre: '2. Examen de la Evidencia', descripcion: 'Examinar la copia de trabajo sin modificar jamás la evidencia original.' },
      { id: 'n2__analisis', nombre: '3. Análisis de Datos (§7)', descripcion: 'Aplicar técnicas forenses repetibles y reproducibles con herramientas validadas.' },
      { id: 'n2__interpretacion', nombre: '4. Interpretación y Reporte (§8–9)', descripcion: 'Evaluar hallazgos con sustento científico y emitir dictamen motivado.' },
    ],
  },
  {
    normativaId: 'n3',
    codigo: 'NIST SP 800-101 r1',
    archivoRag: `${BASE}/Guidelines on Mobile Device-NIST Special Publication 800-101.md`,
    etapas: [
      { id: 'n3__preservacion', nombre: '1. Preservación Móvil', descripcion: 'Activar Modo Avión e introducir el dispositivo en bolsa de aislamiento RF (Faraday).' },
      { id: 'n3__adquisicion', nombre: '2. Adquisición Lógica / Física', descripcion: 'Extraer almacenamiento interno, bases SQLite y tarjetas SIM/SD.' },
      { id: 'n3__examen', nombre: '3. Examen y Análisis de Artefactos', descripcion: 'Analizar mensajería, registros de llamadas, imágenes, notas de voz y metadatos.' },
      { id: 'n3__reporte', nombre: '4. Reporte Técnico', descripcion: 'Documentar herramientas, versiones, hashes y resultados.' },
    ],
  },
  {
    normativaId: 'n4',
    codigo: 'MUCC-2017',
    archivoRag: `${BASE}/MANUAL_ÚNICO_DE_CADENA DE_CUSTODIA_DE_EVIDENCIAS_(VERSIÓN_FINAL_29SEP17).md`,
    etapas: [
      {
        id: 'n4__fase_inicial',
        nombre: '1. Fase Inicial – Obtención',
        descripcion: 'Obtención de evidencia física/digital (Modalidad Consignación) y apertura de PRCC.',
        subetapas: [
          { id: 'n4__proteccion', nombre: 'Protección Técnica', descripcion: 'Delimitar y resguardar la integridad del medio consignado.' },
          { id: 'n4__observacion', nombre: 'Observación Preliminar', descripcion: 'Evaluar condiciones físicas iniciales.' },
          { id: 'n4__fijacion', nombre: 'Fijación', descripcion: 'Fijación fotográfica 360° y descripción escrita detallada.' },
          { id: 'n4__coleccion', nombre: 'Colección', descripcion: 'Recepción técnica documentada.' },
          { id: 'n4__embalaje', nombre: 'Embalaje y Rotulación', descripcion: 'Embalaje individual con precinto de seguridad numerado.' },
          { id: 'n4__prcc', nombre: 'Registro en PRCC', descripcion: 'Apertura formal de la Planilla de Registro de Cadena de Custodia.' },
        ],
      },
      {
        id: 'n4__fase_lab',
        nombre: '2. Fase de Laboratorio – Peritación',
        descripcion: 'Recepción, apertura de precinto, peritación técnica y remisión.',
        subetapas: [
          { id: 'n4__recepcion_lab', nombre: 'Recepción en Laboratorio', descripcion: 'Verificar indemnidad del precinto y concordancia con PRCC.' },
          { id: 'n4__designacion', nombre: 'Designación de Peritos', descripcion: 'Asignación colegiada de peritos competentes.' },
          { id: 'n4__peritaje', nombre: 'Peritaje', descripcion: 'Adquisición verificada con hash, análisis e interpretación.' },
          { id: 'n4__remision', nombre: 'Remisión de Resultados', descripcion: 'Emisión del dictamen pericial motivado.' },
        ],
      },
      {
        id: 'n4__fase_judicial',
        nombre: '3. Fase de Disposición Judicial',
        descripcion: 'Resguardo y exhibición probatoria ante tribunales.',
      },
      {
        id: 'n4__fase_final',
        nombre: '4. Fase de Disposición Final',
        descripcion: 'Devolución formal al titular, remisión fiscal o cierre de PRCC.',
      },
    ],
  },
  {
    normativaId: 'n5',
    codigo: 'ACPO-v5',
    archivoRag: `${BASE}/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.md`,
    etapas: [
      { id: 'n5__p1', nombre: 'Principio 1', descripcion: 'Ninguna acción debe alterar datos originales que puedan presentarse en juicio.' },
      { id: 'n5__p2', nombre: 'Principio 2', descripcion: 'Cuando sea necesario acceder a datos originales, el perito debe ser competente y explicar sus actos.' },
      { id: 'n5__p3', nombre: 'Principio 3', descripcion: 'Mantener registro de auditoría completo para permitir verificación independiente.' },
      { id: 'n5__p4', nombre: 'Principio 4', descripcion: 'El responsable de la investigación garantiza el cumplimiento legal y técnico.' },
    ],
  },
  {
    normativaId: 'n6',
    codigo: 'LEDI-2001',
    archivoRag: `${BASE}/Ley Especial de Delitos informáticos (2001). Publicado en Gaceta Oficial Nº 37.313 .md`,
    etapas: [
      { id: 'n6__sistemas', nombre: 'Arts. 6–12 – Delitos contra Sistemas', descripcion: 'Acceso indebido, sabotaje, espionaje informático y falsificación.' },
      { id: 'n6__privacidad', nombre: 'Arts. 20–22 – Privacidad de Data y Comunicaciones', descripcion: 'Legitimación por consentimiento expreso y prohibición de revelación indebida.' },
    ],
  },
  {
    normativaId: 'n7',
    codigo: 'LMDFE-2001',
    archivoRag: `${BASE}/Ley-sobre-Mensajes-de-Datos-y-Firmas-Electronicas.md`,
    etapas: [
      { id: 'n7__eficacia', nombre: 'Art. 4 – Eficacia Probatoria', descripcion: 'Los mensajes de datos tienen la misma eficacia probatoria que los documentos escritos.' },
      { id: 'n7__original', nombre: 'Art. 7 – Integridad y Valor de Original', descripcion: 'Acreditación de integridad inalterada desde su generación mediante hash criptográfico.' },
      { id: 'n7__firma', nombre: 'Art. 16 – Firma Electrónica', descripcion: 'Vinculación inequívoca del signatario con el mensaje de datos.' },
    ],
  },
  {
    normativaId: 'n8',
    codigo: 'LPPC-1991',
    archivoRag: `${BASE}/ley-sobre-proteccion-a-la-privacidad-de-las-comunicaciones.md`,
    etapas: [
      { id: 'n8__privacidad', nombre: 'Arts. 1–2 – Secreto de Comunicaciones', descripcion: 'Prohibición de interceptación o grabación clandestina entre terceros.' },
      { id: 'n8__forjamiento', nombre: 'Art. 4 – Prohibición de Forjamiento', descripcion: 'Sanción al forjamiento o alteración del contenido de comunicaciones.' },
    ],
  },
  {
    normativaId: 'n9',
    codigo: 'CENIF-2012',
    archivoRag: `${BASE}/Creación del CENIF (2012). Centro Nacional de Informática Forense. Publicado en Gaceta Oficial N° 39.847 de fecha 20 de enero..md`,
    etapas: [
      { id: 'n9__creacion', nombre: 'Creación del CENIF (G.O. 39.847)', descripcion: 'Prestación de servicios de peritaje informático forense a evidencias digitales.' },
      { id: 'n9__herramientas', nombre: 'Validación de Técnicas y Herramientas', descripcion: 'Uso de técnicas y herramientas forenses ampliamente probadas y aceptadas.' },
    ],
  },
  {
    normativaId: 'n10',
    codigo: 'ISO/IEC 27002:2022',
    archivoRag: `${BASE}/ISO 27002_2022 ES.md`,
    etapas: [
      { id: 'n10__fisicos', nombre: 'Controles Físicos', descripcion: 'Resguardo físico de evidencias en bóveda y control de acceso.' },
      { id: 'n10__supresion', nombre: 'A.8.10 – Supresión de Información', descripcion: 'Borrado seguro e irreversible de copias temporales tras el cierre del peritaje.' },
      { id: 'n10__logs', nombre: 'A.8.15 – Registro de Eventos (Logs)', descripcion: 'Bitácora inmutable de acciones realizadas en el sistema.' },
    ],
  },
  {
    normativaId: 'n11',
    codigo: 'ISO/IEC 27001:2022',
    archivoRag: `${BASE}/ISO-27001_2022_NOEDER.md`,
    etapas: [
      { id: 'n11__operacion', nombre: 'Operación del SGSI', descripcion: 'Control de riesgos, confidencialidad y cumplimiento documental.' },
      { id: 'n11__evaluacion', nombre: 'Evaluación y Auditoría', descripcion: 'Verificación de conformidad y mejora continua del laboratorio.' },
    ],
  },
  {
    normativaId: 'n13',
    codigo: 'NIST SP 800-86',
    archivoRag: `${BASE}/NIST SP 800-86_ingles.md`,
    etapas: [
      { id: 'n13__recoleccion', nombre: '1. Recolección', descripcion: 'Identificación, preservación y adquisición bit-a-bit con verificación de hash.' },
      { id: 'n13__examen', nombre: '2. Examen', descripcion: 'Extracción y preparación reproducible de datos en copia de trabajo.' },
      { id: 'n13__analisis', nombre: '3. Análisis', descripcion: 'Correlación técnica de hallazgos sobre sistemas de archivos y logs.' },
      { id: 'n13__reporte', nombre: '4. Reporte', descripcion: 'Documentación científica de metodología, herramientas y conclusiones.' },
    ],
  },
  {
    normativaId: 'n17',
    codigo: 'RFC 3227',
    archivoRag: `${BASE}/RFC 3227 (2002).md`,
    etapas: [
      { id: 'n17__volatilidad', nombre: 'Orden de Volatilidad', descripcion: 'Priorizar extracción de datos volátiles antes que persistentes.' },
      { id: 'n17__archivo', nombre: 'Archivo y Sumas Criptográficas', descripcion: 'Registrar cada paso y sellar con digest criptográfico.' },
    ],
  },
];
