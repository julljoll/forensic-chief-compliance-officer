/**
 * SHA256.US — Codificador Vectorial Estándar ISO/IEC 15417 Code-128 (Subconjunto B)
 * Genera patrones exactos de barras y espacios para:
 * 1. Renderizado vectorial nítido en PDF (`pdf-lib` drawRectangle) sin pixelado al imprimir.
 * 2. Renderizado SVG en el Popup de Verificación QR (`/verificar`) para cotejo visual directo.
 */

// Tabla canónica ISO/IEC 15417 Code 128 (patrones de anchos: Barra, Espacio, Barra, Espacio, Barra, Espacio)
// Valores 0..105 suman 11 módulos cada uno; Stop (106) suma 13 módulos (7 elementos).
const CODE128_PATTERNS: readonly string[] = [
  '212222', '222122', '222221', '121223', '121322', '131222', '122213', '122312', // 0..7
  '132212', '221213', '221312', '231212', '112232', '122132', '122231', '113222', // 8..15
  '123122', '123221', '223211', '221132', '221231', '213212', '223112', '312131', // 16..23
  '311222', '321122', '321221', '312212', '322112', '322211', '212123', '212321', // 24..31
  '232121', '111323', '131123', '131321', '112313', '132113', '132311', '211313', // 32..39
  '231113', '231311', '112133', '112331', '132131', '113123', '113321', '133121', // 40..47
  '313121', '211331', '231131', '213113', '213311', '213131', '311123', '311321', // 48..55
  '331121', '312113', '312311', '332111', '314111', '221411', '431111', '111224', // 56..63
  '111422', '121124', '121421', '141122', '141221', '112214', '112412', '122114', // 64..71
  '122411', '142112', '142211', '241211', '221114', '413111', '241112', '134111', // 72..79
  '111242', '121142', '121241', '114212', '124112', '124211', '411212', '421112', // 80..87
  '421211', '212141', '214121', '412121', '111143', '111341', '131141', '114113', // 88..95
  '114311', '411113', '411311', '113141', '114131', '311141', '411131',           // 96..102
  '211412', // 103: START A
  '211214', // 104: START B
  '211232', // 105: START C
  '2331112', // 106: STOP (13 módulos)
];

const START_CODE_B = 104;
const STOP_CODE = 106;

export interface Code128Encoded {
  text: string;
  /** Secuencia binaria de módulos ('1' = barra, '0' = espacio) */
  modules: string;
  /** Segmentos de barras listas para dibujo vectorial (offset en módulos y ancho en módulos) */
  bars: Array<{ x: number; w: number }>;
  /** Total de módulos de ancho (sin quiet zone) */
  totalModules: number;
  checksum: number;
}

/**
 * Codifica una cadena ASCII imprimible (32..126) usando Code-128B con dígito verificador mod 103.
 */
export function encodeCode128B(input: string): Code128Encoded {
  const sanitized = input
    .trim()
    .replace(/[^\x20-\x7E]/g, '')
    .slice(0, 48);

  if (!sanitized) {
    throw new Error('Code-128B requiere al menos un carácter ASCII imprimible');
  }

  const values: number[] = [START_CODE_B];
  let checksumSum = START_CODE_B;

  for (let i = 0; i < sanitized.length; i++) {
    const codeVal = sanitized.charCodeAt(i) - 32;
    values.push(codeVal);
    checksumSum += codeVal * (i + 1);
  }

  const checksum = checksumSum % 103;
  values.push(checksum);
  values.push(STOP_CODE);

  let modules = '';
  for (const v of values) {
    const pattern = CODE128_PATTERNS[v];
    for (let j = 0; j < pattern.length; j++) {
      const width = Number(pattern[j]);
      const bit = j % 2 === 0 ? '1' : '0';
      modules += bit.repeat(width);
    }
  }

  const bars: Array<{ x: number; w: number }> = [];
  let idx = 0;
  while (idx < modules.length) {
    if (modules[idx] === '1') {
      const start = idx;
      while (idx < modules.length && modules[idx] === '1') {
        idx++;
      }
      bars.push({ x: start, w: idx - start });
    } else {
      idx++;
    }
  }

  return {
    text: sanitized,
    modules,
    bars,
    totalModules: modules.length,
    checksum,
  };
}

/**
 * Genera un SVG vectorial limpio de Code-128B para mostrar en la web (ej. Popup de Corroboración QR)
 */
export function renderCode128Svg(
  text: string,
  options: { color?: string; height?: number; quietZone?: number } = {}
): string {
  const color = options.color ?? '#B50909';
  const height = options.height ?? 34;
  const quietZone = options.quietZone ?? 8;

  const encoded = encodeCode128B(text);
  const totalWidth = encoded.totalModules + quietZone * 2;
  const rects = encoded.bars
    .map((b) => `<rect x="${b.x + quietZone}" y="0" width="${b.w}" height="${height}" fill="${color}" />`)
    .join('');

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalWidth} ${height}" width="100%" height="${height}" preserveAspectRatio="none" role="img" aria-label="Código de barras ${encoded.text}">${rects}</svg>`;
}
