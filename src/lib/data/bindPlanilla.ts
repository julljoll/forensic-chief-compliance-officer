/**
 * SHA256.US — Data Binder para Planillas Oficiales en Astro.
 * Regla Canónica: Las 13 planillas oficiales se muestran y se imprimen
 * únicamente en blanco sin rellenar para ser llenadas a mano.
 */

import type { CasoCMS } from '../domain/types';

export async function bindPlanilla(_planillaId: string): Promise<CasoCMS | undefined> {
  if (typeof window === 'undefined') return undefined;

  // Garantizar que todos los campos dinámicos permanezcan completamente en blanco sin rellenar
  const elements = document.querySelectorAll<HTMLElement>('[data-field]');
  elements.forEach((el) => {
    el.textContent = '';
  });

  return undefined;
}

