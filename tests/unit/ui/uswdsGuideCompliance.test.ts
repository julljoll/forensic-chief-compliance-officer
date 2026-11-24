import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('Cumplimiento Visual USWDS (DC3 Federal Theme) y Guía Operativa Pericial', () => {
  const viewsDir = path.resolve(process.cwd(), 'src/components/views');

  it('USWDS-01: Todas las vistas operativas del CMS utilizan el encabezado unificado PageHeader.astro', () => {
    const operationalViews = [
      'DashboardView.astro',
      'CasosView.astro',
      'FlujoIsoView.astro',
      'CustodiaView.astro',
      'PlanillasCatalogoView.astro',
      'NormativaRagView.astro',
      'AuditoriaView.astro',
      'ExportarView.astro',
      'SeguridadTotpView.astro',
    ];

    for (const view of operationalViews) {
      const content = fs.readFileSync(path.resolve(viewsDir, view), 'utf8');
      expect(content, `${view} debe importar y renderizar <PageHeader`).toContain('<PageHeader');
    }
  });

  it('USWDS-02: FlujoIsoView incluye la Guía Operativa SOP (.usa-process-list) para las 6 fases (F0 a F5)', () => {
    const flujo = fs.readFileSync(path.resolve(viewsDir, 'FlujoIsoView.astro'), 'utf8');
    expect(flujo).toContain('SOP_GUIDE_MAP');
    expect(flujo).toContain('usa-process-list');
    expect(flujo).toContain('Guía Operativa de Ejecución Pericial');
    for (const fase of ['F0', 'F1', 'F2', 'F3', 'F4', 'F5']) {
      expect(flujo).toContain(`${fase}: [`);
    }
  });

  it('USWDS-03: StepIndicator.astro soporta navegación reactiva por fase (data-step-fase)', () => {
    const stepInd = fs.readFileSync(
      path.resolve(process.cwd(), 'src/components/uswds/StepIndicator.astro'),
      'utf8'
    );
    expect(stepInd).toContain('usa-step-indicator');
    expect(stepInd).toContain('data-step-fase=');
    expect(stepInd).toContain('id="step-indicator-num"');
    expect(stepInd).toContain('id="step-indicator-title"');
  });

  it('USWDS-04: NuevoCasoModal guía el registro por consignación de móviles y medios digitales', () => {
    const modal = fs.readFileSync(
      path.resolve(process.cwd(), 'src/components/casos/NuevoCasoModal.astro'),
      'utf8'
    );
    expect(modal).toContain('Teléfono Inteligente (Smartphone)');
    expect(modal).toContain('Disco Duro / SSD / Memoria USB');
    expect(modal).toContain('Computadora / Laptop');
    expect(modal).toContain('Servidor / Unidad NAS');
    expect(modal).toContain('Cámara de Seguridad (DVR / NVR / CCTV)');
    expect(modal).toContain('Reloj Inteligente (Smartwatch / Wearable)');
    expect(modal).toContain('Medio Óptico (CD / DVD)');
  });
});
