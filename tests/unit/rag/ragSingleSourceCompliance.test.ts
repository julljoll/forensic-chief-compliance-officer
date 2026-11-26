import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { RAG_INFORMATICA_CATALOG, RAG_INFORMATICA_BASE_DIR } from '../../../src/data/ragInformaticaCatalog';
import { NORMATIVAS_INICIALES } from '../../../src/lib/data/seed';
import { NORMATIVAS_ETAPAS } from '../../../src/data/normativasEtapas';
import { NORMATIVAS_RAG_MAPPING } from '../../../src/data/normativasMapping';
import { PLANILLAS_REGISTRY } from '../../../src/data/planillasRegistry';
import fasesIso from '../../../src/data/fases-iso.json';

describe('Verificación de Fuente Única RAG (RAG/Informacion_docling_rag/Informatica) y Arquitectura Astro', () => {
  const root = process.cwd();

  it('RAG-01: Todos los documentos de RAG_INFORMATICA_CATALOG y NORMATIVAS_INICIALES existen físicamente en RAG/Informacion_docling_rag/Informatica/', () => {
    expect(RAG_INFORMATICA_CATALOG.length).toBeGreaterThanOrEqual(25);
    expect(NORMATIVAS_INICIALES.length).toBe(RAG_INFORMATICA_CATALOG.length);

    for (const doc of RAG_INFORMATICA_CATALOG) {
      expect(doc.archivoRag.startsWith(`${RAG_INFORMATICA_BASE_DIR}/`)).toBe(true);
      expect(doc.hashPdfSha256).toMatch(/^[a-f0-9]{64}$/);
      const fullPath = path.resolve(root, doc.archivoRag);
      expect(fs.existsSync(fullPath), `Debe existir en disco: ${doc.archivoRag}`).toBe(true);
    }

    for (const norma of NORMATIVAS_INICIALES) {
      expect(norma.urlReferencia).toBeDefined();
      expect(norma.urlReferencia!.startsWith(`${RAG_INFORMATICA_BASE_DIR}/`)).toBe(true);
      expect(fs.existsSync(path.resolve(root, norma.urlReferencia!))).toBe(true);
    }
  });

  it('RAG-02: Cero referencias a carpetas fuera de Informatica/ en datos, mapeos, etapas y fases', () => {
    const dataFiles = [
      'src/data/ragInformaticaCatalog.ts',
      'src/lib/data/seed.ts',
      'src/data/normativasEtapas.ts',
      'src/data/normativasMapping.ts',
      'src/data/planillasRegistry.ts',
      'src/data/fases-iso.json',
    ];
    const forbiddenBranches = [
      'normativas_rag/',
      'Informacion_docling_rag/Penal/',
      'Informacion_docling_rag/Civil/',
      'Informacion_docling_rag/Constitucion/',
      'Informacion_docling_rag/Mercantil/',
      'Informacion_docling_rag/Tributario/',
      'Informacion_docling_rag/Jurisprudencias/',
    ];

    for (const rel of dataFiles) {
      const content = fs.readFileSync(path.resolve(root, rel), 'utf8');
      for (const bad of forbiddenBranches) {
        expect(content, `${rel} no debe referenciar ${bad}`).not.toContain(bad);
      }
    }

    for (const etapa of NORMATIVAS_ETAPAS) {
      expect(etapa.archivoRag.startsWith(`${RAG_INFORMATICA_BASE_DIR}/`)).toBe(true);
      expect(fs.existsSync(path.resolve(root, etapa.archivoRag))).toBe(true);
    }

    for (const group of Object.values(NORMATIVAS_RAG_MAPPING)) {
      for (const item of group.normativas) {
        expect(item.archivoRag.startsWith(`${RAG_INFORMATICA_BASE_DIR}/`)).toBe(true);
        expect(fs.existsSync(path.resolve(root, item.archivoRag))).toBe(true);
      }
    }
  });

  it('RAG-03: Cero citas o herramientas alucinadas en catálogos, exportadores y las 13 planillas Folio', () => {
    const hallucinatedPatterns = [
      'ISO/IEC 27701',
      'ISO/IEC 27041',
      'G.O. N° 37.076',
      'COPP Art. 186',
      'COPP Art. 153',
      'PhotoHolmes',
      'PyOgg',
    ];

    const filesToCheck = [
      'src/data/ragInformaticaCatalog.ts',
      'src/lib/data/seed.ts',
      'src/data/normativasEtapas.ts',
      'src/data/normativasMapping.ts',
      'src/data/planillasRegistry.ts',
      'src/data/fases-iso.json',
      'src/lib/export/exportGoogleDocs.ts',
      'src/lib/export/exportSvgEngine.ts',
      ...fs.readdirSync(path.resolve(root, 'src/components/planillas'))
        .filter((f) => f.endsWith('.astro'))
        .map((f) => `src/components/planillas/${f}`),
    ];

    for (const rel of filesToCheck) {
      const content = fs.readFileSync(path.resolve(root, rel), 'utf8');
      for (const bad of hallucinatedPatterns) {
        expect(content, `${rel} no debe contener cita/motor alucinado: ${bad}`).not.toContain(bad);
      }
    }

    for (const def of Object.values(PLANILLAS_REGISTRY)) {
      expect(def.archivosRag.length).toBeGreaterThan(0);
      for (const ar of def.archivosRag) {
        expect(ar.startsWith(`${RAG_INFORMATICA_BASE_DIR}/`)).toBe(true);
        expect(fs.existsSync(path.resolve(root, ar))).toBe(true);
      }
    }
  });

  it('RAG-04: Todos los controles de F0–F5 en fases-iso.json enlazan a un documento existente en Informatica/', () => {
    expect(fasesIso.fases.length).toBe(6);
    for (const fase of fasesIso.fases) {
      for (const ctrl of fase.controles as Array<{ id: string; fuenteRag?: string; detalleRag?: string }>) {
        expect(ctrl.fuenteRag, `Control ${ctrl.id} debe definir fuenteRag`).toBeTruthy();
        expect(ctrl.fuenteRag!.startsWith(`${RAG_INFORMATICA_BASE_DIR}/`)).toBe(true);
        expect(fs.existsSync(path.resolve(root, ctrl.fuenteRag!)), `Debe existir ${ctrl.fuenteRag}`).toBe(true);
        expect(ctrl.detalleRag && ctrl.detalleRag.length > 15, `Control ${ctrl.id} debe tener detalleRag`).toBe(true);
      }
    }
  });

  it('RAG-05: Arquitectura Astro nativa + USWDS con Progressive Disclosure en vistas principales', () => {
    const astroViews = fs.readdirSync(path.resolve(root, 'src/components/views'));
    for (const v of astroViews) {
      expect(v.endsWith('.astro')).toBe(true);
    }

    const uswdsComponents = fs.readdirSync(path.resolve(root, 'src/components/uswds'));
    expect(uswdsComponents).toContain('Accordion.astro');
    expect(uswdsComponents).toContain('StatusDot.astro');
    expect(uswdsComponents).toContain('RagSourceBadge.astro');
    expect(uswdsComponents).toContain('StepIndicator.astro');

    const dashboard = fs.readFileSync(path.resolve(root, 'src/components/views/DashboardView.astro'), 'utf8');
    expect(dashboard).toContain('<Accordion');
    expect(dashboard).toContain('<StatusDot');
    expect(dashboard).toContain('RAG/Informacion_docling_rag/Informatica');

    const flujo = fs.readFileSync(path.resolve(root, 'src/components/views/FlujoIsoView.astro'), 'utf8');
    expect(flujo).toContain('<Accordion');
    expect(flujo).toContain('<RagSourceBadge');
    expect(flujo).toContain('PASO 1 DE 3');
    expect(flujo).toContain('PASO 2 DE 3');
    expect(flujo).toContain('PASO 3 DE 3');

    const astroConfig = fs.readFileSync(path.resolve(root, 'astro.config.mjs'), 'utf8');
    expect(astroConfig).not.toContain('**/pdf/**');
  });
});
