import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('Verificación de Cumplimiento Legal y Estructural de Planillas (Etapa 4)', () => {
  it('LEG-01: ActaEntrevista cita CP Arts. 243 y 246 (falso testimonio en causa penal)', () => {
    const filePath = path.resolve(process.cwd(), 'src/components/planillas/ActaEntrevista.astro');
    const content = fs.readFileSync(filePath, 'utf8');
    expect(content).toContain('CP ARTS. 243 Y 246');
    expect(content).toContain('Arts. 243 y 246 del Código Penal');
    expect(content).not.toContain('242');
  });

  it('LEG-02: Verificación MATCH de Hash cita ISO/IEC 27037 §5.4.4 / §7.1.3', () => {
    const consent = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/ActaConsentimiento.astro'), 'utf8');
    const desprec = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/ActaDesprecintado.astro'), 'utf8');
    const dictamen = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/ActaDictamen.astro'), 'utf8');
    const fasesJson = fs.readFileSync(path.resolve(process.cwd(), 'src/data/fases-iso.json'), 'utf8');

    expect(consent).toContain('§5.4.4 / §7.1.3');
    expect(desprec).toContain('§5.4.4 / §7.1.3');
    expect(dictamen).toContain('§5.4.4 / §7.1.3');
    expect(fasesJson).toContain('§5.4.4 / §7.1.3');
  });

  it('LEG-03: ActaObtencion cita ISO/IEC 27037 §5.4.2 / §5.4.3', () => {
    const obtencion = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/ActaObtencion.astro'), 'utf8');
    expect(obtencion).toContain('ISO/IEC 27037 §5.4.2 / §5.4.3');
  });

  it('EST-01: Actuaciones entre peritos de laboratorio usan leftRole="perito" en PlanillaFirmasBilaterales', () => {
    const dualExpertFiles = [
      'src/components/planillas/ActaDesprecintado.astro',
      'src/components/planillas/PlanillaAudioSonic.astro',
      'src/components/planillas/PlanillaEvaluacionUX.astro',
      'src/components/planillas/ActaDictamen.astro',
      'src/components/planillas/DictamenImagenes.astro',
      'src/components/planillas/DictamenAudios.astro',
      'src/components/planillas/ActaSanitizacion.astro',
      'src/components/planillas/ActaAuditoriaTimeline.astro',
    ];

    for (const file of dualExpertFiles) {
      const content = fs.readFileSync(path.resolve(process.cwd(), file), 'utf8');
      expect(content, `File ${file} should have leftRole="perito"`).toContain('leftRole="perito"');
    }
  });

  it('EST-02: PlanillaPRCC incluye campos de traspasos conforme a MUCC-2017', () => {
    const prcc = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/PlanillaPRCC.astro'), 'utf8');
    expect(prcc).toContain('N° Oficio / Memorando');
    expect(prcc).toContain('Despacho / Fiscalía');
    expect(prcc).toContain('Cred./CIV');
    expect(prcc).toContain('Precinto (N° y Condición)');
  });

  it('EST-03: ActaObtencion incluye verificación de aislamiento de redes (Modo Avión + Faraday)', () => {
    const obtencion = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/ActaObtencion.astro'), 'utf8');
    expect(obtencion).toContain('Modo Avión Activado');
    expect(obtencion).toContain('Bolsa Faraday N°');
    expect(obtencion).toContain('Bloqueo WiFi / BT / Celular / NFC');
  });

  it('EST-04: ActaEntregaResultados contiene las 4 opciones normativas de Disposición Final', () => {
    const entrega = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/ActaEntregaResultados.astro'), 'utf8');
    expect(entrega).toContain('Devolución formal al Titular o Interlocutor Legítimo');
    expect(entrega).toContain('Remisión a Sede Fiscal o Tribunal de Control');
    expect(entrega).toContain('Depósito en Bóveda de Resguardo');
    expect(entrega).toContain('Destrucción / Desincorporación Autorizada');
  });

  it('EST-05: Dictámenes de Imágenes y Audios cumplen con COPP Art. 225 Num 1, 2 y 3', () => {
    const img = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/DictamenImagenes.astro'), 'utf8');
    const aud = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/DictamenAudios.astro'), 'utf8');

    expect(img).toContain('COPP ART. 225 NUM. 1');
    expect(img).toContain('COPP ART. 225 NUM. 2');
    expect(img).toContain('COPP ART. 225 NUM. 3');

    expect(aud).toContain('COPP ART. 225 NUM. 1');
    expect(aud).toContain('COPP ART. 225 NUM. 2');
    expect(aud).toContain('COPP ART. 225 NUM. 3');
  });

  it('Dactiloscopía: PULGAR IZQ. antecede a PULGAR DER. anatómicamente', () => {
    const firmas = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/PlanillaFirmasBilaterales.astro'), 'utf8');
    const posIzq = firmas.indexOf('PULGAR IZQ.');
    const posDer = firmas.indexOf('PULGAR DER.');
    expect(posIzq).toBeGreaterThan(-1);
    expect(posDer).toBeGreaterThan(-1);
    expect(posIzq).toBeLessThan(posDer);
  });

  it('FED-01: Todas las 13 planillas verifican el procedimiento por consignación multimedio y móvil con bloque federal e hidratación data-default', () => {
    const header = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/PlanillaHeader.astro'), 'utf8');
    expect(header).toContain('PROCEDURE:');
    expect(header).toContain('CONSIGNACIÓN (MUCC-2017)');
    expect(header).toContain('FORM CODE:');
    expect(header).toContain('JURISDICTION:');

    const consent = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas/ActaConsentimiento.astro'), 'utf8');
    expect(consent).toContain('Móvil / Smartphone');
    expect(consent).toContain('Disco Duro');
    expect(consent).toContain('CD / DVD');
    expect(consent).toContain('Reloj / Wearable');
    expect(consent).toContain('Cámara DVR / CCTV');
    expect(consent).toContain('Imágenes / Fotos');
    expect(consent).toContain('Redes Sociales / Mensajería');
    expect(consent).toContain('Notas de Voz / Audios');
    expect(consent).toContain('Capturas de Pantalla');

    const allPlanillas = [
      'ActaConsentimiento.astro',
      'ActaEntrevista.astro',
      'ActaObtencion.astro',
      'PlanillaPRCC.astro',
      'ActaDesprecintado.astro',
      'PlanillaAudioSonic.astro',
      'PlanillaEvaluacionUX.astro',
      'ActaDictamen.astro',
      'DictamenImagenes.astro',
      'DictamenAudios.astro',
      'ActaEntregaResultados.astro',
      'ActaSanitizacion.astro',
      'ActaAuditoriaTimeline.astro',
    ];

    for (const file of allPlanillas) {
      const content = fs.readFileSync(path.resolve(process.cwd(), 'src/components/planillas', file), 'utf8');
      expect(content, `${file} debe incluir atributos data-default para Modo Datos`).toContain('data-default=');
    }
  });
});

