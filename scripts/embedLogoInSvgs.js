const fs = require('fs');
const path = require('path');

const logoPath = path.join(__dirname, '../public/logo.png');
const logoB64 = fs.readFileSync(logoPath).toString('base64');
const logoDataUri = `data:image/png;base64,${logoB64}`;

const files = [
  path.join(__dirname, '../public/svg/planillas/PLANILLA_EVALUACION_UX_FORENSE_FOLIO.svg'),
  path.join(__dirname, '../public/svg/planillas/MATRIZ_VALIDACION_HIPOTESIS_FORENSE_FOLIO.svg'),
  path.join(__dirname, '../public/svg/planillas/PLANILLA_INFORME_FORENSE_AUDIO_SONIC_FOLIO.svg'),
  path.join(__dirname, '../public/svg/planillas/PLANILLA_REGISTRO_CADENA_CUSTODIA_PRCC.svg')
];

files.forEach(filePath => {
  if (!fs.existsSync(filePath)) return;
  let content = fs.readFileSync(filePath, 'utf8');
  if (!content.includes('<image')) return;

  if (!content.includes('xmlns:xlink')) {
    content = content.replace('<svg ', '<svg xmlns:xlink="http://www.w3.org/1999/xlink" ');
  }
  
  const oldImageRegex = /<image [^>]*x="6" y="6" width="63" height="63"[^>]*\/>/g;
  const newImageTag = `<image href="${logoDataUri}" xlink:href="${logoDataUri}" x="6" y="6" width="63" height="63" preserveAspectRatio="xMidYMid meet" />`;
  
  if (oldImageRegex.test(content)) {
    content = content.replace(oldImageRegex, newImageTag);
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`✅ Logo embebido en base64 en: ${path.basename(filePath)}`);
  }
});
