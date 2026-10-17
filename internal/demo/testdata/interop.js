// 상호운용 시험용 Node 스크립트: node interop.js enc|dec <입력> <키 hex> <출력>
const fs = require('fs');
const K = require('../ui/kmsfile.js');
(async () => {
  const [mode, inPath, keyHex, outPath] = process.argv.slice(2);
  const key = Uint8Array.from(Buffer.from(keyHex, 'hex'));
  const blob = new Blob([fs.readFileSync(inPath)]);
  let out;
  if (mode === 'enc') out = await K.encryptFile(blob, 'team.k', 'kms:v1:fixture', key);
  else out = await K.decryptFile(blob, await K.readHeader(blob), key);
  fs.writeFileSync(outPath, Buffer.from(await out.arrayBuffer()));
})().catch((e) => { console.error(e.message); process.exit(1); });
