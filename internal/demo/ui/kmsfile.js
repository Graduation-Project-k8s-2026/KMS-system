// KMSF 파일 형식(pkg/kmsfile)의 브라우저 구현. WebCrypto(AES-GCM)로 청크마다 암복호화한다 — 원문은 이 브라우저를 떠나지 않는다.
// 형식: 헤더 "KMSF" | 버전(1) | 키 이름 길이(2) | 키 이름 | data key 암호문 길이(2) | 암호문 | 청크 크기(4) | 기본 nonce(12)
//       본문: 청크별 AES-256-GCM. nonce = 기본 nonce의 마지막 8바이트 XOR 청크 번호, AAD = SHA-256(헤더) | 청크 번호(8) | 마지막 여부(1)
// Go 구현(pkg/kmsfile)과 바이트 단위로 호환되어야 한다 (Go 테스트가 Node로 양방향 확인).
(function (root) {
  'use strict';
  var MAGIC = [0x4b, 0x4d, 0x53, 0x46], VERSION = 1, DEFAULT_CHUNK = 64 * 1024, MIN_CHUNK = 1024, MAX_CHUNK = 16 * 1024 * 1024, TAG = 16;
  var te = new TextEncoder(), td = new TextDecoder('utf-8', { fatal: true });

  function subtle() { return (root.crypto || globalThis.crypto).subtle; }
  function rand(n) { var b = new Uint8Array(n); (root.crypto || globalThis.crypto).getRandomValues(b); return b; }
  function concat(parts) {
    var n = parts.reduce(function (s, p) { return s + p.length; }, 0), out = new Uint8Array(n), o = 0;
    parts.forEach(function (p) { out.set(p, o); o += p.length; });
    return out;
  }
  function u16(n) { return new Uint8Array([(n >>> 8) & 255, n & 255]); }
  function u32(n) { return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }

  function buildHeader(keyName, dkCiphertext, chunkSize, nonce) {
    var kn = te.encode(keyName), ct = te.encode(dkCiphertext);
    if (!kn.length || kn.length > 255 || !ct.length || ct.length > 4096) throw new Error('헤더 값이 올바르지 않아요');
    return concat([new Uint8Array(MAGIC), new Uint8Array([VERSION]), u16(kn.length), kn, u16(ct.length), ct, u32(chunkSize), nonce]);
  }

  function chunkNonce(base, idx) {
    var n = new Uint8Array(base), hi = Math.floor(idx / 4294967296), lo = idx >>> 0;
    var dv = new DataView(n.buffer);
    dv.setUint32(4, (dv.getUint32(4) ^ hi) >>> 0);
    dv.setUint32(8, (dv.getUint32(8) ^ lo) >>> 0);
    return n;
  }
  function chunkAAD(hash, idx, last) {
    var aad = new Uint8Array(41);
    aad.set(hash, 0);
    var dv = new DataView(aad.buffer);
    dv.setUint32(32, Math.floor(idx / 4294967296));
    dv.setUint32(36, idx >>> 0);
    aad[40] = last ? 1 : 0;
    return aad;
  }
  async function importKey(dataKey, usage) {
    if (!(dataKey instanceof Uint8Array) || dataKey.length !== 32) throw new Error('data key는 32바이트여야 해요');
    return subtle().importKey('raw', dataKey, 'AES-GCM', false, [usage]);
  }
  async function readBytes(blob, start, end) { return new Uint8Array(await blob.slice(start, end).arrayBuffer()); }

  // encryptFile: blob(File) → KMSF Blob. dataKey는 다 쓰고 나서 0으로 지운다.
  async function encryptFile(blob, keyName, dkCiphertext, dataKey, onProgress) {
    var key;
    try { key = await importKey(dataKey, 'encrypt'); } finally { dataKey.fill(0); }
    var cs = DEFAULT_CHUNK, nonce = rand(12), header = buildHeader(keyName, dkCiphertext, cs, nonce);
    var hash = new Uint8Array(await subtle().digest('SHA-256', header));
    var n = Math.max(1, Math.ceil(blob.size / cs)), parts = [header];
    for (var i = 0; i < n; i++) {
      var plain = await readBytes(blob, i * cs, Math.min(blob.size, (i + 1) * cs));
      var ct = await subtle().encrypt({ name: 'AES-GCM', iv: chunkNonce(nonce, i), additionalData: chunkAAD(hash, i, i === n - 1), tagLength: 128 }, key, plain);
      parts.push(new Uint8Array(ct));
      if (onProgress && (i % 64 === 0 || i === n - 1)) onProgress((i + 1) / n);
    }
    return new Blob(parts, { type: 'application/octet-stream' });
  }

  // readHeader: 파일 앞부분에서 헤더를 읽는다. { keyName, dkCiphertext, chunkSize, nonce, raw }
  async function readHeader(blob) {
    var head = await readBytes(blob, 0, Math.min(blob.size, 4 + 1 + 2 + 255 + 2 + 4096 + 4 + 12));
    if (head.length < 5 || MAGIC.some(function (b, i) { return head[i] !== b; })) throw new Error('KMSF 파일이 아니에요');
    if (head[4] !== VERSION) throw new Error('지원하지 않는 파일 버전이에요');
    var p = 5;
    function need(n) { if (p + n > head.length) throw new Error('파일 헤더가 손상되었어요'); }
    need(2); var kl = (head[p] << 8) | head[p + 1]; p += 2;
    if (!kl || kl > 255) throw new Error('파일 헤더가 손상되었어요');
    need(kl); var keyName = td.decode(head.slice(p, p + kl)); p += kl;
    need(2); var cl = (head[p] << 8) | head[p + 1]; p += 2;
    if (!cl || cl > 4096) throw new Error('파일 헤더가 손상되었어요');
    need(cl); var ct = td.decode(head.slice(p, p + cl)); p += cl;
    need(4); var cs = ((head[p] << 24) | (head[p + 1] << 16) | (head[p + 2] << 8) | head[p + 3]) >>> 0; p += 4;
    if (cs < MIN_CHUNK || cs > MAX_CHUNK) throw new Error('파일 헤더가 손상되었어요');
    need(12); var nonce = head.slice(p, p + 12); p += 12;
    return { keyName: keyName, dkCiphertext: ct, chunkSize: cs, nonce: nonce, raw: head.slice(0, p) };
  }

  // decryptFile: 헤더가 읽힌 KMSF Blob → 평문 Blob. 인증 실패(변조·잘림·덧붙임·다른 키)는 예외.
  async function decryptFile(blob, header, dataKey, onProgress) {
    var key;
    try { key = await importKey(dataKey, 'decrypt'); } finally { dataKey.fill(0); }
    var hash = new Uint8Array(await subtle().digest('SHA-256', header.raw));
    var start = header.raw.length, body = blob.size - start, size = header.chunkSize + TAG;
    if (body < TAG) throw new Error('AUTH');
    var n = Math.ceil(body / size), parts = [];
    for (var i = 0; i < n; i++) {
      var ct = await readBytes(blob, start + i * size, Math.min(blob.size, start + (i + 1) * size));
      try {
        var pt = await subtle().decrypt({ name: 'AES-GCM', iv: chunkNonce(header.nonce, i), additionalData: chunkAAD(hash, i, i === n - 1), tagLength: 128 }, key, ct);
      } catch (e) { throw new Error('AUTH'); }
      parts.push(new Uint8Array(pt));
      if (onProgress && (i % 64 === 0 || i === n - 1)) onProgress((i + 1) / n);
    }
    return new Blob(parts, { type: 'application/octet-stream' });
  }

  var api = { encryptFile: encryptFile, readHeader: readHeader, decryptFile: decryptFile, DEFAULT_CHUNK: DEFAULT_CHUNK };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.KMSFile = api;
})(typeof window !== 'undefined' ? window : globalThis);
