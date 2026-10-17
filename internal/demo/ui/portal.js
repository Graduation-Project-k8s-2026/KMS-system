// KMS 사용자 포털. 서버 값은 textContent로만 넣는다(XSS 방지). 입력·결과는 저장하지 않고,
// 페이지를 떠날 때(pagehide) 지운다. 토큰은 서버가 붙이므로 브라우저는 토큰을 알지 못한다.
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { if (k === 'text') el.textContent = attrs[k]; else if (k === 'class') el.className = attrs[k]; else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), attrs[k]); else el.setAttribute(k, attrs[k]); });
    [].concat(kids || []).forEach(function (c) { if (c != null) el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return el;
  }
  var value = $('value'), keySel = $('key'), result = $('result');

  // ---- KMS 응답 → 한국어 (원래 코드는 작게 같이 표시) ----
  // 포털이 쓰는 서비스 계정(예: kms-demo/app-a → app-a). 상단에 상시 표시하지 않고 403 안내 안에만 넣는다.
  var saName = '';
  var STATUS_KO = { 400: '입력이 올바르지 않거나 허용된 키가 아니에요', 401: '서비스 계정 인증에 실패했어요',
    404: 'KMS에 이 키가 없어요', 409: '이 키는 사용 중지(또는 삭제 예약) 상태예요', 413: '입력이 너무 커요', 503: 'KMS가 봉인 중이거나 일시적으로 사용할 수 없어요' };
  function statusText(status) {
    if (status === 403) return '이 서비스 계정에는 이 키를 쓸 권한이 없어요' + (saName ? ' (현재 ' + saName + ' 권한)' : '');
    return STATUS_KO[status] || '요청에 실패했어요';
  }
  function errBox(status) {
    return h('div', { class: 'err', role: 'alert' }, [statusText(status), ' ', h('small', { text: 'HTTP ' + (status || '연결 실패') })]);
  }
  function show(node) { result.hidden = false; while (result.firstChild) result.removeChild(result.firstChild); result.appendChild(node); }
  function copyBtn(getText) {
    var b = h('button', { class: 'btn ghost small', type: 'button', text: '복사', onclick: function () {
      navigator.clipboard.writeText(getText()).then(function () { b.textContent = '복사됨'; setTimeout(function () { b.textContent = '복사'; }, 1500); });
    } });
    return b;
  }
  function ctVersion(ct) { var m = /^kms:v(\d+):/.exec(ct || ''); return m ? parseInt(m[1], 10) : null; }
  function utf8Len(s) { return new TextEncoder().encode(s).length; }
  function b64ToText(b64) {
    try { var bin = atob(b64), bytes = Uint8Array.from(bin, function (c) { return c.charCodeAt(0); }); return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch (e) { return null; } // 글자가 아닌 데이터면 Base64만 보여 준다
  }

  // ---- 호출 ----
  async function call(op, text) {
    try {
      var res = await fetch('/' + op, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-Request': '1' }, body: JSON.stringify({ key: keySel.value, value: text }) });
      if (!res.ok) return { ok: false, status: res.status };
      return { ok: true, value: (await res.json()).value };
    } catch (e) { return { ok: false, status: 0 }; }
  }

  var buttons = document.querySelectorAll('[data-op]');
  buttons.forEach(function (b) {
    b.addEventListener('click', async function () {
      var op = b.dataset.op, text = value.value;
      if (!text) { show(h('div', { class: 'err', text: '입력칸이 비어 있어요.' })); return; }
      buttons.forEach(function (x) { x.disabled = true; });
      var r = await call(op, text);
      buttons.forEach(function (x) { x.disabled = false; });
      if (!r.ok) { show(errBox(r.status)); return; }
      var key = h('span', { class: 'pill', text: keySel.value });
      if (op === 'encrypt') {
        var v = ctVersion(r.value), grow = r.value.length - utf8Len(text);
        show(h('div', {}, [h('h2', {}, ['암호화 결과 ', key]), h('div', { class: 'out', text: r.value }), h('div', { class: 'actions' }, copyBtn(function () { return r.value; })),
          h('div', { class: 'meta' }, [h('span', { text: '암호화에 쓴 키 버전: ' + (v === null ? '알 수 없음' : 'v' + v + ' (암호문 앞의 kms:v' + v + ':)') }),
            h('span', { text: '원문 ' + utf8Len(text) + ' B → 암호문 ' + r.value.length + ' B (' + (grow >= 0 ? '+' : '') + grow + ' B)' })]),
          h('p', { class: 'hint', text: '암호문은 버전 표시, 무작위 값, 인증 태그가 붙고 Base64로 바뀌어서 원문보다 길어져요. 이 암호문을 복호화 칸에 붙여 넣어 보세요.' })]));
      } else if (op === 'decrypt') {
        var plain = b64ToText(r.value), vv = ctVersion(text);
        show(h('div', {}, [h('h2', {}, ['복호화 결과 ', key]), h('div', { class: 'out', text: plain === null ? '(글자가 아닌 데이터예요. 아래 Base64를 보세요)' : plain }),
          h('div', { class: 'actions' }, copyBtn(function () { return plain === null ? r.value : plain; })),
          h('div', { class: 'meta' }, [h('span', { text: '이 암호문의 키 버전: ' + (vv === null ? '알 수 없음' : 'v' + vv) }), h('span', { text: 'Base64: ' + r.value })])]));
      } else {
        var from = ctVersion(text), to = ctVersion(r.value);
        show(h('div', {}, [h('h2', {}, ['새 버전으로 옮긴 암호문 ', key]), h('div', { class: 'out', text: r.value }), h('div', { class: 'actions' }, copyBtn(function () { return r.value; })),
          h('div', { class: 'meta' }, [h('span', { text: '키 버전: ' + (from === null ? '?' : 'v' + from) + ' → ' + (to === null ? '?' : 'v' + to) + (from !== null && from === to ? ' (이미 최신 버전이에요)' : '')}),
            h('span', { text: '원문은 화면에 나타나지 않았어요' })]),
          h('p', { class: 'hint', text: '옛 암호문 대신 이 새 암호문을 보관하세요. 관리자가 옛 버전을 차단하기 전에 옮겨 두면 안전해요.' })]));
      }
    });
  });
  function wipe() { value.value = ''; result.hidden = true; while (result.firstChild) result.removeChild(result.firstChild); }
  $('clear').addEventListener('click', wipe);
  window.addEventListener('pagehide', wipe);

  // ---- 탭 ----
  document.querySelectorAll('.tab').forEach(function (t) {
    t.addEventListener('click', function () {
      document.querySelectorAll('.tab').forEach(function (x) { var on = x === t; x.classList.toggle('on', on); x.setAttribute('aria-selected', on ? 'true' : 'false'); });
      $('tab-use').hidden = t.dataset.tab !== 'use'; $('tab-file').hidden = t.dataset.tab !== 'file'; $('tab-guide').hidden = t.dataset.tab !== 'guide';
    });
  });

  // ---- 사용 가이드 (토큰 자리는 <TOKEN> 자리표시자) ----
  function guide(key) {
    var k = key || 'my-key', box = $('guide');
    while (box.firstChild) box.removeChild(box.firstChild);
    function block(title, text) {
      box.appendChild(h('div', { class: 'guide-t', text: title }));
      box.appendChild(h('div', { class: 'code-block' }, [h('pre', { text: text }), copyBtn(function () { return text; })]));
    }
    var auth = '-H "Authorization: Bearer <TOKEN>"';
    block('1. 경로 (모두 POST, JSON)', 'POST /v1/encrypt/' + k + '   → 암호화\nPOST /v1/decrypt/' + k + '   → 복호화\nPOST /v1/rewrap/' + k + '    → 최신 버전으로 옮기기');
    block('2. 암호화 — 요청·응답 (plaintext는 Base64)', '요청: {"plaintext": "aGVsbG8="}\n응답: {"ciphertext": "kms:v2:AbCd…"}');
    block('3. 복호화 — 요청·응답', '요청: {"ciphertext": "kms:v2:AbCd…"}\n응답: {"plaintext": "aGVsbG8="}');
    block('4. rewrap — 요청·응답', '요청: {"ciphertext": "kms:v1:XyZ…"}\n응답: {"ciphertext": "kms:v2:EfGh…"}   (원문 노출 없음)');
    block('curl — 암호화', 'curl -s ' + auth + ' \\\n  -H "Content-Type: application/json" \\\n  -d \'{"plaintext":"aGVsbG8="}\' \\\n  <KMS_URL>/v1/encrypt/' + k);
    block('curl — 복호화', 'curl -s ' + auth + ' \\\n  -H "Content-Type: application/json" \\\n  -d \'{"ciphertext":"kms:v2:AbCd…"}\' \\\n  <KMS_URL>/v1/decrypt/' + k);
    block('curl — rewrap', 'curl -s ' + auth + ' \\\n  -H "Content-Type: application/json" \\\n  -d \'{"ciphertext":"kms:v1:XyZ…"}\' \\\n  <KMS_URL>/v1/rewrap/' + k);
    box.appendChild(h('p', { class: 'hint', text: '<TOKEN>은 앱의 서비스 계정 토큰(audience: kms-system)이에요. 권한이 없는 키를 쓰면 403이 와요. 오류 코드: 401 인증 실패, 403 권한 없음, 404 키 없음, 503 봉인/일시 장애.' }));
  }
  keySel.addEventListener('change', function () { guide(keySel.value); });

  // ---- 시작: 키 목록과 서비스 계정 이름 ----
  fetch('/api/config').then(function (r) { return r.json(); }).then(function (c) {
    saName = String(c.service_account || '').split('/').pop();
    (c.keys || []).forEach(function (k) { keySel.appendChild(h('option', { value: k, text: k })); $('fkey').appendChild(h('option', { value: k, text: k })); });
    guide(keySel.value);
  }).catch(function () { show(h('div', { class: 'err', text: '설정을 불러오지 못했어요' })); });

  // ---- 파일 암호화 (브라우저 안에서; 형식은 pkg/kmsfile과 호환) ----
  var MAX_FILE = 1024 * 1024 * 1024, fileEl = $('file'), fstatus = $('f-status'), fresult = $('f-result'), lastUrl = null;
  function fmsg(text, isErr) { fstatus.textContent = text; fstatus.className = isErr ? 'err' : 'meta'; }
  function fclear() { if (lastUrl) { URL.revokeObjectURL(lastUrl); lastUrl = null; } while (fresult.firstChild) fresult.removeChild(fresult.firstChild); fresult.hidden = true; }
  function offer(blob, name) {
    fclear(); lastUrl = URL.createObjectURL(blob);
    fresult.hidden = false;
    fresult.appendChild(h('a', { class: 'btn', href: lastUrl, download: name, text: '내려받기: ' + name }));
  }
  async function postJSON(path, body) {
    var res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-Request': '1' }, body: JSON.stringify(body) });
    if (!res.ok) { var e = new Error('HTTP'); e.status = res.status; throw e; }
    return res.json();
  }
  function b64ToBytes(b64) { return Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); }); }
  function pickFile() {
    var f = fileEl.files && fileEl.files[0];
    if (!f) { fmsg('파일을 먼저 고르세요.', true); return null; }
    if (f.size > MAX_FILE) { fmsg('파일이 너무 커요 (1 GiB 이하만 지원해요). 명령줄 도구 kms를 쓰세요.', true); return null; }
    return f;
  }
  async function fileOp(kind) {
    var f = pickFile(); if (!f) return;
    var btns = [$('f-enc'), $('f-dec')]; btns.forEach(function (b) { b.disabled = true; }); fclear();
    try {
      if (kind === 'enc') {
        fmsg('데이터 키를 받는 중…');
        var dk = await postJSON('/datakey', { key: $('fkey').value });
        fmsg('브라우저에서 암호화하는 중…');
        var blob = await KMSFile.encryptFile(f, $('fkey').value, dk.ciphertext, b64ToBytes(dk.plaintext), function (p) { fmsg('암호화 중… ' + Math.round(p * 100) + '%'); });
        dk = null;
        offer(blob, f.name + '.kmsf'); fmsg('암호화 완료 (' + blob.size + ' B). 원문은 서버로 보내지 않았어요.');
      } else {
        var hd = await KMSFile.readHeader(f);
        var opt = Array.prototype.some.call($('fkey').options, function (o) { return o.value === hd.keyName; });
        if (!opt) throw Object.assign(new Error('KEY'), { keyName: hd.keyName });
        fmsg('데이터 키를 복호화하는 중…');
        var r = await postJSON('/decrypt', { key: hd.keyName, value: hd.dkCiphertext });
        fmsg('브라우저에서 복호화하는 중…');
        var out = await KMSFile.decryptFile(f, hd, b64ToBytes(r.value), function (p) { fmsg('복호화 중… ' + Math.round(p * 100) + '%'); });
        offer(out, f.name.replace(/\.kmsf$/i, '') || 'decrypted'); fmsg('복호화 완료 (' + out.size + ' B).');
      }
    } catch (e) {
      if (e.status) fmsg(statusText(e.status) + ' (HTTP ' + e.status + ')', true);
      else if (e.message === 'AUTH') fmsg('파일이 변조되었거나 잘렸어요(인증 실패). 결과를 만들지 않았어요.', true);
      else if (e.message === 'KEY') fmsg('이 파일은 이 포털에서 쓸 수 없는 키(' + e.keyName + ')로 암호화되었어요.', true);
      else fmsg(e.message || '처리하지 못했어요', true);
    } finally { btns.forEach(function (b) { b.disabled = false; }); }
  }
  $('f-enc').addEventListener('click', function () { fileOp('enc'); });
  $('f-dec').addEventListener('click', function () { fileOp('dec'); });
  window.addEventListener('pagehide', function () { fclear(); fileEl.value = ''; });
})();
