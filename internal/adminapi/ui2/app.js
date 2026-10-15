// KMS 관리 화면 v2. 기존 화면과 같은 API만 호출한다(/api/session, /v1/*, /api/jobs, /api/audit,
// /api/dashboard/metrics, /api/bench/results/{id}). 서버 값은 항상 textContent로만 넣는다(XSS 방지).
(function () {
  'use strict';

  // ---- 작은 도우미 ----
  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') el.textContent = attrs[k];
      else if (k === 'class') el.className = attrs[k];
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), attrs[k]);
      else el.setAttribute(k, attrs[k]);
    });
    [].concat(children || []).forEach(function (c) {
      if (c == null) return;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function $(id) { return document.getElementById(id); }
  function fmtDate(s) {
    var d = new Date(s);
    if (!s || isNaN(d) || d.getFullYear() < 2000) return '—';
    return d.toLocaleString('ko-KR', { dateStyle: 'medium', timeStyle: 'short' });
  }
  function fmtPeriod(sec) {
    if (!sec) return '수동';
    if (sec % 86400 === 0) return sec / 86400 + '일';
    if (sec % 3600 === 0) return sec / 3600 + '시간';
    return sec + '초';
  }

  // ---- API (기존 console.html과 같은 방식: 쓰기 요청 전에 /api/session에서 CSRF 토큰을 받아 X-CSRF-Token으로 보낸다) ----
  var session = { role: '', csrf_token: '' };
  async function api(method, path, body) {
    var opts = { method: method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    if (method !== 'GET') {
      var s = await fetch('/api/session').then(function (r) { return r.json(); });
      opts.headers['X-CSRF-Token'] = s.csrf_token;
    }
    try {
      var res = await fetch(path, opts);
      var data = null, text = '';
      try { text = await res.text(); data = JSON.parse(text); } catch (e) { /* JSON이 아닌 본문 */ }
      return { ok: res.ok, status: res.status, data: data, text: text };
    } catch (e) {
      return { ok: false, status: 0, data: null, text: '' };
    }
  }
  // isAdmin()은 "쓰기 버튼을 보여도 되는가"다. 실제 역할이 admin이고 "뷰어로 보기"가 꺼져 있을 때만 true.
  // 뷰어로 보기는 화면만 바꾸는 미리보기라 서버 권한(Security.Wrap)은 그대로다.
  var viewAsViewer = false;
  try { viewAsViewer = sessionStorage.getItem('kms-view-as-viewer') === '1'; } catch (e) { /* 저장소 사용 불가 */ }
  function isAdmin() { return session.role === 'admin' && !viewAsViewer; }

  // ---- 봉인 상태 표시 (API 값은 그대로, 화면 문구만 바꾼다) ----
  var seal = null; // /v1/sys/seal-status 응답
  function sealView(st) {
    if (!st) return { cls: 'pill-muted', label: '상태 알 수 없음', sub: '봉인 상태를 가져오지 못했어요' };
    if (!st.sealed) return { cls: 'pill-ok', label: '● 사용 가능', sub: '봉인 해제됨 · 암복호화 처리 중' };
    return { cls: 'pill-warn', label: '○ 봉인됨', sub: '조각 3개를 입력하면 해제돼요' };
  }
  function renderTopbar() {
    var v = sealView(seal);
    var b = $('seal-badge');
    b.className = 'pill ' + v.cls;
    b.textContent = v.label;
    $('who').textContent = session.role ? (session.user ? session.user + ' · ' : '') + (session.role === 'admin' ? '관리자' : '뷰어') : '';
    var tg = $('role-toggle');
    tg.hidden = session.role !== 'admin';
    tg.textContent = viewAsViewer ? '뷰어로 보는 중 · 관리자로 돌아가기' : '관리자 ⇄ 뷰어로 보기';
    $('role-note').hidden = !viewAsViewer;
  }
  async function loadSeal() {
    var r = await api('GET', '/v1/sys/seal-status');
    seal = r.ok ? r.data : null;
    renderTopbar();
    return seal;
  }

  // ---- Prometheus (/api/dashboard/metrics?metric=requests) ----
  function promTotal(vec) { // 벡터 결과의 값 합계, code가 2xx가 아닌 것은 오류로 따로 센다
    var total = 0, err = 0;
    (vec.result || []).forEach(function (s) {
      var v = parseFloat(s.value[1]);
      if (isNaN(v)) return;
      total += v;
      if (String((s.metric || {}).code || '2').charAt(0) !== '2') err += v;
    });
    return { total: total, err: err };
  }
  function promSeries(matrix) { // 시계열별 값을 시각별로 합산
    var byT = {};
    (matrix.result || []).forEach(function (s) {
      s.values.forEach(function (p) {
        var v = parseFloat(p[1]);
        if (!isNaN(v)) byT[p[0]] = (byT[p[0]] || 0) + v;
      });
    });
    return Object.keys(byT).sort(function (a, b) { return a - b; }).map(function (t) { return [+t, byT[t]]; });
  }

  // ---- SVG 선 차트 ----
  function lineChart(points) {
    var W = 800, H = 220, L = 44, R = 12, T = 12, B = 24;
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('class', 'chart');
    function el(name, attrs, text) {
      var e = document.createElementNS(ns, name);
      Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
      if (text != null) e.textContent = text;
      svg.appendChild(e);
      return e;
    }
    var max = Math.max.apply(null, points.map(function (p) { return p[1]; }).concat([1]));
    var t0 = points[0][0], t1 = points[points.length - 1][0] || t0 + 1;
    function x(t) { return L + (t - t0) / ((t1 - t0) || 1) * (W - L - R); }
    function y(v) { return T + (1 - v / max) * (H - T - B); }
    [0, 0.5, 1].forEach(function (f) {
      var yy = y(max * f);
      el('line', { x1: L, x2: W - R, y1: yy, y2: yy, stroke: '#dfe3e8', 'stroke-width': 1 });
      el('text', { x: L - 6, y: yy + 4, 'text-anchor': 'end' }, (max * f).toFixed(max < 10 ? 1 : 0));
    });
    el('path', { d: points.map(function (p, i) { return (i ? 'L' : 'M') + x(p[0]).toFixed(1) + ' ' + y(p[1]).toFixed(1); }).join(' '),
      fill: 'none', stroke: '#1d4ed8', 'stroke-width': 2.5 });
    var tl = function (t) { return new Date(t * 1000).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }); };
    el('text', { x: L, y: H - 6 }, tl(t0));
    el('text', { x: W - R, y: H - 6, 'text-anchor': 'end' }, tl(t1));
    return svg;
  }

  // ---- 페이지: 대시보드 ----
  function card(k, v, s, cls) {
    return h('div', { class: 'card' }, [h('div', { class: 'k', text: k }), h('div', { class: 'v ' + (cls || ''), text: v }), h('div', { class: 's', text: s || '' })]);
  }
  // 페이지가 바뀌면 route()가 타이머를 모두 끈다(대시보드 10초 갱신, 성능 시험 3초 갱신).
  var timers = [], onVisible = null;
  function addTimer(fn, ms) { var id = setInterval(fn, ms); timers.push(id); return id; }
  function clearTimers() { timers.forEach(clearInterval); timers = []; onVisible = null; }
  document.addEventListener('visibilitychange', function () { if (!document.hidden && onVisible) onVisible(); });

  async function pageDashboard(view) {
    view.appendChild(h('h1', { text: '대시보드' }));
    view.appendChild(h('p', { class: 'page-sub', text: 'KMS의 현재 상태와 트래픽, 최근 성능 시험 결과 · 10초마다 자동 갱신' }));
    var cards = h('div', { class: 'cards' });
    var chartBody = h('div', { class: 'note', text: '불러오는 중…' });
    var chartBox = h('div', { class: 'panel' }, [h('h2', { text: '트래픽 (최근 15분, 초당 요청)' }), chartBody,
      h('div', { class: 'hint-small', text: 'Prometheus 수집 주기 때문에 10~30초 지연될 수 있어요.' })]);
    var benchBody = h('div', { class: 'note', text: '불러오는 중…' });
    var benchBox = h('div', { class: 'panel' }, [h('h2', { text: '최근 성능 시험' }), benchBody]);
    view.appendChild(cards); view.appendChild(chartBox); view.appendChild(benchBox);

    async function refresh() {
      var res = await Promise.all([loadSeal(), api('GET', '/v1/keys'), api('GET', '/api/dashboard/metrics?metric=requests'),
        api('GET', '/api/dashboard/metrics?metric=requests&range=1'), api('GET', '/api/jobs')]);
      var sv = sealView(seal), keysRes = res[1], reqNow = res[2], reqRange = res[3], jobs = res[4];

      clear(cards);
      var sealCard = card('봉인 상태', sv.label, sv.sub, seal && !seal.sealed ? 'ok' : 'warn');
      if (seal) sealCard.appendChild(h('div', { class: 'raw mono', text: 'sealed=' + seal.sealed + ' · seal_type=' + seal.seal_type + (seal.initialized !== undefined ? ' · initialized=' + seal.initialized : '') }));
      cards.appendChild(sealCard);
      var nkeys = keysRes.ok && keysRes.data && keysRes.data.keys ? keysRes.data.keys.length : null;
      cards.appendChild(card('키 수', nkeys === null ? '—' : String(nkeys), nkeys === null ? '봉인 중이거나 조회 불가' : '등록된 transit 키'));
      var t = reqNow.ok && reqNow.data ? promTotal(reqNow.data.data) : null;
      cards.appendChild(card('초당 요청', t ? t.total.toFixed(2) : '—', t ? '최근 5분 평균' : '메트릭 없음(N/A)'));
      cards.appendChild(card('오류율', t && t.total > 0 ? (t.err / t.total * 100).toFixed(1) + '%' : (t ? '0%' : '—'), t ? '2xx 외 응답 비율' : '메트릭 없음(N/A)'));

      var pts = reqRange.ok && reqRange.data ? promSeries(reqRange.data.data) : [];
      clear(chartBody); chartBody.className = '';
      if (pts.length > 1) chartBody.appendChild(lineChart(pts));
      else { chartBody.className = 'note'; chartBody.textContent = '표시할 시계열이 없어요 (Prometheus 연결 또는 요청 없음)'; }

      clear(benchBody); benchBody.className = '';
      if (!jobs.ok || !jobs.data || !jobs.data.length) {
        benchBody.className = 'note'; benchBody.textContent = '실행한 성능 시험이 없어요.';
      } else {
        var runs = jobs.data.slice().sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); }).slice(0, 5);
        var tb = h('table', {}, [h('thead', {}, h('tr', {}, ['시험', '실행 ID', '상태', '시작'].map(function (c) { return h('th', { text: c }); })))]);
        var body = h('tbody');
        runs.forEach(function (r) {
          body.appendChild(h('tr', {}, [h('td', { text: runLabel(r) }), h('td', {}, h('small', { class: 'mono muted', text: r.run_id.slice(0, 8) })),
            h('td', { text: STATE_KO[r.state] || r.state }), h('td', { text: fmtDate(r.created_at) })]));
        });
        tb.appendChild(body);
        benchBody.appendChild(h('div', { class: 'table-wrap' }, tb));
      }
    }
    await refresh();
    addTimer(function () { if (!document.hidden) refresh(); }, 10000);
    onVisible = refresh; // 숨겨졌다 다시 보이면 바로 한 번 갱신
  }

  // ---- 확인 모달 (브라우저 alert/confirm 대신 화면 안에서 확인) ----
  function confirmModal(title, message, okLabel, danger, typeWord) {
    return new Promise(function (resolve) {
      var prevFocus = document.activeElement;
      function done(v) { document.removeEventListener('keydown', onKey); back.remove(); if (prevFocus && prevFocus.focus) prevFocus.focus(); resolve(v); }
      function onKey(e) { if (e.key === 'Escape') done(false); }
      var ok = h('button', { class: 'btn' + (danger ? ' danger' : ''), text: okLabel || '확인', onclick: function () { done(true); } });
      var back = h('div', { class: 'modal-back', onclick: function (e) { if (e.target === back) done(false); } },
        h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' }, [
          h('h2', { text: title }), h('p', { text: message }),
          h('div', { class: 'modal-actions' }, [h('button', { class: 'btn ghost', text: '취소', onclick: function () { done(false); } }), ok])]));
      var typed = null;
      if (typeWord) { // 위험 동작: 지정한 단어를 직접 입력해야 확인 버튼이 켜진다
        ok.disabled = true;
        typed = h('input', { type: 'text', autocomplete: 'off', placeholder: typeWord, 'aria-label': '확인 문구 입력' });
        typed.addEventListener('input', function () { ok.disabled = typed.value.trim() !== typeWord; });
        back.firstChild.insertBefore(h('p', { class: 'muted', text: '계속하려면 "' + typeWord + '"를 입력하세요.' }), back.firstChild.lastChild);
        back.firstChild.insertBefore(typed, back.firstChild.lastChild);
      }
      document.body.appendChild(back);
      document.addEventListener('keydown', onKey);
      (typed || ok).focus();
    });
  }
  var STATUS_KO = { 401: '로그인이 필요해요', 403: '권한이 없어요', 404: '경로를 찾을 수 없어요', 409: '이미 존재해요', 413: '요청이 너무 커요',
    503: 'KMS가 봉인되었거나 일시적으로 사용할 수 없어요' };
  function serverMsg(r) { return ((r.data && r.data.error) || r.text || '').toString().trim().slice(0, 200); }
  // 한국어 설명 + (원래 코드와 서버 메시지는 뒤에 붙임)
  function errText(r) {
    if (!r.status) return '서버에 연결하지 못했어요';
    var detail = 'HTTP ' + r.status + (serverMsg(r) ? ' · ' + serverMsg(r) : '');
    return (STATUS_KO[r.status] || '요청에 실패했어요') + ' (' + detail + ')';
  }
  // 메시지 박스용: 한국어 설명은 보통 크기, 코드·서버 메시지는 작게
  function failMsg(prefix, r) {
    if (!r.status) return h('span', { text: prefix + errText(r) });
    return h('span', {}, [prefix + (STATUS_KO[r.status] || '요청에 실패했어요') + ' ',
      h('small', { class: 'err-detail', text: 'HTTP ' + r.status + (serverMsg(r) ? ' · ' + serverMsg(r) : '') })]);
  }
  function msgBox() { return h('div', { class: 'msg', hidden: 'hidden' }); }
  function showMsg(el, text, kind) { el.className = 'msg ' + (kind || ''); clear(el); if (text) el.appendChild(typeof text === 'string' ? document.createTextNode(text) : text); el.hidden = !text; }
  function field(label, input, hint) {
    return h('label', { class: 'field' }, [h('span', { class: 'lbl', text: label }), input, hint ? h('span', { class: 'hint', text: hint }) : null]);
  }
  // "90일 / 30일 / 안 함" 버튼 + 초 직접 입력 (기존 콘솔과 같은 값)
  function rotateField(input) {
    var presets = [['90일', 7776000], ['30일', 2592000], ['안 함', 0]].map(function (p) {
      return h('button', { type: 'button', class: 'btn ghost small', text: p[0], onclick: function () { input.value = p[1]; } });
    });
    return h('div', { class: 'field' }, [h('span', { class: 'lbl', text: '자동 회전 주기(초)' }), h('div', { class: 'row' }, [input].concat(presets)),
      h('span', { class: 'hint', text: '권장: 90일(7776000초). 비워 두면 수동 회전이에요.' })]);
  }
  function numInput(ph) { return h('input', { type: 'number', min: '0', placeholder: String(ph == null ? '' : ph) }); }

  // ---- 페이지: 키 목록 (+ 키 생성) ----
  async function pageKeys(view) {
    view.appendChild(h('h1', { text: '키' }));
    view.appendChild(h('p', { class: 'page-sub', text: '행을 클릭하면 상세 화면으로 이동해요' }));
    var box = h('div', { class: 'table-wrap' }, h('div', { class: 'empty', text: '불러오는 중…' }));
    if (isAdmin()) view.appendChild(createKeyPanel(function () { route(); }));
    view.appendChild(box);
    await loadSeal();
    var list = await api('GET', '/v1/keys');
    if (!list.ok || !list.data) {
      clear(box); box.appendChild(h('div', { class: 'empty', text: seal && seal.sealed ? '봉인 중이라 키 목록을 볼 수 없어요. 봉인 화면에서 먼저 해제하세요.' : '키 목록을 불러오지 못했어요' }));
      return;
    }
    var names = list.data.keys || [];
    if (!names.length) { clear(box); box.appendChild(h('div', { class: 'empty', text: '등록된 키가 없어요' })); return; }
    var metas = await Promise.all(names.map(function (n) { return api('GET', '/v1/keys/' + encodeURIComponent(n)); }));
    var tb = h('table', {}, h('thead', {}, h('tr', {}, ['이름', '최신 버전', '최소 복호화 버전', '자동 회전', '생성일'].map(function (c) { return h('th', { text: c }); }))));
    var body = h('tbody');
    metas.filter(function (r) { return r.ok && r.data; }).forEach(function (r) {
      var m = r.data;
      body.appendChild(h('tr', { class: 'click', onclick: function () { location.hash = '#/keys/' + encodeURIComponent(m.Name); } }, [
        h('td', { class: 'mono', text: m.Name }), h('td', { text: 'v' + m.LatestVersion }), h('td', { text: 'v' + m.MinDecryptionVersion }),
        h('td', { text: fmtPeriod(m.AutoRotatePeriodSec) }), h('td', { text: fmtDate(m.CreatedAt) })]));
    });
    tb.appendChild(body); clear(box); box.appendChild(tb);
  }

  function createKeyPanel(onDone) {
    var name = h('input', { type: 'text', placeholder: '예: campus-shipping', autocomplete: 'off' });
    var rot = numInput('');
    var msg = msgBox();
    var form = h('form', { class: 'panel' }, [h('h2', { text: '새 키 만들기' }),
      h('div', { class: 'form-grid' }, [field('키 이름', name), rotateField(rot)]),
      h('div', { class: 'row' }, [h('button', { type: 'submit', class: 'btn', text: '키 생성' })]), msg]);
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var n = name.value.trim();
      if (!n) { showMsg(msg, '키 이름을 입력하세요.', 'bad'); return; }
      var body = { name: n };
      if (rot.value !== '') body.auto_rotate_period_sec = parseInt(rot.value, 10);
      var r = await api('POST', '/v1/keys', body);
      if (!r.ok) { showMsg(msg, failMsg('키 생성 실패: ', r), 'bad'); return; }
      onDone();
    });
    return form;
  }

  // ---- 페이지: 키 상세 ----
  async function pageKeyDetail(view, name) {
    view.appendChild(h('p', {}, h('a', { href: '#/keys', text: '← 키 목록' })));
    var r = await api('GET', '/v1/keys/' + encodeURIComponent(name));
    if (!r.ok || !r.data) { view.appendChild(h('div', { class: 'note', text: '키를 불러오지 못했어요: ' + errText(r) })); return; }
    var m = r.data;
    view.appendChild(h('h1', { class: 'mono', text: m.Name }));
    view.appendChild(h('p', { class: 'page-sub', text: '종류: ' + m.Type + ' · 생성 ' + fmtDate(m.CreatedAt) + ' · 마지막 회전 ' + fmtDate(m.LastRotatedAt) }));
    view.appendChild(h('div', { class: 'cards three' }, [card('최신 버전', 'v' + m.LatestVersion, '새 암호화에 쓰는 버전'),
      card('최소 복호화 버전', 'v' + m.MinDecryptionVersion, '이 미만 버전은 복호화가 차단돼요'), card('자동 회전', fmtPeriod(m.AutoRotatePeriodSec), m.AutoRotatePeriodSec ? m.AutoRotatePeriodSec + '초마다' : '수동으로만 회전')]));

    var vt = h('table', {}, h('thead', {}, h('tr', {}, ['버전', '생성일', '상태'].map(function (c) { return h('th', { text: c }); }))));
    var vb = h('tbody');
    (m.Versions || []).slice().sort(function (a, b) { return b.Version - a.Version; }).forEach(function (v) {
      var blocked = v.Version < m.MinDecryptionVersion;
      var st = v.Version === m.LatestVersion ? h('span', { class: 'pill pill-ok', text: '최신' }) : blocked ? h('span', { class: 'pill pill-bad', text: '복호화 차단' }) : h('span', { class: 'pill pill-muted', text: '복호화 가능' });
      vb.appendChild(h('tr', {}, [h('td', { text: 'v' + v.Version }), h('td', { text: fmtDate(v.CreatedAt) }), h('td', {}, st)]));
    });
    vt.appendChild(vb);
    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '버전' }), h('div', { class: 'table-wrap' }, vt)]));

    if (!isAdmin()) { view.appendChild(h('div', { class: 'note', text: '조회 전용 계정이라 키를 바꿀 수 없어요.' })); return; }

    var msg = msgBox();
    var rotate = h('button', { class: 'btn', text: '회전', onclick: async function () {
      var ok = await confirmModal('키를 회전할까요?', '새 버전 v' + (m.LatestVersion + 1) + '이 만들어지고 이후 암호화는 새 버전을 써요. 기존 버전으로 암호화된 데이터는 최소 복호화 버전 이상이면 계속 복호화돼요.', '회전');
      if (!ok) return;
      var res = await api('POST', '/v1/keys/' + encodeURIComponent(name) + '/rotate', {});
      if (!res.ok) { showMsg(msg, failMsg('회전 실패: ', res), 'bad'); return; }
      route();
    } });
    var minIn = h('input', { type: 'number', min: '1', max: String(m.LatestVersion), placeholder: String(m.MinDecryptionVersion) });
    var rotIn = numInput(m.AutoRotatePeriodSec);
    var save = h('button', { class: 'btn', text: '설정 저장', onclick: async function () {
      var body = {};
      if (minIn.value !== '') body.min_decryption_version = parseInt(minIn.value, 10);
      if (rotIn.value !== '') body.auto_rotate_period_sec = parseInt(rotIn.value, 10);
      if (!Object.keys(body).length) { showMsg(msg, '변경할 값을 입력하세요.', 'bad'); return; }
      if (body.min_decryption_version > m.MinDecryptionVersion) {
        var ok = await confirmModal('이전 버전 복호화를 차단할까요?', 'v' + (body.min_decryption_version - 1) + ' 이하 버전으로 암호화된 데이터는 더 이상 복호화할 수 없어요. 먼저 재암호화(rewrap)를 끝냈는지 확인하세요.', '차단하고 저장', true);
        if (!ok) return;
      }
      var res = await api('POST', '/v1/keys/' + encodeURIComponent(name) + '/config', body);
      if (!res.ok) { showMsg(msg, failMsg('저장 실패: ', res), 'bad'); return; }
      route();
    } });
    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '관리' }),
      h('div', { class: 'row' }, [rotate, h('span', { class: 'muted', text: '수동으로 새 버전을 만들어요' })]),
      h('div', { class: 'form-grid top-gap' }, [field('최소 복호화 버전', minIn, '1 ~ ' + m.LatestVersion + ' (현재 v' + m.MinDecryptionVersion + ')'), rotateField(rotIn)]),
      h('div', { class: 'row' }, [save]), msg]));
  }

  // ---- 페이지: 봉인 ----
  // seal-profile API는 관리 소켓에 없다(internal/api/admin). seal_type 값으로 화면에서 정적 표를 보여 준다.
  // true/false는 예/아니요, null은 모르는 값(—), 문자열은 그대로 표시.
  var SEAL_PROFILES = {
    shamir: { name: 'Shamir (조각 입력)', humans: true, count: '3명 (5개 중)', spof: false, hw: false, auto: false },
    tpm: { name: 'TPM', humans: false, count: '0명', spof: null, hw: true, auto: '예 (향후 지원)' },
    k8s: { name: 'Kubernetes Secret', humans: false, count: '0명', spof: null, hw: false, auto: null },
    dev: { name: '개발용(dev)', humans: false, count: '0명', spof: null, hw: false, auto: null }
  };
  function profileCell(v) { return document.createTextNode(v === null ? '—' : v === true ? '예' : v === false ? '아니요' : String(v)); }

  async function pageSeal(view) {
    view.appendChild(h('h1', { text: '봉인' }));
    view.appendChild(h('p', { class: 'page-sub', text: '루트 키 보호 상태와 해제' }));
    await loadSeal();
    var v = sealView(seal);
    var top = h('div', { class: 'panel' }, [h('h2', { text: '상태' }), h('span', { class: 'pill ' + v.cls, text: v.label }), h('p', { class: 'muted', text: v.sub })]);
    if (seal) {
      var raw = Object.keys(seal).map(function (k) { return k + '=' + seal[k]; }).join(' · ');
      top.appendChild(h('div', { class: 'raw mono', text: raw }));
    }
    view.appendChild(top);

    if (seal && !seal.sealed && isAdmin()) {
      var smsg = msgBox();
      view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '봉인하기' }),
        h('p', { class: 'muted', text: '봉인하면 KMS가 잠기고 클러스터 Secret 읽기가 멈춥니다. 해제하려면 조각 3개가 필요합니다.' }),
        h('div', { class: 'row' }, h('button', { class: 'btn danger', text: '봉인하기', onclick: async function () {
          var ok = await confirmModal('KMS를 봉인할까요?', '봉인하면 KMS가 잠기고 클러스터 Secret 읽기가 멈춥니다. 해제하려면 조각 3개가 필요합니다.', '봉인', true, 'seal');
          if (!ok) return;
          var r = await api('POST', '/v1/sys/seal', {});
          if (!r.ok) { showMsg(smsg, failMsg('봉인 실패: ', r), 'bad'); return; }
          route();
        } })), smsg]));
    }

    if (seal && seal.sealed && isAdmin()) {
      var msg = msgBox();
      var panel = h('div', { class: 'panel' }, [h('h2', { text: '봉인 해제' })]);
      if (seal.seal_type === 'shamir') {
        var inp = h('input', { type: 'text', placeholder: '조각(share)을 붙여 넣으세요', autocomplete: 'off' });
        var f = h('form', { class: 'row' }, [inp, h('button', { class: 'btn', type: 'submit', text: '조각 제출' })]);
        f.addEventListener('submit', async function (e) {
          e.preventDefault();
          var share = inp.value.trim(); if (!share) return;
          var r = await api('POST', '/v1/sys/unseal', { share: share });
          if (!r.ok) { showMsg(msg, failMsg('조각 제출 실패: ', r), 'bad'); return; }
          route();
        });
        panel.appendChild(h('p', { class: 'muted', text: seal.progress ? '제출된 조각: ' + seal.progress : '조각 3개를 입력하면 해제돼요' }));
        panel.appendChild(f);
      } else {
        panel.appendChild(h('div', { class: 'row' }, h('button', { class: 'btn', text: '봉인 해제', onclick: async function () {
          var r = await api('POST', '/v1/sys/unseal', {});
          if (!r.ok) { showMsg(msg, failMsg('해제 실패: ', r), 'bad'); return; }
          route();
        } })));
      }
      panel.appendChild(msg);
      view.appendChild(panel);
    }

    var prof = h('div', { class: 'panel' }, [h('h2', { text: '현재 Seal 특성' })]);
    view.appendChild(prof);
    var d = seal && SEAL_PROFILES[seal.seal_type];
    if (!d) { prof.appendChild(h('div', { class: 'note', text: seal ? '알 수 없는 seal 종류(' + seal.seal_type + ')라 특성 표를 보여 줄 수 없어요.' : 'seal 종류를 알 수 없어요' })); return; }
    var rows = [['종류', d.name], ['사람 필요', d.humans], ['필요 인원', d.count], ['단일 장애점(SPOF)', d.spof], ['하드웨어 의존', d.hw], ['자동 해제', d.auto]];
    var tb = h('tbody');
    rows.forEach(function (x) { tb.appendChild(h('tr', {}, [h('th', { text: x[0] }), h('td', {}, profileCell(x[1]))])); });
    prof.appendChild(h('div', { class: 'table-wrap' }, h('table', { class: 'kv' }, tb)));
    prof.appendChild(h('div', { class: 'hint-small', text: '설계상 특성을 보여 주는 참고용 표예요(seal 종류 기준). —는 이 화면이 아직 정하지 않은 값이에요.' }));
  }

  // ---- 페이지: 성능 시험 ----
  var STATE_KO = { queued: '대기', running: '실행 중', cancelling: '취소 중', succeeded: '성공', failed: '실패', cancelled: '취소됨', timed_out: '시간 초과' };
  var ACTIVE = { queued: 1, running: 1, cancelling: 1 };
  function runLabel(x) { return x.spec.mode + ' · 동시성 ' + x.spec.concurrency + ' · ' + x.spec.count + '회'; }
  function benchStats(res) {
    var secs = (new Date(res.ended_at) - new Date(res.started_at)) / 1000;
    return { rps: secs > 0 ? res.requests / secs : null };
  }
  async function pageOps(view) {
    view.appendChild(h('h1', { text: '성능 시험' }));
    view.appendChild(h('p', { class: 'page-sub', text: '클러스터 안에서 시험 Job을 띄워 처리량과 지연을 측정합니다. 대시보드의 트래픽은 실제 요청을 관찰한 값입니다.' }));
    var msg = msgBox(), statusEl = h('span', { class: 'run-status' });
    var tracked = null, pollId = null; // tracked: 이 화면에서 시작한 실행의 ID
    function setStatus(spin, text) { clear(statusEl); if (spin) statusEl.appendChild(h('span', { class: 'spinner', 'aria-hidden': 'true' })); statusEl.appendChild(document.createTextNode(text)); }
    if (isAdmin()) {
      view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '새 시험' }), h('div', { class: 'row' }, [
        h('button', { class: 'btn', text: '100회 왕복 시험 시작', onclick: async function () {
          var ok = await confirmModal('시험을 시작할까요?', 'transit 모드로 암복호화를 100회 왕복해요. 클러스터에 시험 Job이 하나 만들어져요.', '시작');
          if (!ok) return;
          var r = await api('POST', '/api/jobs', { mode: 'transit', scenario: 'basic', op: 'roundtrip', count: 100, concurrency: 1, payload_bytes: 1024, duration_seconds: 0 });
          if (!r.ok) { showMsg(msg, failMsg('시작 실패: ', r), 'bad'); return; }
          showMsg(msg, '');
          tracked = r.data && r.data.run_id;
          setStatus(true, '실행 중…');
          load();
        } }), statusEl]), msg]));
    }
    var box = h('div', { class: 'table-wrap' }, h('div', { class: 'empty', text: '불러오는 중…' }));
    view.appendChild(box);

    async function load() {
      var jr = await api('GET', '/api/jobs');
      if (!jr.ok || !Array.isArray(jr.data)) { clear(box); box.appendChild(h('div', { class: 'empty', text: '작업 목록을 불러오지 못했어요: ' + errText(jr) })); return; }
      var runs = jr.data.slice().sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); });
      var results = await Promise.all(runs.map(function (x) { return x.upload === 'stored' ? api('GET', '/api/bench/results/' + encodeURIComponent(x.run_id)) : Promise.resolve(null); }));
      var active = false;
      runs.forEach(function (x, i) {
        var res = results[i] && results[i].ok ? results[i].data : null;
        if (ACTIVE[x.state] || (x.state === 'succeeded' && x.upload === 'pending')) active = true;
        if (x.run_id !== tracked) return;
        if (ACTIVE[x.state] || (x.state === 'succeeded' && !res && x.upload === 'pending')) setStatus(true, '실행 중…');
        else if (x.state === 'succeeded' && res) { var st = benchStats(res); setStatus(false, '완료 · 초당 ' + (st.rps === null ? '—' : st.rps.toFixed(1)) + '회'); }
        else setStatus(false, '실패');
      });
      clear(box);
      if (!runs.length) { box.appendChild(h('div', { class: 'empty', text: '실행한 시험이 없어요' })); }
      else {
        var heads = ['모드 · 동시성 · 횟수', '실행 ID', '상태', '시작', '초당 요청', 'p50', 'p99', '오류 수', ''];
        var tb = h('table', {}, h('thead', {}, h('tr', {}, heads.map(function (c) { return h('th', { text: c }); }))));
        var body = h('tbody');
        runs.forEach(function (x, i) {
          var res = results[i] && results[i].ok ? results[i].data : null, rps = '—', p50 = '—', p99 = '—', errs = '—';
          if (res) {
            var st = benchStats(res);
            rps = st.rps === null ? '—' : st.rps.toFixed(1);
            p50 = (res.p50_seconds * 1000).toFixed(1) + ' ms'; p99 = (res.p99_seconds * 1000).toFixed(1) + ' ms'; errs = String(res.errors);
          }
          var cancel = isAdmin() && (x.state === 'queued' || x.state === 'running') ? h('button', { class: 'btn ghost small', text: '취소', onclick: async function () {
            var ok = await confirmModal('시험을 취소할까요?', runLabel(x) + ' 실행을 중단해요.', '시험 취소', true);
            if (!ok) return;
            var r = await api('DELETE', '/api/jobs/' + encodeURIComponent(x.run_id));
            if (!r.ok) { showMsg(msg, failMsg('취소 실패: ', r), 'bad'); return; }
            load();
          } }) : null;
          body.appendChild(h('tr', {}, [h('td', { text: runLabel(x) }), h('td', {}, h('small', { class: 'mono muted', title: x.run_id, text: x.run_id.slice(0, 8) })),
            h('td', { text: STATE_KO[x.state] || x.state }), h('td', { text: fmtDate(x.created_at) }), h('td', { text: rps }), h('td', { text: p50 }), h('td', { text: p99 }),
            h('td', { text: errs }), h('td', {}, cancel)]));
        });
        tb.appendChild(body); box.appendChild(tb);
      }
      // 실행 중이면 3초마다 다시 불러오고, 끝나면 멈춘다
      if (active && !pollId) pollId = addTimer(load, 3000);
      if (!active && pollId) { clearInterval(pollId); pollId = null; }
    }
    await load();
  }

  // ---- 페이지: 감사 로그 ----
  async function pageAudit(view) {
    view.appendChild(h('h1', { text: '감사 로그' }));
    view.appendChild(h('p', { class: 'page-sub', text: '오늘 기록된 최근 요청' }));
    var box = h('div', { class: 'table-wrap' }, h('div', { class: 'empty', text: '불러오는 중…' }));
    view.appendChild(box);
    var r = await api('GET', '/api/audit');
    if (!r.ok) { clear(box); box.appendChild(h('div', { class: 'empty', text: '감사 로그를 불러오지 못했어요: ' + errText(r) })); return; }
    var ev = (r.data || []).slice().sort(function (a, b) { return new Date(b.utc) - new Date(a.utc); }).slice(0, 100);
    if (!ev.length) { clear(box); box.appendChild(h('div', { class: 'empty', text: '기록이 없어요' })); return; }
    var tb = h('table', {}, h('thead', {}, h('tr', {}, ['시각', '사용자', '동작', '허용', '결과', '요청 ID'].map(function (c) { return h('th', { text: c }); }))));
    var body = h('tbody');
    ev.forEach(function (e) {
      body.appendChild(h('tr', {}, [h('td', { text: fmtDate(e.utc) }), h('td', { text: e.subject }), h('td', { class: 'mono', text: e.action }),
        h('td', {}, h('span', { class: 'pill ' + (e.allowed ? 'pill-ok' : 'pill-bad'), text: e.allowed ? '허용' : '거부' })),
        h('td', {}, h('span', { class: 'pill ' + (e.success ? 'pill-ok' : 'pill-bad'), text: e.success ? '성공' : '실패' })), h('td', { class: 'mono', text: e.request_id })]));
    });
    tb.appendChild(body); clear(box); box.appendChild(tb);
  }

  // ---- 라우팅 (해시 기반: #/dashboard, #/keys, #/keys/<이름> ...) ----
  var pages = { dashboard: pageDashboard, keys: pageKeys, seal: pageSeal, ops: pageOps, audit: pageAudit };
  function route() {
    var parts = location.hash.replace(/^#\//, '').split('/');
    var page = pages[parts[0]] ? parts[0] : 'dashboard';
    document.querySelectorAll('#nav a').forEach(function (a) { a.classList.toggle('active', a.dataset.page === page); });
    clearTimers();
    var view = $('view'); clear(view);
    if (parts[0] === 'keys' && parts[1]) pageKeyDetail(view, decodeURIComponent(parts[1]));
    else pages[page](view);
  }

  async function init() {
    var s = await fetch('/api/session').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
    if (s) session = s;
    renderTopbar();
    $('role-toggle').addEventListener('click', function () {
      viewAsViewer = !viewAsViewer;
      try { sessionStorage.setItem('kms-view-as-viewer', viewAsViewer ? '1' : '0'); } catch (e) { /* 무시 */ }
      renderTopbar(); route();
    });
    window.addEventListener('hashchange', route);
    route();
  }
  init();
})();
