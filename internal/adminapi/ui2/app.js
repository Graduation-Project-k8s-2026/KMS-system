// KMS 관리 화면 v2 — 공통 도구. 기존 화면과 같은 API만 호출한다
// (/api/session, /v1/*, /api/jobs, /api/audit, /api/dashboard/metrics, /api/bench/results/{id}, /api/info, /api/console-users).
// 서버 값은 항상 textContent로만 넣는다(XSS 방지). 페이지 파일들은 window.KMS를 통해 이 도구를 쓴다.
(function () {
  'use strict';
  var K = window.KMS = { pages: {}, session: { role: '', user: '', csrf_token: '' }, seal: null, flash: '', token: 0 };

  // ---- DOM 도우미 ----
  var h = K.h = function (tag, attrs, children) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') el.textContent = attrs[k];
      else if (k === 'class') el.className = attrs[k];
      else if (k === 'value') el.value = attrs[k];
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), attrs[k]);
      else el.setAttribute(k, attrs[k]);
    });
    [].concat(children || []).forEach(function (c) {
      if (c == null) return;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return el;
  };
  var clear = K.clear = function (el) { while (el.firstChild) el.removeChild(el.firstChild); };
  K.$ = function (id) { return document.getElementById(id); };
  K.th = function (cols) { return h('thead', {}, h('tr', {}, cols.map(function (c) { return typeof c === 'string' ? h('th', { text: c }) : c; }))); };
  K.tableWrap = function (table) { return h('div', { class: 'table-wrap' }, table); };
  K.note = function (text) { return h('div', { class: 'note', text: text }); };
  K.pageHead = function (view, title, sub) {
    view.appendChild(h('h1', { text: title }));
    if (sub) view.appendChild(h('p', { class: 'page-sub', text: sub }));
  };

  // ---- 키 상태 배지 (active / disabled / pending_deletion) ----
  K.keyState = function (m) { return (m && m.state) || 'active'; };
  K.stateBadge = function (m) {
    var st = K.keyState(m);
    if (st === 'disabled') return h('span', { class: 'pill pill-muted', text: '사용 중지' });
    if (st === 'pending_deletion') {
      var d = K.validDate(m.deletion_date);
      return h('span', { class: 'pill pill-bad', text: '삭제 예정' + (d ? ' ' + d.toLocaleDateString('ko-KR') : '') });
    }
    return h('span', { class: 'pill pill-ok', text: '사용 중' });
  };
  // 보호 키 목록(/api/info의 protected_keys). 화면은 버튼을 미리 막을 뿐이고 최종 판단은 KMS(409 key_protected)다.
  K.protectedKeys = async function () {
    var r = await K.api('GET', '/api/info');
    return r.ok && r.data && Array.isArray(r.data.protected_keys) ? r.data.protected_keys : [];
  };

  // ---- 서식 ----
  K.validDate = function (s) { var d = new Date(s); return s && !isNaN(d) && d.getFullYear() >= 2000 ? d : null; };
  K.fmtDate = function (s) {
    var d = K.validDate(s);
    return d ? d.toLocaleString('ko-KR', { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  };
  K.fmtDateSec = function (s) {
    var d = K.validDate(s);
    return d ? d.toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'medium' }) : '—';
  };
  K.daysAgo = function (s) { var d = K.validDate(s); return d ? Math.floor((Date.now() - d.getTime()) / 86400000) : null; };
  K.fmtPeriod = function (sec) {
    if (!sec) return '수동';
    if (sec % 86400 === 0) return sec / 86400 + '일';
    if (sec % 3600 === 0) return sec / 3600 + '시간';
    return sec + '초';
  };
  K.digest12 = function (img) { var m = /@sha256:([a-f0-9]+)/.exec(img || ''); return m ? m[1].slice(0, 12) : '—'; };
  K.fmtDur = function (sec) { return sec == null ? '—' : sec < 60 ? sec.toFixed(1) + '초' : Math.floor(sec / 60) + '분 ' + Math.round(sec % 60) + '초'; };

  // ---- API (기존 console.html과 같은 방식: 쓰기 요청 전에 /api/session에서 CSRF 토큰을 받아 X-CSRF-Token으로 보낸다) ----
  K.api = async function (method, path, body) {
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
  };

  // ---- 역할: 실제 역할 + "뷰어로 보기" 미리보기 ----
  // writable()은 "쓰기 버튼을 켜도 되는가"다. 실제 역할이 admin이고 뷰어로 보기가 꺼져 있을 때만 true.
  // 뷰어로 보기는 화면만 바꾼다. 서버 권한(Security.Wrap)은 그대로다.
  var viewAsViewer = false;
  try { viewAsViewer = sessionStorage.getItem('kms-view-as-viewer') === '1'; } catch (e) { /* 저장소 사용 불가 */ }
  K.writable = function () { return K.session.role === 'admin' && !viewAsViewer; };
  K.setViewAsViewer = function (v) {
    viewAsViewer = v;
    try { sessionStorage.setItem('kms-view-as-viewer', v ? '1' : '0'); } catch (e) { /* 무시 */ }
    K.renderTopbar(); K.route();
  };
  // 쓰기 컨트롤은 숨기지 않고 회색으로 잠근다(hover하면 이유 안내). fieldset[disabled]가 안의 입력·버튼을 모두 끈다.
  K.lock = function (node) {
    if (K.writable()) return node;
    return h('fieldset', { class: 'locked', disabled: 'disabled', title: '관리자 권한이 필요해요' }, node);
  };

  // ---- 봉인 상태 표시 (API 값은 그대로, 화면 문구만 바꾼다) ----
  K.sealView = function (st) {
    if (!st) return { cls: 'pill-muted', label: '상태 알 수 없음', sub: '봉인 상태를 가져오지 못했어요' };
    if (!st.sealed) return { cls: 'pill-ok', label: '● 사용 가능', sub: '봉인 해제됨 · 암복호화 처리 중' };
    return { cls: 'pill-warn', label: '○ 봉인됨', sub: '조각 3개를 입력하면 해제돼요' };
  };
  K.renderTopbar = function () {
    var v = K.sealView(K.seal), b = K.$('seal-badge');
    b.className = 'pill ' + v.cls; b.textContent = v.label;
    var s = K.session;
    K.$('who').textContent = s.role ? (s.user ? s.user + ' · ' : '') + (s.role === 'admin' ? '관리자' : '뷰어') : '';
    var seg = K.$('role-seg'); clear(seg);
    if (s.role) {
      var realAdmin = s.role === 'admin';
      [['admin', '관리자'], ['viewer', '뷰어']].forEach(function (o) {
        var active = o[0] === 'admin' ? K.writable() : !K.writable();
        var btn = h('button', { type: 'button', class: 'seg-btn' + (active ? ' on' : ''), text: o[1], 'aria-pressed': active ? 'true' : 'false',
          onclick: function () { if (realAdmin) K.setViewAsViewer(o[0] === 'viewer'); } });
        if (!realAdmin && o[0] === 'admin') { btn.disabled = true; btn.title = '이 계정은 뷰어 권한이에요'; }
        seg.appendChild(btn);
      });
    }
    var ro = K.$('ro-banner');
    ro.hidden = K.writable() || !s.role;
    ro.textContent = '조회 전용' + (s.role === 'admin' ? ' · 화면 미리보기예요. 서버 권한은 그대로예요.' : ' · 이 계정은 읽기만 할 수 있어요.');
  };
  K.loadSeal = async function () {
    var r = await K.api('GET', '/v1/sys/seal-status');
    K.seal = r.ok ? r.data : null;
    K.renderTopbar();
    return K.seal;
  };

  // ---- 오류 문구: 상태 코드별 한국어 설명 + (원래 코드·서버 메시지는 작게) ----
  var STATUS_KO = { 401: '로그인이 필요해요', 403: '권한이 없어요', 404: '경로를 찾을 수 없어요', 409: '현재 상태에서는 할 수 없어요', 413: '요청이 너무 커요',
    503: 'KMS가 봉인되었거나 일시적으로 사용할 수 없어요' };
  function serverMsg(r) { return ((r.data && (r.data.message || r.data.error)) || r.text || '').toString().trim().slice(0, 200); }
  var errText = K.errText = function (r) {
    if (!r.status) return '서버에 연결하지 못했어요';
    return (STATUS_KO[r.status] || '요청에 실패했어요') + ' (HTTP ' + r.status + (serverMsg(r) ? ' · ' + serverMsg(r) : '') + ')';
  };
  K.failMsg = function (prefix, r) {
    if (!r.status) return h('span', { text: prefix + errText(r) });
    return h('span', {}, [prefix + (STATUS_KO[r.status] || '요청에 실패했어요') + ' ',
      h('small', { class: 'err-detail', text: 'HTTP ' + r.status + (serverMsg(r) ? ' · ' + serverMsg(r) : '') })]);
  };
  K.msgBox = function () { return h('div', { class: 'msg', hidden: 'hidden' }); };
  K.showMsg = function (el, text, kind) {
    el.className = 'msg ' + (kind || ''); clear(el);
    if (text) el.appendChild(typeof text === 'string' ? document.createTextNode(text) : text);
    el.hidden = !text;
  };

  // ---- 확인 모달 (브라우저 alert/confirm 대신 화면 안에서 확인) ----
  K.confirm = function (title, message, okLabel, danger, typeWord) {
    return new Promise(function (resolve) {
      var prevFocus = document.activeElement;
      function done(v) { document.removeEventListener('keydown', onKey); back.remove(); if (prevFocus && prevFocus.focus) prevFocus.focus(); resolve(v); }
      function onKey(e) { if (e.key === 'Escape') done(false); }
      var ok = h('button', { class: 'btn' + (danger ? ' danger' : ''), text: okLabel || '확인', onclick: function () { done(true); } });
      var box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' }, [h('h2', { text: title })]);
      [].concat(message).forEach(function (m) { box.appendChild(h('p', { text: m })); });
      var typed = null;
      if (typeWord) { // 위험 동작: 지정한 단어를 직접 입력해야 확인 버튼이 켜진다
        ok.disabled = true;
        typed = h('input', { type: 'text', autocomplete: 'off', placeholder: typeWord, 'aria-label': '확인 문구 입력' });
        typed.addEventListener('input', function () { ok.disabled = typed.value.trim() !== typeWord; });
        box.appendChild(h('p', { class: 'muted', text: '계속하려면 "' + typeWord + '"를 입력하세요.' }));
        box.appendChild(typed);
      }
      box.appendChild(h('div', { class: 'modal-actions' }, [h('button', { class: 'btn ghost', text: '취소', onclick: function () { done(false); } }), ok]));
      var back = h('div', { class: 'modal-back', onclick: function (e) { if (e.target === back) done(false); } }, box);
      document.body.appendChild(back);
      document.addEventListener('keydown', onKey);
      (typed || ok).focus();
    });
  };

  // ---- 폼 도우미 ----
  K.field = function (label, input, hint) {
    return h('label', { class: 'field' }, [h('span', { class: 'lbl', text: label }), input, hint ? h('span', { class: 'hint', text: hint }) : null]);
  };
  K.numInput = function (ph, min, max) {
    var a = { type: 'number', placeholder: String(ph == null ? '' : ph) };
    if (min != null) a.min = String(min);
    if (max != null) a.max = String(max);
    return h('input', a);
  };
  // "90일 / 30일 / 안 함" 버튼 + 초 직접 입력 (기존 콘솔과 같은 값)
  K.rotateField = function (input) {
    var presets = [['90일', 7776000], ['30일', 2592000], ['안 함', 0]].map(function (p) {
      return h('button', { type: 'button', class: 'btn ghost small', text: p[0], onclick: function () { input.value = p[1]; } });
    });
    return h('div', { class: 'field' }, [h('span', { class: 'lbl', text: '자동 교체 주기(초)' }), h('div', { class: 'row' }, [input].concat(presets)),
      h('span', { class: 'hint', text: '권장: 90일(7776000초). 비워 두면 수동으로 교체해요.' })]);
  };
  K.card = function (k, v, s, cls) {
    return h('div', { class: 'card' }, [h('div', { class: 'k', text: k }), h('div', { class: 'v ' + (cls || ''), text: v }), h('div', { class: 's', text: s || '' })]);
  };

  // ---- 내려받기 (브라우저에서 파일 생성) ----
  K.download = function (name, text, mime) {
    var url = URL.createObjectURL(new Blob([text], { type: mime + ';charset=utf-8' }));
    var a = h('a', { href: url, download: name }); document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  };
  K.toCSV = function (rows, cols) {
    function q(v) { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
    return '﻿' + [cols.join(',')].concat(rows.map(function (r) { return cols.map(function (c) { return q(r[c]); }).join(','); })).join('\n') + '\n';
  };

  // ---- Prometheus (/api/dashboard/metrics?metric=requests) ----
  K.promTotal = function (vec) {
    var total = 0, err = 0;
    (vec.result || []).forEach(function (s) {
      var v = parseFloat(s.value[1]);
      if (isNaN(v)) return;
      total += v;
      if (String((s.metric || {}).code || '2').charAt(0) !== '2') err += v;
    });
    return { total: total, err: err };
  };
  K.promSeries = function (matrix) {
    var byT = {};
    (matrix.result || []).forEach(function (s) {
      s.values.forEach(function (p) { var v = parseFloat(p[1]); if (!isNaN(v)) byT[p[0]] = (byT[p[0]] || 0) + v; });
    });
    return Object.keys(byT).sort(function (a, b) { return a - b; }).map(function (t) { return [+t, byT[t]]; });
  };

  // ---- SVG 차트 ----
  var NS = 'http://www.w3.org/2000/svg';
  function svgRoot(W, H) {
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); svg.setAttribute('class', 'chart');
    svg.el = function (name, attrs, text) {
      var e = document.createElementNS(NS, name);
      Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
      if (text != null) e.textContent = text;
      svg.appendChild(e); return e;
    };
    return svg;
  }
  K.lineChart = function (points) {
    var W = 800, H = 220, L = 44, R = 12, T = 12, B = 24, svg = svgRoot(W, H);
    var max = Math.max.apply(null, points.map(function (p) { return p[1]; }).concat([1]));
    var t0 = points[0][0], t1 = points[points.length - 1][0] || t0 + 1;
    function x(t) { return L + (t - t0) / ((t1 - t0) || 1) * (W - L - R); }
    function y(v) { return T + (1 - v / max) * (H - T - B); }
    [0, 0.5, 1].forEach(function (f) {
      var yy = y(max * f);
      svg.el('line', { x1: L, x2: W - R, y1: yy, y2: yy, stroke: '#dfe3e8', 'stroke-width': 1 });
      svg.el('text', { x: L - 6, y: yy + 4, 'text-anchor': 'end' }, (max * f).toFixed(max < 10 ? 1 : 0));
    });
    svg.el('path', { d: points.map(function (p, i) { return (i ? 'L' : 'M') + x(p[0]).toFixed(1) + ' ' + y(p[1]).toFixed(1); }).join(' '), fill: 'none', stroke: '#1d4ed8', 'stroke-width': 2.5 });
    var long = (t1 - t0) > 12 * 3600; // 긴 범위는 날짜도 함께 표시
    var tl = function (t) { return long ? new Date(t * 1000).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
      : new Date(t * 1000).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
    svg.el('text', { x: L, y: H - 6 }, tl(t0)); svg.el('text', { x: W - R, y: H - 6, 'text-anchor': 'end' }, tl(t1));
    return svg;
  };
  // groups: [{label, values:[v1,v2,..]}], names: 계열 이름(범례). 값이 하나면 단순 막대.
  var SERIES_COLORS = ['#1d4ed8', '#7c8ea8', '#c2410c'];
  K.barChart = function (groups, names, unit) {
    var W = 800, H = 260, L = 56, R = 12, T = 16, B = 56, svg = svgRoot(W, H);
    var max = 0; groups.forEach(function (g) { g.values.forEach(function (v) { if (v != null && v > max) max = v; }); });
    max = max || 1;
    function y(v) { return T + (1 - v / max) * (H - T - B); }
    [0, 0.5, 1].forEach(function (f) {
      var yy = y(max * f);
      svg.el('line', { x1: L, x2: W - R, y1: yy, y2: yy, stroke: '#dfe3e8' });
      svg.el('text', { x: L - 6, y: yy + 4, 'text-anchor': 'end' }, (max * f).toFixed(max < 10 ? 1 : 0));
    });
    var gw = (W - L - R) / groups.length, k = names.length, bw = Math.min(46, gw * 0.7 / k);
    groups.forEach(function (g, gi) {
      var x0 = L + gi * gw + (gw - bw * k) / 2;
      g.values.forEach(function (v, i) {
        if (v == null) return;
        var top = y(v);
        svg.el('rect', { x: x0 + i * bw, y: top, width: bw - 2, height: Math.max(0, H - B - top), fill: k === 1 ? SERIES_COLORS[0] : SERIES_COLORS[i % 3], rx: 2 });
        svg.el('text', { x: x0 + i * bw + bw / 2 - 1, y: top - 4, 'text-anchor': 'middle' }, v >= 100 ? Math.round(v) : v.toFixed(1));
      });
      svg.el('text', { x: L + gi * gw + gw / 2, y: H - B + 18, 'text-anchor': 'middle' }, g.label);
    });
    if (k > 1) names.forEach(function (n, i) {
      svg.el('rect', { x: L + i * 90, y: H - 16, width: 10, height: 10, fill: SERIES_COLORS[i % 3] });
      svg.el('text', { x: L + i * 90 + 14, y: H - 7 }, n);
    });
    svg.el('text', { x: W - R, y: 12, 'text-anchor': 'end' }, unit);
    return svg;
  };

  // ---- 타이머 / 라우팅 ----
  // 페이지가 바뀌면 route()가 타이머를 모두 끈다(대시보드 10초 갱신, 성능 시험 3초 갱신).
  var timers = [];
  K.onVisible = null;
  K.addTimer = function (fn, ms) { var id = setInterval(fn, ms); timers.push(id); return id; };
  K.clearTimers = function () { timers.forEach(clearInterval); timers = []; K.onVisible = null; };
  document.addEventListener('visibilitychange', function () { if (!document.hidden && K.onVisible) K.onVisible(); });

  K.route = function () {
    var parts = location.hash.replace(/^#\//, '').split('?')[0].split('/');
    var page = K.pages[parts[0]] ? parts[0] : 'home';
    document.querySelectorAll('#nav a').forEach(function (a) { a.classList.toggle('active', a.dataset.page === page); });
    K.clearTimers(); K.token++;
    var view = K.$('view'); clear(view);
    K.pages[page](view, parts.slice(1).map(decodeURIComponent));
  };
})();
