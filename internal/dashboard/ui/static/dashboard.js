// KMS 운영·성능 대시보드. 외부 라이브러리 없이 SVG를 직접 그린다.
// 서버가 준 문자열(라벨 등)은 항상 textContent로만 넣는다(XSS 방지).
(function () {
  'use strict';

  var SVGNS = 'http://www.w3.org/2000/svg';
  var POLL_MS = 5000;

  // 계열은 "무엇인가"에 고정한다(순위가 아니라). 색 외에 선 모양·마커로도 구분한다.
  var OPS = [
    { key: 'encrypt', color: 'var(--s1)', dash: '', marker: 'circle' },
    { key: 'decrypt', color: 'var(--s2)', dash: '6 3', marker: 'square' },
    { key: 'rewrap', color: 'var(--s3)', dash: '2 3', marker: 'triangle' }
  ];
  var RUN_COLORS = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)', 'var(--s8)'];
  var MAX_COMPARE = RUN_COLORS.length;

  // ---------- DOM 도우미 ----------
  function h(tag, attrs) {
    var el = document.createElement(tag);
    fill(el, attrs, arguments, 2);
    return el;
  }
  function s(tag, attrs) {
    var el = document.createElementNS(SVGNS, tag);
    fill(el, attrs, arguments, 2);
    return el;
  }
  function fill(el, attrs, args, from) {
    if (attrs) for (var k in attrs) {
      if (k === 'text') el.textContent = attrs[k];
      else if (k === 'class') el.setAttribute('class', attrs[k]);
      else if (k.indexOf('on') === 0) el.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== null && attrs[k] !== undefined) el.setAttribute(k, attrs[k]);
    }
    for (var i = from; i < args.length; i++) {
      var c = args[i];
      if (c === null || c === undefined || c === false) continue;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function $(id) { return document.getElementById(id); }

  // ---------- 서식 ----------
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function clock(sec, withSec) {
    var d = new Date(sec * 1000);
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + (withSec ? ':' + pad(d.getSeconds()) : '');
  }
  function dateTime(iso) {
    var d = new Date(iso);
    if (isNaN(d)) return '—';
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  function num(v, digits) {
    if (v === null || v === undefined || isNaN(v)) return '—';
    var a = Math.abs(v);
    if (digits === undefined) digits = a >= 100 ? 0 : a >= 10 ? 1 : 2;
    return v.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: digits });
  }
  function pct(v) { return v === null || v === undefined ? '—' : num(v * 100, 1) + '%'; }

  function niceMax(v) {
    if (!(v > 0)) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var f = v / p;
    var n = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return n * p;
  }

  // ---------- 마커 / 범례 견본 ----------
  function markerShape(kind, x, y, color) {
    var g = s('g', { 'class': 'marker' });
    var r = 4.5;
    if (kind === 'square') g.appendChild(s('rect', { x: x - r, y: y - r, width: 2 * r, height: 2 * r, fill: color, stroke: 'var(--panel)', 'stroke-width': 2 }));
    else if (kind === 'triangle') g.appendChild(s('path', { d: 'M' + x + ' ' + (y - r - 1) + ' L' + (x + r + 1) + ' ' + (y + r) + ' L' + (x - r - 1) + ' ' + (y + r) + ' Z', fill: color, stroke: 'var(--panel)', 'stroke-width': 2 }));
    else g.appendChild(s('circle', { cx: x, cy: y, r: r, fill: color, stroke: 'var(--panel)', 'stroke-width': 2 }));
    return g;
  }
  function legendSwatch(ser) {
    var svg = s('svg', { width: 30, height: 12, 'aria-hidden': 'true' });
    svg.appendChild(s('line', { x1: 0, x2: 30, y1: 6, y2: 6, stroke: ser.color, 'stroke-width': 2, 'stroke-dasharray': ser.dash || null }));
    svg.appendChild(markerShape(ser.marker, 15, 6, ser.color));
    return svg;
  }

  // ---------- 선 차트 ----------
  // spec: { title, unit, t:[sec], series:[{name,color,dash,marker,values:[num|null],fmt}], yMax?, fmt, extra? }
  // 값이 전부 null이면 emptyText를 보여준다. 표 보기는 항상 제공한다.
  function lineChart(spec) {
    var card = h('div', { 'class': 'card chart-card' });
    var plotBox = h('div', { 'class': 'plot' });
    var tableBox = h('div', { hidden: '' });
    var showTable = false;
    var toggle = h('button', { 'class': 'view-toggle', type: 'button', text: '표 보기' });
    toggle.addEventListener('click', function () {
      showTable = !showTable;
      plotBox.hidden = showTable;
      legend.hidden = showTable;
      tableBox.hidden = !showTable;
      toggle.textContent = showTable ? '차트 보기' : '표 보기';
    });
    card.appendChild(h('div', { 'class': 'chart-head' },
      h('h3', { text: spec.title }), h('span', { 'class': 'unit', text: spec.unit || '' }), toggle));

    var legend = h('div', { 'class': 'legend' });
    spec.series.forEach(function (ser) {
      var last = null;
      for (var i = ser.values.length - 1; i >= 0; i--) if (ser.values[i] !== null) { last = ser.values[i]; break; }
      legend.appendChild(h('span', { 'class': 'item' }, legendSwatch(ser), h('span', { text: ser.name }),
        h('span', { 'class': 'val', text: (ser.fmt || spec.fmt)(last) })));
    });
    card.appendChild(legend);
    card.appendChild(plotBox);
    card.appendChild(tableBox);
    if (spec.extra) card.appendChild(h('div', { 'class': 'extra', text: spec.extra }));

    var hasData = spec.series.some(function (ser) { return ser.values.some(function (v) { return v !== null; }); });
    if (!hasData) {
      plotBox.appendChild(h('div', { 'class': 'empty', text: spec.emptyText || '표시할 데이터가 없습니다' }));
    } else {
      drawLines(plotBox, spec);
    }
    tableBox.appendChild(seriesTable(spec));
    return card;
  }

  function drawLines(box, spec) {
    var W = 520, H = 220, m = { l: 52, r: 14, t: 12, b: 26 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    var n = spec.t.length;
    var max = 0;
    spec.series.forEach(function (ser) { ser.values.forEach(function (v) { if (v !== null && v > max) max = v; }); });
    var yMax = spec.yMax || niceMax(max * 1.05);
    var t0 = spec.t[0], t1 = spec.t[n - 1];
    function X(i) { return m.l + (n === 1 ? pw / 2 : (spec.t[i] - t0) / (t1 - t0) * pw); }
    function Y(v) { return m.t + ph - v / yMax * ph; }

    var svg = s('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': spec.title });
    var axis = s('g', { 'class': 'axis' });
    for (var k = 0; k <= 4; k++) {
      var yv = yMax * k / 4, y = Y(yv);
      axis.appendChild(s('line', { 'class': 'gridline', x1: m.l, x2: W - m.r, y1: y, y2: y }));
      axis.appendChild(s('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end', text: (spec.axisFmt || spec.fmt)(yv) }));
    }
    var ticks = Math.min(5, n);
    for (var q = 0; q < ticks; q++) {
      var idx = ticks === 1 ? 0 : Math.round(q * (n - 1) / (ticks - 1));
      axis.appendChild(s('text', { x: X(idx), y: H - 6, 'text-anchor': q === 0 ? 'start' : q === ticks - 1 ? 'end' : 'middle', text: clock(spec.t[idx], true) }));
    }
    svg.appendChild(axis);

    spec.series.forEach(function (ser) {
      // null은 선을 이어주지 않고 끊는다(요청 없음/카운터 리셋을 0으로 오해하지 않게).
      var d = '', pen = false, lastIdx = -1;
      ser.values.forEach(function (v, i) {
        if (v === null) { pen = false; return; }
        d += (pen ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(v).toFixed(1);
        pen = true; lastIdx = i;
      });
      if (d) svg.appendChild(s('path', { d: d, fill: 'none', stroke: ser.color, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-dasharray': ser.dash || null }));
      if (lastIdx >= 0) svg.appendChild(markerShape(ser.marker, X(lastIdx), Y(ser.values[lastIdx]), ser.color));
    });

    // 호버: 십자선 + 툴팁
    var cross = s('line', { y1: m.t, y2: m.t + ph, stroke: 'var(--text-dim)', 'stroke-width': 1, 'stroke-dasharray': '3 3', visibility: 'hidden' });
    var dots = s('g', {});
    svg.appendChild(cross); svg.appendChild(dots);
    var tip = h('div', { 'class': 'tip' });
    var hit = s('rect', { x: m.l, y: m.t, width: pw, height: ph, fill: 'transparent' });
    svg.appendChild(hit);
    box.appendChild(svg); box.appendChild(tip);

    function show(ev) {
      var r = svg.getBoundingClientRect();
      var px = (ev.clientX - r.left) / r.width * W;
      var best = 0, bd = Infinity;
      for (var i = 0; i < n; i++) { var dd = Math.abs(X(i) - px); if (dd < bd) { bd = dd; best = i; } }
      cross.setAttribute('x1', X(best)); cross.setAttribute('x2', X(best)); cross.setAttribute('visibility', 'visible');
      clear(dots); clear(tip);
      tip.appendChild(h('div', { 'class': 't', text: clock(spec.t[best], true) }));
      spec.series.forEach(function (ser) {
        var v = ser.values[best];
        if (v !== null) dots.appendChild(markerShape(ser.marker, X(best), Y(v), ser.color));
        tip.appendChild(h('div', { 'class': 'row' }, h('span', { text: ser.name }), h('b', { text: (ser.fmt || spec.fmt)(v) })));
      });
      tip.style.display = 'block';
      var left = X(best) / W * r.width + 12;
      if (left + tip.offsetWidth > r.width) left -= tip.offsetWidth + 24;
      tip.style.left = Math.max(0, left) + 'px';
      tip.style.top = '8px';
    }
    function hide() { cross.setAttribute('visibility', 'hidden'); clear(dots); tip.style.display = 'none'; }
    hit.addEventListener('mousemove', show);
    hit.addEventListener('mouseleave', hide);
  }

  function seriesTable(spec) {
    var tbl = h('table', { 'class': 'data' });
    var head = h('tr', null, h('th', { text: '시각' }));
    spec.series.forEach(function (ser) { head.appendChild(h('th', { 'class': 'num', text: ser.name })); });
    tbl.appendChild(h('thead', null, head));
    var body = h('tbody');
    // 최신 값이 위로. 너무 길어지지 않게 최근 60행만.
    for (var i = spec.t.length - 1, shown = 0; i >= 0 && shown < 60; i--, shown++) {
      var tr = h('tr', null, h('td', { text: clock(spec.t[i], true) }));
      spec.series.forEach(function (ser) { tr.appendChild(h('td', { 'class': 'num', text: (ser.fmt || spec.fmt)(ser.values[i]) })); });
      body.appendChild(tr);
    }
    tbl.appendChild(body);
    return h('div', { 'class': 'table-wrap', style: 'max-height:260px;overflow:auto' }, tbl);
  }

  // ---------- 상태 카드 ----------
  function statCard(k, vNode, src, small) {
    return h('div', { 'class': 'stat' }, h('div', { 'class': 'k', text: k }),
      h('div', { 'class': 'v' + (small ? ' small-v' : '') }, vNode),
      src !== undefined ? h('div', { 'class': 'src', text: src ? '출처: ' + src : '출처: —' }) : null);
  }

  function renderStatus(st) {
    var cards = $('cards');
    clear(cards);
    var src = st.sources || {};
    var sealedBadge;
    if (st.sealed === null) sealedBadge = h('span', { 'class': 'badge na', text: '? 알 수 없음' });
    else if (st.sealed) sealedBadge = h('span', { 'class': 'badge bad', text: '🔒 sealed' });
    else sealedBadge = h('span', { 'class': 'badge ok', text: '🔓 unsealed' });
    cards.appendChild(statCard('봉인 상태', sealedBadge, src.sealed));
    cards.appendChild(statCard('키 개수', document.createTextNode(st.keys === null ? '—' : num(st.keys, 0)), src.keys));
    cards.appendChild(statCard('키 버전 합계', document.createTextNode(st.key_versions === null ? '—' : num(st.key_versions, 0)), src.key_versions));
    cards.appendChild(statCard('마지막 unseal', document.createTextNode(st.last_unseal ? dateTime(st.last_unseal) : '—'), src.last_unseal, true));

    var m = st.metrics || {};
    var collect;
    if (!m.enabled) collect = h('span', { 'class': 'badge na', text: '꺼짐' });
    else if (m.ok) collect = h('span', { 'class': 'badge ok', text: '✔ 정상' });
    else collect = h('span', { 'class': 'badge bad', text: '✖ 수집 불가' });
    var detail = m.enabled ? (m.ok ? m.interval_seconds + '초 주기 · ' + m.samples + '개' : '재시도 중') : 'ADMIN_API_METRICS_URL 비어 있음';
    var cc = h('div', { 'class': 'stat' }, h('div', { 'class': 'k', text: '메트릭 수집' }), h('div', { 'class': 'v' }, collect),
      h('div', { 'class': 'src', text: detail }));
    cards.appendChild(cc);

    var note = $('collect-note');
    if (!m.enabled) {
      note.hidden = false;
      note.textContent = '메트릭 수집이 꺼져 있습니다. 봉인 상태와 키 개수만 admin.sock에서 가져오며, 트래픽 차트와 키 버전·마지막 unseal은 표시되지 않습니다.';
    } else if (!m.ok) {
      note.hidden = false;
      note.textContent = '메트릭 수집 불가 — 계속 재시도합니다.' + (m.last_error ? ' (' + m.last_error + ')' : '') +
        (m.last_success ? ' 마지막 성공: ' + dateTime(m.last_success) : '') +
        ' · 봉인 상태와 키 개수는 admin.sock에서 대신 가져왔습니다. 클러스터에서는 ADMIN_API_METRICS_URL을 KMS 메트릭 주소로 설정했는지 확인하세요.';
    } else {
      note.hidden = true;
    }
  }

  // ---------- 트래픽 ----------
  var chartsBox = $('charts');

  function opSeries(tr, field, suffix, dash) {
    var out = [];
    OPS.forEach(function (op) {
      var ser = tr.ops && tr.ops[op.key];
      if (!ser) return;
      out.push({ name: op.key + (suffix || ''), color: op.color, dash: dash === undefined ? op.dash : dash, marker: op.marker, values: ser[field] });
    });
    return out;
  }

  function renderTraffic(tr) {
    var msg = $('traffic-msg');
    if (!tr.t.length) {
      msg.hidden = false;
      msg.textContent = '아직 표시할 시계열이 없습니다. 수집이 시작되고 두 번째 샘플이 쌓이면(' + tr.step_seconds + '초 뒤) 나타납니다.';
    } else {
      msg.hidden = true;
    }
    clear(chartsBox);
    var t = tr.t;
    var noOps = '작업 메트릭이 없습니다 (아직 요청이 없음)';

    // 에러율 요약(차트 아래 한 줄)
    var errs = [];
    OPS.forEach(function (op) {
      var ser = tr.ops && tr.ops[op.key];
      if (!ser) return;
      var last = null;
      for (var i = ser.error_rate.length - 1; i >= 0; i--) if (ser.error_rate[i] !== null) { last = ser.error_rate[i]; break; }
      errs.push(op.key + ' ' + pct(last));
    });

    chartsBox.appendChild(lineChart({
      title: '처리량', unit: '요청/초', t: t, fmt: function (v) { return num(v); },
      series: opSeries(tr, 'rps'), emptyText: noOps,
      extra: errs.length ? '최근 에러율 — ' + errs.join(' · ') : ''
    }));

    var lat = opSeries(tr, 'p50_ms', ' p50', undefined).concat(opSeries(tr, 'p99_ms', ' p99', '1 0'));
    // p99는 실선 대신 점선 계열과 구분되도록 마커 없이 얇은 점선으로 그린다.
    lat.forEach(function (ser) { if (/p99$/.test(ser.name)) ser.dash = '1 4'; });
    chartsBox.appendChild(lineChart({
      title: '지연 p50 / p99', unit: 'ms', t: t, fmt: function (v) { return num(v, 2); },
      series: lat, emptyText: noOps
    }));

    var az = tr.authz;
    var noAz = '인가 메트릭이 없습니다 (인가 off이거나 아직 호출 없음)';
    chartsBox.appendChild(lineChart({
      title: '인가 캐시 적중률', unit: '%', t: t, yMax: 1, fmt: pct, axisFmt: function (v) { return num(v * 100, 0) + '%'; },
      series: az ? [{ name: '적중률', color: 'var(--s1)', dash: '', marker: 'circle', values: az.cache_hit_ratio }] : [],
      emptyText: noAz
    }));
    chartsBox.appendChild(lineChart({
      title: 'SAR 호출', unit: '회/초', t: t, fmt: function (v) { return num(v); },
      series: az ? [{ name: 'SAR/s', color: 'var(--s4)', dash: '', marker: 'square', values: az.sar_rps }] : [],
      emptyText: noAz
    }));
    chartsBox.appendChild(lineChart({
      title: 'SAR 평균 vs apiserver 왕복 평균', unit: 'ms (차이 = 클라이언트 대기)', t: t, fmt: function (v) { return num(v, 2); },
      series: az ? [
        { name: 'SAR 평균', color: 'var(--s1)', dash: '', marker: 'circle', values: az.sar_avg_ms },
        { name: 'apiserver 왕복', color: 'var(--s2)', dash: '6 3', marker: 'square', values: az.apiserver_rtt_avg_ms },
        { name: '클라이언트 대기', color: 'var(--s3)', dash: '2 3', marker: 'triangle', values: az.client_wait_avg_ms }
      ] : [],
      emptyText: noAz
    }));
  }

  // ---------- 폴링 ----------
  var inflight = false;
  function fetchJSON(url) {
    return fetch(url, { cache: 'no-store' }).then(function (r) {
      return r.json().then(function (body) {
        if (!r.ok) throw new Error(body && body.error ? body.error : 'HTTP ' + r.status);
        return body;
      });
    });
  }
  function refresh() {
    if (inflight || document.hidden) return;
    inflight = true;
    var win = $('window').value;
    Promise.all([fetchJSON('/api/dashboard/status'), fetchJSON('/api/dashboard/traffic?window=' + encodeURIComponent(win))
      .catch(function (e) { return { error: e.message }; })])
      .then(function (res) {
        renderStatus(res[0]);
        if (res[1].error) {
          var msg = $('traffic-msg');
          msg.hidden = false; msg.textContent = '트래픽을 가져오지 못했습니다: ' + res[1].error;
        } else {
          renderTraffic(res[1]);
        }
        $('updated').textContent = '갱신 ' + clock(Date.now() / 1000, true);
      })
      .catch(function (e) {
        $('updated').textContent = '관리 API 응답 없음: ' + e.message;
      })
      .then(function () { inflight = false; });
  }

  // ---------- 벤치 결과 ----------
  var metas = [];
  var selected = [];   // 선택 순서대로 id
  var docs = {};       // id -> 결과 JSON
  var benchMsg = $('bench-msg');

  function loadBench() {
    return fetchJSON('/api/bench/results').then(function (list) {
      metas = list;
      selected = selected.filter(function (id) { return list.some(function (m) { return m.id === id; }); });
      renderBenchList();
      renderCompare();
    }).catch(function (e) {
      benchMsg.hidden = false; benchMsg.textContent = '벤치 결과를 가져오지 못했습니다: ' + e.message;
    });
  }

  function renderBenchList() {
    var tbl = $('bench-list');
    clear(tbl);
    if (!metas.length) {
      tbl.appendChild(h('tbody', null, h('tr', null, h('td', { 'class': 'dim', text: '아직 제출된 벤치 결과가 없습니다.' }))));
      return;
    }
    tbl.appendChild(h('thead', null, h('tr', null,
      h('th', { text: '비교' }), h('th', { text: '#' }), h('th', { text: '시각' }), h('th', { text: '라벨' }),
      h('th', { text: '시나리오' }), h('th', { 'class': 'num', text: '조건 수' }), h('th', { text: '' }))));
    var body = h('tbody');
    metas.forEach(function (m) {
      var pos = selected.indexOf(m.id);
      var cb = h('input', { type: 'checkbox', 'aria-label': m.label + ' 비교에 포함' });
      cb.checked = pos >= 0;
      cb.disabled = pos < 0 && selected.length >= MAX_COMPARE;
      cb.addEventListener('change', function () { toggleSelect(m.id, cb.checked); });
      var del = h('button', { type: 'button', text: '삭제' });
      del.addEventListener('click', function () { removeBench(m); });
      body.appendChild(h('tr', null,
        h('td', null, cb),
        h('td', null, pos >= 0 ? h('span', null, h('span', { 'class': 'swatch', style: 'background:' + RUN_COLORS[pos] }), String(pos + 1)) : ''),
        h('td', { text: dateTime(m.timestamp) }),
        h('td', { text: m.label || '(라벨 없음)', title: m.id }),
        h('td', { text: (m.scenarios || []).join(', ') }),
        h('td', { 'class': 'num', text: String(m.conditions) }),
        h('td', null, del)));
    });
    tbl.appendChild(body);
  }

  function toggleSelect(id, on) {
    var i = selected.indexOf(id);
    if (on && i < 0 && selected.length < MAX_COMPARE) selected.push(id);
    if (!on && i >= 0) selected.splice(i, 1);
    renderBenchList();
    var need = selected.filter(function (x) { return !docs[x]; });
    Promise.all(need.map(function (x) {
      return fetchJSON('/api/bench/results/' + encodeURIComponent(x)).then(function (d) { docs[x] = d; });
    })).then(renderCompare).catch(function (e) {
      benchMsg.hidden = false; benchMsg.textContent = '결과를 읽지 못했습니다: ' + e.message;
    });
  }

  function removeBench(m) {
    if (!window.confirm('"' + (m.label || m.id) + '" 결과를 삭제할까요? (되돌릴 수 없음)')) return;
    fetch('/api/bench/results/' + encodeURIComponent(m.id), { method: 'DELETE' }).then(function (r) {
      if (!r.ok && r.status !== 404) throw new Error('HTTP ' + r.status);
      delete docs[m.id];
      benchMsg.hidden = true;
      return loadBench();
    }).catch(function (e) {
      benchMsg.hidden = false; benchMsg.textContent = '삭제하지 못했습니다: ' + e.message;
    });
  }

  function sizeLabel(b) {
    if (b >= 1048576 && b % 1048576 === 0) return (b / 1048576) + 'MB';
    if (b >= 1024 && b % 1024 === 0) return (b / 1024) + 'KB';
    return b + 'B';
  }
  function groupKey(r) { return r.operation + ' · ' + sizeLabel(r.payload_bytes); }

  // 선택한 실행에서 "작업 · 페이로드" 그룹별로, 동시성 -> 값 표를 만든다.
  function collectGroups() {
    var groups = {};
    selected.forEach(function (id, idx) {
      var d = docs[id];
      if (!d) return;
      d.runs.forEach(function (r) {
        var g = groups[groupKey(r)] = groups[groupKey(r)] || {};
        var row = g[r.concurrency] = g[r.concurrency] || {};
        if (row[idx] === undefined) row[idx] = r; // 같은 조건이 여러 시나리오에 있으면 첫 값
      });
    });
    return groups;
  }

  function metricOf(r, metric) {
    if (!r) return null;
    if (metric === 'ops') return r.ops_per_sec;
    return (metric === 'p50' ? r.latency.p50_seconds : r.latency.p99_seconds) * 1000;
  }

  function renderCompare() {
    var box = $('compare');
    var chart = $('compare-chart');
    if (!selected.length || !selected.every(function (id) { return docs[id]; })) {
      box.hidden = !selected.length;
      if (!selected.length) return;
    }
    box.hidden = false;
    var groups = collectGroups();
    var keys = Object.keys(groups).sort();
    var gsel = $('group');
    var prev = gsel.value;
    clear(gsel);
    keys.forEach(function (k) { gsel.appendChild(h('option', { value: k, text: k })); });
    if (keys.indexOf(prev) >= 0) {
      gsel.value = prev;
    } else if (keys.length) {
      // 기본값: 선택한 실행이 가장 많이 겹치는 조건(비교가 의미 있는 쪽)
      var bestKey = keys[0], bestN = -1;
      keys.forEach(function (k) {
        var seen = {};
        Object.keys(groups[k]).forEach(function (c) { Object.keys(groups[k][c]).forEach(function (i) { seen[i] = true; }); });
        var n = Object.keys(seen).length;
        if (n > bestN) { bestN = n; bestKey = k; }
      });
      gsel.value = bestKey;
    }
    clear(chart);
    if (!keys.length) { chart.appendChild(h('div', { 'class': 'empty', text: '비교할 데이터가 없습니다' })); return; }
    drawCompare(chart, groups[gsel.value], $('metric').value, gsel.value);
  }

  function drawCompare(box, rows, metric, groupName) {
    var concs = Object.keys(rows).map(Number).sort(function (a, b) { return a - b; });
    var unit = metric === 'ops' ? 'ops/sec' : 'ms';
    var fmt = function (v) { return metric === 'ops' ? num(v, 0) : num(v, 2); };
    var nRuns = selected.length;

    // 범례(번호 + 라벨 + 시각)
    var legend = h('div', { 'class': 'legend' });
    selected.forEach(function (id, i) {
      var m = metas.filter(function (x) { return x.id === id; })[0] || {};
      legend.appendChild(h('span', { 'class': 'item' }, h('span', { 'class': 'swatch', style: 'background:' + RUN_COLORS[i] }),
        h('span', { text: (i + 1) + '. ' + (m.label || id) + ' (' + dateTime(m.timestamp) + ')' })));
    });
    box.appendChild(legend);

    var max = 0;
    concs.forEach(function (c) { for (var i = 0; i < nRuns; i++) { var v = metricOf(rows[c][i], metric); if (v !== null && v > max) max = v; } });
    var yMax = niceMax(max * 1.08);
    var groupW = 110, W = Math.max(520, 60 + concs.length * groupW), H = 260;
    var m = { l: 56, r: 12, t: 20, b: 44 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    function Y(v) { return m.t + ph - v / yMax * ph; }

    var svg = s('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': groupName + ' ' + unit + ' 비교', style: 'max-width:' + W + 'px' });
    var axis = s('g', { 'class': 'axis' });
    for (var k = 0; k <= 4; k++) {
      var y = Y(yMax * k / 4);
      axis.appendChild(s('line', { 'class': 'gridline', x1: m.l, x2: W - m.r, y1: y, y2: y }));
      axis.appendChild(s('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end', text: fmt(yMax * k / 4) }));
    }
    svg.appendChild(axis);

    var slot = pw / concs.length;
    var barW = Math.min(26, (slot - 14) / nRuns - 2);
    concs.forEach(function (c, ci) {
      var gx = m.l + ci * slot + slot / 2;
      var start = gx - (nRuns * (barW + 2) - 2) / 2;
      for (var i = 0; i < nRuns; i++) {
        var v = metricOf(rows[c][i], metric);
        var bx = start + i * (barW + 2);
        if (v !== null) {
          var top = Y(v), hgt = Math.max(1, m.t + ph - top);
          // 위쪽만 둥글게(데이터 끝), 바닥은 기준선에 붙인다.
          var r = Math.min(4, barW / 2, hgt);
          svg.appendChild(s('path', {
            d: 'M' + bx + ' ' + (m.t + ph) + ' V' + (top + r) + ' Q' + bx + ' ' + top + ' ' + (bx + r) + ' ' + top +
              ' H' + (bx + barW - r) + ' Q' + (bx + barW) + ' ' + top + ' ' + (bx + barW) + ' ' + (top + r) + ' V' + (m.t + ph) + ' Z',
            fill: RUN_COLORS[i]
          }), s('title', { text: (i + 1) + '번 · 동시성 ' + c + ' · ' + fmt(v) + ' ' + unit }));
          if (nRuns <= 4) svg.appendChild(s('text', { x: bx + barW / 2, y: top - 4, 'text-anchor': 'middle', 'font-size': 10, fill: 'var(--text-dim)', text: fmt(v) }));
        }
        // 색에만 의존하지 않도록 막대 아래에 실행 번호를 적는다.
        svg.appendChild(s('text', { x: bx + barW / 2, y: m.t + ph + 13, 'text-anchor': 'middle', 'font-size': 10, fill: 'var(--text-dim)', text: String(i + 1) }));
      }
      svg.appendChild(s('text', { x: gx, y: H - 8, 'text-anchor': 'middle', 'font-size': 12, fill: 'var(--text)', text: '동시성 ' + c }));
    });
    box.appendChild(h('div', { style: 'overflow-x:auto' }, svg));

    // 표(항상 표시)
    var tbl = h('table', { 'class': 'data' });
    var head = h('tr', null, h('th', { text: '동시성' }));
    selected.forEach(function (id, i) {
      var mm = metas.filter(function (x) { return x.id === id; })[0] || {};
      head.appendChild(h('th', { 'class': 'num', text: (i + 1) + '. ' + (mm.label || id) + ' (' + unit + ')' }));
    });
    tbl.appendChild(h('thead', null, head));
    var body = h('tbody');
    concs.forEach(function (c) {
      var tr = h('tr', null, h('td', { text: String(c) }));
      for (var i = 0; i < nRuns; i++) tr.appendChild(h('td', { 'class': 'num', text: fmt(metricOf(rows[c][i], metric)) }));
      body.appendChild(tr);
    });
    tbl.appendChild(body);
    box.appendChild(h('div', { 'class': 'table-wrap' }, tbl));
  }

  $('group').addEventListener('change', renderCompare);
  $('metric').addEventListener('change', renderCompare);
  $('window').addEventListener('change', function () { inflight = false; refresh(); });

  refresh();
  setInterval(refresh, POLL_MS);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) refresh(); });
  loadBench();
})();
