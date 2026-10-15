// 성능 시험: 설정 폼, 프리셋, 스윕/반복, 결과 비교, 내려받기, 시험 시간대 서버 지표
(function () {
  'use strict';
  var K = window.KMS, h = K.h, clear = K.clear;
  var ACTIVE = { queued: 1, running: 1, cancelling: 1 };
  // 서버(internal/jobs Spec.Validate)의 한도와 같은 값. 화면에서 먼저 검사해 알려 준다.
  var LIMITS = { conc: [1, 32], count: [1, 100000], payload: [1, 1048576], duration: [0, 300] };
  var PRESETS = [
    ['빠른 확인', { mode: 'transit', conc: 1, kind: 'count', count: 100, payload: 1024 }],
    ['표준', { mode: 'transit', conc: 16, kind: 'count', count: 2000, payload: 1024 }],
    ['60초 부하', { mode: 'transit', conc: 16, kind: 'duration', duration: 60, payload: 1024 }],
    ['큰 요청', { mode: 'transit', conc: 4, kind: 'count', count: 500, payload: 65536 }]
  ];
  var SWEEP = [1, 4, 16, 32];
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function isActive(x) { return ACTIVE[x.state] || (x.state === 'succeeded' && x.upload === 'pending'); }
  function limitText(s) { return s.duration_seconds > 0 ? s.duration_seconds + '초' : s.count + '회'; }
  function mean(a) { return a.reduce(function (x, y) { return x + y; }, 0) / a.length; }
  function std(a) { var m = mean(a); return Math.sqrt(mean(a.map(function (v) { return (v - m) * (v - m); }))); }

  K.pages.ops = async function (view) {
    var token = K.token;
    K.pageHead(view, '성능 시험', '클러스터 안에서 시험 Job을 띄워 처리량과 지연을 측정합니다. 대시보드의 트래픽은 실제 요청을 관찰한 값입니다.');

    // ---------- 설정 폼 ----------
    var modeSel = h('select', { 'aria-label': '모드' }, [['transit', 'transit (Transit API)'], ['plugin', 'plugin (KMS v2 소켓)'], ['e2e', 'e2e (Secret 생성→etcd)']].map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
    var concIn = h('input', { type: 'number', min: 1, max: 32, value: '1' });
    var kindCount = h('input', { type: 'radio', name: 'limitkind', value: 'count', checked: 'checked' });
    var kindDur = h('input', { type: 'radio', name: 'limitkind', value: 'duration' });
    var countIn = h('input', { type: 'number', min: 1, max: 100000, value: '100' });
    var durIn = h('input', { type: 'number', min: 1, max: 300, value: '60' });
    var payIn = h('input', { type: 'number', min: 1, max: 1048576, value: '1024' });
    var runSingle = h('input', { type: 'radio', name: 'runkind', value: 'single', checked: 'checked' });
    var runSweep = h('input', { type: 'radio', name: 'runkind', value: 'sweep' });
    var runRepeat = h('input', { type: 'radio', name: 'runkind', value: 'repeat' });
    var repIn = h('input', { type: 'number', min: 2, max: 5, value: '3' });
    var formMsg = K.msgBox(), progress = h('div', { class: 'run-status' }), summary = h('div');

    function syncKind() { countIn.disabled = !kindCount.checked; durIn.disabled = !kindDur.checked; concIn.disabled = runSweep.checked; repIn.disabled = !runRepeat.checked; }
    [kindCount, kindDur, runSingle, runSweep, runRepeat].forEach(function (e) { e.addEventListener('change', syncKind); });
    function applyPreset(p) {
      modeSel.value = p.mode; concIn.value = p.conc; payIn.value = p.payload;
      if (p.kind === 'duration') { kindDur.checked = true; durIn.value = p.duration; } else { kindCount.checked = true; countIn.value = p.count; }
      runSingle.checked = true; syncKind(); K.showMsg(formMsg, '');
    }
    function inRange(v, lim) { return Number.isInteger(v) && v >= lim[0] && v <= lim[1]; }
    // 화면에서 입력 범위를 검사한다. 통과하면 {spec}, 아니면 {err}
    function readSpec() {
      var conc = parseInt(concIn.value, 10), pay = parseInt(payIn.value, 10), spec = { mode: modeSel.value, scenario: 'basic', op: 'roundtrip', payload_bytes: pay };
      if (!runSweep.checked && !inRange(conc, LIMITS.conc)) return { err: '동시성은 1~32 사이의 정수여야 해요.' };
      spec.concurrency = conc;
      if (!inRange(pay, LIMITS.payload)) return { err: '요청 크기는 1~1048576 바이트여야 해요.' };
      if (kindDur.checked) {
        var d = parseInt(durIn.value, 10);
        if (!inRange(d, [1, LIMITS.duration[1]])) return { err: '시간은 1~300초여야 해요.' };
        spec.duration_seconds = d; spec.count = LIMITS.count[1]; // 서버는 횟수 상한(count)과 시간 중 먼저 끝나는 쪽에서 멈춘다
      } else {
        var c = parseInt(countIn.value, 10);
        if (!inRange(c, LIMITS.count)) return { err: '횟수는 1~100000 사이의 정수여야 해요.' };
        spec.count = c; spec.duration_seconds = 0;
      }
      if (runRepeat.checked && !inRange(parseInt(repIn.value, 10), [2, 5])) return { err: '반복 횟수는 2~5회예요.' };
      return { spec: spec };
    }
    function buildPlan(spec) {
      if (runSweep.checked) return SWEEP.map(function (c) { return Object.assign({}, spec, { concurrency: c }); });
      if (runRepeat.checked) { var n = parseInt(repIn.value, 10), a = []; for (var i = 0; i < n; i++) a.push(Object.assign({}, spec)); return a; }
      return [spec];
    }

    var planning = false;
    var startBtn = h('button', { class: 'btn', type: 'button', text: '시험 시작', onclick: async function () {
      if (planning) return;
      var rs = readSpec();
      if (rs.err) { K.showMsg(formMsg, rs.err, 'bad'); return; }
      K.showMsg(formMsg, '');
      var plan = buildPlan(rs.spec);
      var heavy = plan.some(function (s) { return s.mode === 'e2e' || s.concurrency >= 32 || s.duration_seconds >= 60; });
      var lines = ['시험 ' + plan.length + '번을 순서대로 실행해요.'];
      if (heavy) lines = ['운영 KMS에 실제 부하를 줍니다. 단일 노드라 클러스터 Secret 처리도 느려질 수 있어요.'].concat(lines);
      var ok = await K.confirm(heavy ? '부하가 큰 시험이에요' : '시험을 시작할까요?', lines.concat(['벤치 Pod는 CPU 1코어로 제한돼요.']), '시작', heavy);
      if (!ok) return;
      runPlan(plan, runRepeat.checked ? 'repeat' : runSweep.checked ? 'sweep' : 'single');
    } });

    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '새 시험' }),
      K.lock(h('div', {}, [
        h('div', { class: 'row' }, [h('span', { class: 'muted', text: '프리셋' })].concat(PRESETS.map(function (p) { return h('button', { type: 'button', class: 'btn ghost small', text: p[0], onclick: function () { applyPreset(p[1]); } }); }))),
        h('div', { class: 'form-grid four top-gap' }, [K.field('모드', modeSel), K.field('동시성', concIn, '1~32'), K.field('요청 크기(바이트)', payIn, '1~1048576 (최대 1 MiB)'),
          h('div', { class: 'field' }, [h('span', { class: 'lbl', text: '끝나는 조건' }),
            h('label', { class: 'row inline' }, [kindCount, ' 횟수 ', countIn]), h('label', { class: 'row inline' }, [kindDur, ' 시간(초) ', durIn]),
            h('span', { class: 'hint', text: '시간으로 하면 횟수 상한 100000에 먼저 닿지 않는 한 그 시간 동안 측정해요' })])]),
        h('div', { class: 'row top-gap' }, [h('span', { class: 'lbl', text: '실행 방식' }),
          h('label', { class: 'row inline' }, [runSingle, ' 한 번']), h('label', { class: 'row inline' }, [runSweep, ' 스윕 (동시성 1→4→16→32)']),
          h('label', { class: 'row inline' }, [runRepeat, ' 같은 조건 반복 ', repIn, ' 회(최대 5)'])]),
        h('div', { class: 'row top-gap' }, [startBtn])])),
      h('div', { class: 'row top-gap' }, [progress]), formMsg,
      h('div', { class: 'hint-small', text: '벤치 Pod는 CPU 1코어로 제한돼요. 스윕·반복은 앞 시험이 끝나야 다음을 시작해요. 이 화면을 떠나면 남은 순서는 중단돼요(이미 시작한 시험은 계속 돼요).' })]));
    view.appendChild(summary);
    syncKind();

    // ---------- 목록 / 선택 / 비교 ----------
    var cache = {}, selected = {}, runs = [], pollId = null;
    var compareBox = h('div'), detailBox = h('div'), tableBox = h('div', { class: 'table-wrap' }, h('div', { class: 'empty', text: '불러오는 중…' }));
    var csvBtn = h('button', { class: 'btn ghost small', type: 'button', text: '선택 CSV' }), jsonBtn = h('button', { class: 'btn ghost small', type: 'button', text: '선택 JSON' });
    var selNote = h('span', { class: 'muted', text: '비교하려면 시험을 2개 이상 체크하세요' });
    view.appendChild(h('div', { class: 'row top-gap' }, [h('h2', { class: 'inline-h', text: '시험 목록' }), csvBtn, jsonBtn, selNote]));
    view.appendChild(tableBox); view.appendChild(compareBox); view.appendChild(detailBox);

    function row(x) { // 내려받기·비교용 평탄한 한 줄
      var res = cache[x.run_id] || {}, secs = res.started_at ? (new Date(res.ended_at) - new Date(res.started_at)) / 1000 : null;
      return { run_id: x.run_id, mode: x.spec.mode, concurrency: x.spec.concurrency, count: x.spec.count, duration_seconds: x.spec.duration_seconds, payload_bytes: x.spec.payload_bytes,
        state: x.state, started_at: res.started_at || '', ended_at: res.ended_at || '', elapsed_seconds: secs === null ? '' : +secs.toFixed(2), requests: res.requests == null ? '' : res.requests,
        errors: res.errors == null ? '' : res.errors, error_rate: res.requests ? +(res.errors / res.requests).toFixed(4) : '', rps: res.requests && secs > 0 ? +(res.requests / secs).toFixed(2) : '',
        p50_ms: res.p50_seconds == null ? '' : +(res.p50_seconds * 1000).toFixed(2), p95_ms: res.p95_seconds == null ? '' : +(res.p95_seconds * 1000).toFixed(2), p99_ms: res.p99_seconds == null ? '' : +(res.p99_seconds * 1000).toFixed(2) };
    }
    var COLS = ['run_id', 'mode', 'concurrency', 'count', 'duration_seconds', 'payload_bytes', 'state', 'started_at', 'ended_at', 'elapsed_seconds', 'requests', 'errors', 'error_rate', 'rps', 'p50_ms', 'p95_ms', 'p99_ms'];
    function selectedRows() { return runs.filter(function (x) { return selected[x.run_id] && cache[x.run_id]; }).map(row); }
    csvBtn.addEventListener('click', function () { var r = selectedRows(); if (r.length) K.download('bench-results.csv', K.toCSV(r, COLS), 'text/csv'); });
    jsonBtn.addEventListener('click', function () { var r = selectedRows(); if (r.length) K.download('bench-results.json', JSON.stringify(r, null, 2), 'application/json'); });

    function drawCompare() {
      var rows = selectedRows();
      csvBtn.disabled = jsonBtn.disabled = !rows.length;
      selNote.textContent = rows.length ? rows.length + '개 선택됨' : '비교하려면 시험을 2개 이상 체크하세요';
      clear(compareBox);
      if (rows.length < 2) return;
      var labels = rows.map(function (r) { return r.run_id.slice(0, 4) + ' c' + r.concurrency; });
      compareBox.appendChild(h('div', { class: 'panel top-gap' }, [h('h2', { text: '결과 비교' }),
        h('div', { class: 'two-col' }, [h('div', {}, [h('h3', { text: '처리량 (초당 요청)' }), K.barChart(rows.map(function (r, i) { return { label: labels[i], values: [r.rps === '' ? null : r.rps] }; }), ['초당 요청'], '요청/초')]),
          h('div', {}, [h('h3', { text: '지연 p50 / p95 / p99 (ms)' }), K.barChart(rows.map(function (r, i) { return { label: labels[i], values: [r.p50_ms, r.p95_ms, r.p99_ms].map(function (v) { return v === '' ? null : v; }) }; }), ['p50', 'p95', 'p99'], 'ms')])]),
        h('div', { class: 'hint-small', text: '막대 아래 이름은 실행 ID 앞 4자 + 동시성(c)이에요. 같은 동시성끼리 비교해야 공정해요.' })]));
    }

    async function showDetail(x) {
      clear(detailBox);
      var res = cache[x.run_id], p = h('div', { class: 'panel top-gap' }, [h('h2', { text: '시험 상세 · ' + x.run_id.slice(0, 8) })]);
      detailBox.appendChild(p);
      var r = row(x), items = [['조건', K.runLabel(x) + ' · 요청 ' + x.spec.payload_bytes + ' B'], ['상태', K.STATE_KO[x.state] || x.state], ['소요 시간', r.elapsed_seconds === '' ? '—' : K.fmtDur(r.elapsed_seconds)],
        ['요청 / 오류', res ? res.requests + ' / ' + res.errors : '—'], ['초당 요청', r.rps === '' ? '—' : r.rps], ['p50 / p95 / p99', res ? r.p50_ms + ' / ' + r.p95_ms + ' / ' + r.p99_ms + ' ms' : '—']];
      var tb = h('tbody'); items.forEach(function (i) { tb.appendChild(h('tr', {}, [h('th', { text: i[0] }), h('td', { text: String(i[1]) })])); });
      p.appendChild(K.tableWrap(h('table', { class: 'kv' }, tb)));
      p.appendChild(h('h3', { class: 'top-gap', text: '이 시험 시간대의 서버 초당 요청 (Prometheus)' }));
      var chart = h('div', { class: 'note', text: '불러오는 중…' }); p.appendChild(chart);
      if (!res) { chart.textContent = '결과가 아직 없어 시간대를 알 수 없어요.'; return; }
      var m = await K.api('GET', '/api/dashboard/metrics?metric=requests&range=1');
      var t0 = new Date(res.started_at) / 1000 - 15, t1 = new Date(res.ended_at) / 1000 + 15;
      var pts = m.ok && m.data ? K.promSeries(m.data.data).filter(function (q) { return q[0] >= t0 && q[0] <= t1; }) : [];
      clear(chart); chart.className = '';
      if (pts.length > 1) chart.appendChild(K.lineChart(pts));
      else { chart.className = 'note'; chart.textContent = m.ok ? '지표가 없어요. 서버 지표는 최근 15분만 볼 수 있어요.' : 'Prometheus 지표를 불러오지 못했어요: ' + K.errText(m); }
    }

    async function load() {
      var jr = await K.api('GET', '/api/jobs');
      if (token !== K.token) return;
      if (!jr.ok || !Array.isArray(jr.data)) { clear(tableBox); tableBox.appendChild(h('div', { class: 'empty', text: '작업 목록을 불러오지 못했어요: ' + K.errText(jr) })); return; }
      runs = jr.data.slice().sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); });
      await Promise.all(runs.map(async function (x) {
        if (x.upload === 'stored' && !cache[x.run_id]) { var r = await K.api('GET', '/api/bench/results/' + encodeURIComponent(x.run_id)); if (r.ok && r.data) cache[x.run_id] = r.data; }
      }));
      if (token !== K.token) return;
      var active = runs.some(isActive);
      clear(tableBox);
      if (!runs.length) tableBox.appendChild(h('div', { class: 'empty', text: '실행한 시험이 없어요' }));
      else {
        var body = h('tbody');
        runs.forEach(function (x) {
          var res = cache[x.run_id], r = row(x), canSel = !!res;
          var cb = h('input', { type: 'checkbox', 'aria-label': '비교에 포함', onchange: function () { selected[x.run_id] = cb.checked; drawCompare(); } });
          if (!canSel) cb.disabled = true; else cb.checked = !!selected[x.run_id];
          var elapsed = r.elapsed_seconds !== '' ? K.fmtDur(r.elapsed_seconds) : ACTIVE[x.state] ? K.fmtDur((Date.now() - new Date(x.created_at)) / 1000) + ' 경과' : '—';
          var cancel = (x.state === 'queued' || x.state === 'running') ? K.lock(h('button', { class: 'btn ghost small', type: 'button', text: '취소', onclick: async function () {
            var ok = await K.confirm('시험을 취소할까요?', [K.runLabel(x) + ' 실행을 중단해요.'], '시험 취소', true);
            if (!ok) return;
            var d = await K.api('DELETE', '/api/jobs/' + encodeURIComponent(x.run_id));
            if (!d.ok) { K.showMsg(formMsg, K.failMsg('취소 실패: ', d), 'bad'); return; }
            load();
          } })) : null;
          body.appendChild(h('tr', {}, [h('td', {}, cb), h('td', { text: K.runLabel(x) }), h('td', { text: x.spec.payload_bytes + ' B' }), h('td', {}, h('small', { class: 'mono muted', title: x.run_id, text: x.run_id.slice(0, 8) })),
            h('td', { text: K.STATE_KO[x.state] || x.state }), h('td', { text: K.fmtDate(x.created_at) }), h('td', { text: elapsed }),
            h('td', { text: r.rps === '' ? '—' : String(r.rps) }), h('td', { text: r.p50_ms === '' ? '—' : r.p50_ms + ' ms' }), h('td', { text: r.p95_ms === '' ? '—' : r.p95_ms + ' ms' }), h('td', { text: r.p99_ms === '' ? '—' : r.p99_ms + ' ms' }),
            h('td', { text: r.error_rate === '' ? '—' : (r.error_rate * 100).toFixed(1) + '%' }),
            h('td', {}, h('div', { class: 'row tight' }, [res ? h('button', { class: 'btn ghost small', type: 'button', text: '상세', onclick: function () { showDetail(x); } }) : null, cancel]))]));
        });
        tableBox.appendChild(h('table', {}, [K.th(['', '모드 · 동시성 · 횟수/시간', '요청 크기', '실행 ID', '상태', '시작', '소요', '초당 요청', 'p50', 'p95', 'p99', '오류율', '']), body]));
      }
      drawCompare();
      if (active && !pollId) pollId = K.addTimer(load, 3000);   // 실행 중이면 3초마다 다시 불러오고, 끝나면 멈춘다
      if (!active && pollId) { clearInterval(pollId); pollId = null; }
    }

    // ---------- 순서대로 실행 (스윕/반복) ----------
    function setProgress(spin, text) { clear(progress); if (spin) progress.appendChild(h('span', { class: 'spinner', 'aria-hidden': 'true' })); progress.appendChild(document.createTextNode(text)); }
    async function waitDone(id) {
      for (;;) {
        await sleep(2000);
        if (token !== K.token) return null;
        var r = await K.api('GET', '/api/jobs/' + encodeURIComponent(id));
        load();
        if (r.ok && r.data && !isActive(r.data)) return r.data;
        if (!r.ok && r.status === 404) return null;
      }
    }
    async function runPlan(plan, kind) {
      planning = true; startBtn.disabled = true; clear(summary);
      var ids = [], failed = false;
      for (var i = 0; i < plan.length; i++) {
        if (token !== K.token) return;
        setProgress(true, (i + 1) + '/' + plan.length + ' 실행 중… (' + plan[i].mode + ' · 동시성 ' + plan[i].concurrency + ')');
        var r = await K.api('POST', '/api/jobs', plan[i]);
        if (!r.ok) { K.showMsg(formMsg, K.failMsg('시작 실패: ', r), 'bad'); failed = true; break; }
        ids.push(r.data.run_id); load();
        var fin = await waitDone(r.data.run_id);
        if (token !== K.token) return;
        if (!fin || fin.state !== 'succeeded') { failed = true; break; }
      }
      planning = false; startBtn.disabled = false;
      await load();
      if (token !== K.token) return;
      var res = ids.map(function (id) { return cache[id]; }).filter(Boolean);
      if (failed) { setProgress(false, '실패 · ' + res.length + '/' + plan.length + '개만 끝났어요'); }
      else {
        var rpsList = res.map(K.rpsOf).filter(function (v) { return v !== null; });
        setProgress(false, '완료 · ' + (rpsList.length ? '초당 ' + mean(rpsList).toFixed(1) + '회' + (rpsList.length > 1 ? ' (평균)' : '') : '결과 업로드 대기'));
      }
      if (kind === 'repeat' && res.length > 1) {
        var rps = res.map(K.rpsOf), p99 = res.map(function (x) { return x.p99_seconds * 1000; });
        summary.appendChild(h('div', { class: 'cards three' }, [K.card('반복 횟수', res.length + '회', '같은 조건'), K.card('초당 요청 (평균 ± 표준편차)', mean(rps).toFixed(1) + ' ± ' + std(rps).toFixed(1), '표준편차가 작을수록 안정적'),
          K.card('p99 지연 (평균 ± 표준편차)', mean(p99).toFixed(2) + ' ± ' + std(p99).toFixed(2) + ' ms', '')]));
      }
      if (kind === 'sweep') { ids.forEach(function (id) { if (cache[id]) selected[id] = true; }); drawCompare(); }
    }

    await load();
  };
})();
