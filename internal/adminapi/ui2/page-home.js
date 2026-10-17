// 홈, 대시보드
(function () {
  'use strict';
  var K = window.KMS, h = K.h, clear = K.clear;

  var STATE_KO = K.STATE_KO = { queued: '대기', running: '실행 중', cancelling: '취소 중', succeeded: '성공', failed: '실패', cancelled: '취소됨', timed_out: '시간 초과' };
  K.runLabel = function (x) {
    var s = x.spec;
    return s.mode + ' · 동시성 ' + s.concurrency + ' · ' + (s.duration_seconds > 0 ? s.duration_seconds + '초' : s.count + '회');
  };
  K.rpsOf = function (res) {
    var secs = (new Date(res.ended_at) - new Date(res.started_at)) / 1000;
    return secs > 0 ? res.requests / secs : null;
  };

  function pathCard(num, title, lines, muted) {
    return h('div', { class: 'card path' + (muted ? ' disabled' : '') }, [h('div', { class: 'k', text: num + ' ' + (muted ? '준비 중' : '경로') }), h('h2', { text: title }),
      h('ul', {}, lines.map(function (l) { return h('li', { text: l }); }))]);
  }
  function link(href, text, primary) { return h('a', { class: 'btn' + (primary ? '' : ' ghost'), href: href, text: text }); }

  // ---- 홈 ----
  K.pages.home = async function (view) {
    var token = K.token;
    var res = await Promise.all([K.loadSeal(), K.api('GET', '/v1/keys'), K.api('GET', '/api/jobs'), K.api('GET', '/api/audit'), K.api('GET', '/api/info')]);
    if (token !== K.token) return; // 그 사이 다른 화면으로 이동함
    var seal = K.seal;
    if (seal && seal.sealed) { // 봉인 상태면 홈 대신 봉인 화면으로 보낸다
      K.flash = 'KMS가 봉인됨 → 조각 3개를 입력하세요';
      location.hash = '#/seal';
      return;
    }
    var sv = K.sealView(seal);
    view.appendChild(h('div', { class: 'home-head' }, [h('h1', { text: 'KMS 관리 콘솔' }), h('span', { class: 'pill ' + sv.cls, text: sv.label })]));
    view.appendChild(h('p', { class: 'page-sub', text: '쿠버네티스 위에서 동작하는 Transit형 KMS' }));

    view.appendChild(h('div', { class: 'cards three' }, [
      pathCard('①', '앱 데이터 (Transit API)', ['앱이 서비스 계정 토큰으로 암호화·복호화·rewrap 요청', 'KMS는 데이터를 저장하지 않고 연산만 해요']),
      pathCard('②', 'Secret 암호화 (KMS v2 → etcd)', ['kube-apiserver가 Secret을 etcd에 쓰기 전에 KMS로 암호화', '이 연동은 소켓으로 직접 통신해요']),
      pathCard('③', '외부 사용자', ['외부 사용자용 접근 경로', '아직 제공하지 않아요'], true)]));

    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '빠른 작업' }), h('div', { class: 'row' }, [
      link('#/keys?new', '키 만들기', true), link('#/keys', '키 목록'), link('#/ops', '성능 시험'), link('#/audit', '감사 로그')])]));

    var keys = res[1], jobs = res[2], audit = res[3], info = res[4];
    var nkeys = keys.ok && keys.data && keys.data.keys ? keys.data.keys.length : null;
    var latest = null;
    if (jobs.ok && Array.isArray(jobs.data)) {
      latest = jobs.data.filter(function (j) { return j.state === 'succeeded' && j.upload === 'stored'; })
        .sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); })[0] || null;
    }
    var benchCard = K.card('최근 성능 시험', '—', '완료된 시험이 없어요');
    if (latest) {
      var r = await K.api('GET', '/api/bench/results/' + encodeURIComponent(latest.run_id));
      if (token !== K.token) return;
      var rps = r.ok && r.data ? K.rpsOf(r.data) : null;
      benchCard = K.card('최근 성능 시험', rps === null ? '—' : '초당 ' + rps.toFixed(1) + '회', K.runLabel(latest));
    }
    var today = audit.ok && Array.isArray(audit.data) ? audit.data.length : null;
    view.appendChild(h('div', { class: 'cards three' }, [
      K.card('키 수', nkeys === null ? '—' : String(nkeys), nkeys === null ? '조회 불가' : '등록된 transit 키'),
      benchCard,
      K.card('오늘 감사 기록', today === null ? '—' : today + '건', today === null ? '감사 기록이 꺼져 있어요' : '오늘(UTC) 기록된 요청')]));

    var i = info.ok && info.data ? info.data : {};
    var rows = [['서버 버전', i.server_version || '—'], ['소스 커밋', i.source_sha ? i.source_sha.slice(0, 12) : '—'], ['봉인 방식', seal ? seal.seal_type : '—'],
      ['감사 기록', i.audit_enabled === undefined ? '—' : i.audit_enabled ? '사용 중' : '꺼짐'],
      ['관리 API 이미지', K.digest12(i.admin_image)], ['벤치 이미지', K.digest12(i.bench_image)]];
    var tb = h('tbody');
    rows.forEach(function (x) { tb.appendChild(h('tr', {}, [h('th', { text: x[0] }), h('td', { class: 'mono', text: x[1] })])); });
    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '배포 정보' }), K.tableWrap(h('table', { class: 'kv' }, tb)),
      h('div', { class: 'hint-small', text: '이미지는 digest 앞 12자만 보여 줘요.' + (info.ok ? '' : ' (/api/info를 불러오지 못했어요)') })]));
  };

  // ---- 대시보드 ----
  K.pages.dashboard = async function (view) {
    K.pageHead(view, '대시보드', 'KMS의 현재 상태와 트래픽, 최근 성능 시험 결과 · 10초마다 자동 갱신');
    var cards = h('div', { class: 'cards' });
    var chartBody = h('div', { class: 'note', text: '불러오는 중…' });
    // 시간 범위: 서버는 15m/1h/6h/24h만 받는다 (상한 24시간). 선택값은 이 브라우저에만 기억한다.
    var WINDOWS = [['15m', '15분'], ['1h', '1시간'], ['6h', '6시간'], ['24h', '24시간']], win = '15m';
    try { var saved = localStorage.getItem('kms-dash-window'); if (WINDOWS.some(function (w) { return w[0] === saved; })) win = saved; } catch (e) { /* 저장소 사용 불가 */ }
    var winSel = h('select', { 'aria-label': '시간 범위' }, WINDOWS.map(function (w) { return h('option', { value: w[0], text: '최근 ' + w[1] }); }));
    winSel.value = win;
    var chartTitle = h('h2', { text: '트래픽' });
    var chartBox = h('div', { class: 'panel' }, [h('div', { class: 'row' }, [chartTitle, winSel]), chartBody,
      h('div', { class: 'hint-small', text: 'Prometheus 수집 주기 때문에 10~30초 지연될 수 있어요.' })]);
    var benchBody = h('div', { class: 'note', text: '불러오는 중…' });
    var benchBox = h('div', { class: 'panel' }, [h('h2', { text: '최근 성능 시험' }), benchBody]);
    view.appendChild(cards); view.appendChild(chartBox); view.appendChild(benchBox);

    async function refresh() {
      var res = await Promise.all([K.loadSeal(), K.api('GET', '/v1/keys'), K.api('GET', '/api/dashboard/metrics?metric=requests'),
        K.api('GET', '/api/dashboard/metrics?metric=requests&range=1&window=' + win), K.api('GET', '/api/jobs')]);
      chartTitle.textContent = '트래픽 (최근 ' + WINDOWS.filter(function (w) { return w[0] === win; })[0][1] + ', 초당 요청)';
      var seal = K.seal, sv = K.sealView(seal), keysRes = res[1], reqNow = res[2], reqRange = res[3], jobs = res[4];
      clear(cards);
      var sealCard = K.card('봉인 상태', sv.label, sv.sub, seal && !seal.sealed ? 'ok' : 'warn');
      if (seal) sealCard.appendChild(h('div', { class: 'raw mono', text: 'sealed=' + seal.sealed + ' · seal_type=' + seal.seal_type + (seal.initialized !== undefined ? ' · initialized=' + seal.initialized : '') }));
      cards.appendChild(sealCard);
      var nkeys = keysRes.ok && keysRes.data && keysRes.data.keys ? keysRes.data.keys.length : null;
      cards.appendChild(K.card('키 수', nkeys === null ? '—' : String(nkeys), nkeys === null ? '봉인 중이거나 조회 불가' : '등록된 transit 키'));
      var t = reqNow.ok && reqNow.data ? K.promTotal(reqNow.data.data) : null;
      cards.appendChild(K.card('초당 요청', t ? t.total.toFixed(2) : '—', t ? '최근 5분 평균' : '메트릭 없음(N/A)'));
      cards.appendChild(K.card('오류율', t && t.total > 0 ? (t.err / t.total * 100).toFixed(1) + '%' : (t ? '0%' : '—'), t ? '2xx 외 응답 비율' : '메트릭 없음(N/A)'));

      var pts = reqRange.ok && reqRange.data ? K.promSeries(reqRange.data.data) : [];
      clear(chartBody); chartBody.className = '';
      if (pts.length > 1) chartBody.appendChild(K.lineChart(pts));
      else { chartBody.className = 'note'; chartBody.textContent = '표시할 시계열이 없어요 (Prometheus 연결 또는 요청 없음)'; }

      clear(benchBody); benchBody.className = '';
      if (!jobs.ok || !jobs.data || !jobs.data.length) {
        benchBody.className = 'note'; benchBody.textContent = '실행한 성능 시험이 없어요.';
      } else {
        var runs = jobs.data.slice().sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); }).slice(0, 5);
        var body = h('tbody');
        runs.forEach(function (r) {
          body.appendChild(h('tr', {}, [h('td', { text: K.runLabel(r) }), h('td', {}, h('small', { class: 'mono muted', text: r.run_id.slice(0, 8) })),
            h('td', { text: STATE_KO[r.state] || r.state }), h('td', { text: K.fmtDate(r.created_at) })]));
        });
        benchBody.appendChild(K.tableWrap(h('table', {}, [K.th(['시험', '실행 ID', '상태', '시작']), body])));
      }
    }
    winSel.addEventListener('change', function () {
      win = winSel.value;
      try { localStorage.setItem('kms-dash-window', win); } catch (e) { /* 무시 */ }
      refresh();
    });
    await refresh();
    K.addTimer(function () { if (!document.hidden) refresh(); }, 10000);
    K.onVisible = refresh;
  };
})();
