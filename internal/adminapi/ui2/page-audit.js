// 감사 로그, 사용자
(function () {
  'use strict';
  var K = window.KMS, h = K.h, clear = K.clear;

  K.pages.audit = async function (view) {
    K.pageHead(view, '감사 로그', '오늘 기록된 관리 작업과 암복호화(Transit) 요청 · 각각 최대 1000건');
    var box = h('div', { class: 'table-wrap' }, h('div', { class: 'empty', text: '불러오는 중…' }));
    var bar = h('div', { class: 'panel filters' });
    view.appendChild(bar); view.appendChild(box);
    var r = await K.api('GET', '/api/audit');
    if (!r.ok) { clear(box); box.appendChild(h('div', { class: 'empty', text: '감사 로그를 불러오지 못했어요: ' + K.errText(r) })); return; }
    var all = Array.isArray(r.data) ? r.data : [];
    function opts(sel, values, allLabel) {
      sel.appendChild(h('option', { value: '', text: allLabel }));
      values.forEach(function (v) { sel.appendChild(h('option', { value: v, text: v })); });
    }
    function uniq(f) { var s = {}; all.forEach(function (e) { s[f(e)] = 1; }); return Object.keys(s).sort(); }
    // "POST /v1/keys completed" 에서 동작 종류만 뽑는다(감사 기록에는 키 이름이 남지 않는다)
    function actionOf(e) { return String(e.action || '').replace(/ (requested|completed)$/, ''); }
    // 경로: 관리 기록(source=admin)은 'admin', Transit 기록은 listener(internal|external)
    function pathOf(e) { return e.source === 'transit' ? (e.listener || 'internal') : 'admin'; }
    var PATH_KO = { admin: '관리', internal: 'Transit 내부', external: 'Transit 외부' };
    var fUser = h('select', { 'aria-label': '사용자' }), fKey = h('select', { 'aria-label': '키' }), fPath = h('select', { 'aria-label': '경로' }), fAct = h('select', { 'aria-label': '동작' }), fRes = h('select', { 'aria-label': '결과' }), fSort = h('select', { 'aria-label': '정렬' });
    opts(fUser, uniq(function (e) { return e.subject; }), '모든 사용자');
    opts(fKey, uniq(function (e) { return e.key || ''; }).filter(Boolean), '모든 키');
    opts(fAct, uniq(actionOf), '모든 동작');
    [['', '모든 경로'], ['admin', '관리(콘솔·소켓)'], ['internal', 'Transit 내부'], ['external', 'Transit 외부']].forEach(function (o) { fPath.appendChild(h('option', { value: o[0], text: o[1] })); });
    [['', '모든 결과'], ['ok', '성공'], ['fail', '실패']].forEach(function (o) { fRes.appendChild(h('option', { value: o[0], text: o[1] })); });
    [['desc', '최신순'], ['asc', '오래된순']].forEach(function (o) { fSort.appendChild(h('option', { value: o[0], text: o[1] })); });
    var q = h('input', { type: 'text', placeholder: '검색 (사용자·키·동작·IP·요청 ID)', 'aria-label': '검색' });
    var count = h('span', { class: 'muted' });
    var csvBtn = h('button', { class: 'btn ghost small', type: 'button', text: 'CSV 내려받기' });
    bar.appendChild(h('div', { class: 'row' }, [fUser, fKey, fPath, fAct, fRes, fSort, q, csvBtn, count]));
    bar.appendChild(h('div', { class: 'hint-small', text: '관리 기록은 요청 시작·완료가 한 쌍으로 남아요. Transit 기록은 요청당 한 줄이고 본문·토큰·평문은 기록하지 않아요. 외부 경로는 클라이언트 IP가 함께 남아요.' }));

    var shown = [];
    function draw() {
      var term = q.value.trim().toLowerCase();
      shown = all.filter(function (e) {
        if (fUser.value && e.subject !== fUser.value) return false;
        if (fKey.value && e.key !== fKey.value) return false;
        if (fPath.value && pathOf(e) !== fPath.value) return false;
        if (fAct.value && actionOf(e) !== fAct.value) return false;
        if (fRes.value === 'ok' && !e.success) return false;
        if (fRes.value === 'fail' && e.success) return false;
        if (term && (e.subject + ' ' + e.action + ' ' + e.request_id + ' ' + (e.key || '') + ' ' + (e.client_ip || '')).toLowerCase().indexOf(term) < 0) return false;
        return true;
      }).sort(function (a, b) { return (new Date(a.utc) - new Date(b.utc)) * (fSort.value === 'asc' ? 1 : -1); });
      count.textContent = shown.length + '건';
      clear(box);
      if (!shown.length) { box.appendChild(h('div', { class: 'empty', text: all.length ? '조건에 맞는 기록이 없어요' : '기록이 없어요' })); return; }
      var body = h('tbody');
      shown.slice(0, 200).forEach(function (e) {
        body.appendChild(h('tr', {}, [h('td', { text: K.fmtDateSec(e.utc) }), h('td', { text: e.subject }), h('td', {}, h('span', { class: 'pill ' + (pathOf(e) === 'external' ? 'pill-bad' : 'pill-muted'), text: PATH_KO[pathOf(e)] }) ),
          h('td', { class: 'mono', text: e.action + (e.status ? ' · ' + e.status : '') }), h('td', { class: 'mono', text: e.key || '—' }), h('td', { class: 'mono', text: e.client_ip || '' }),
          h('td', {}, h('span', { class: 'pill ' + (e.allowed ? 'pill-ok' : 'pill-bad'), text: e.allowed ? '허용' : '거부' })),
          h('td', {}, h('span', { class: 'pill ' + (e.success ? 'pill-ok' : 'pill-bad'), text: e.success ? '성공' : '실패' })), h('td', { class: 'mono', text: e.request_id })]));
      });
      box.appendChild(h('table', {}, [K.th(['시각', '사용자', '경로', '동작', '키', '클라이언트 IP', '허용', '결과', '요청 ID']), body]));
      if (shown.length > 200) box.appendChild(h('div', { class: 'hint-small pad', text: '화면에는 200건까지만 보여 줘요. 전체는 CSV로 내려받으세요.' }));
    }
    [fUser, fKey, fPath, fAct, fRes, fSort].forEach(function (s) { s.addEventListener('change', draw); });
    q.addEventListener('input', draw);
    csvBtn.addEventListener('click', function () {
      var rows = shown.map(function (e) { return { utc: e.utc, source: e.source || '', listener: e.listener || '', subject: e.subject, action: e.action, key: e.key || '', client_ip: e.client_ip || '', status: e.status || '', allowed: e.allowed, success: e.success, request_id: e.request_id }; });
      K.download('audit-log.csv', K.toCSV(rows, ['utc', 'source', 'listener', 'subject', 'action', 'key', 'client_ip', 'status', 'allowed', 'success', 'request_id']), 'text/csv');
    });
    draw();
  };

  // ---- 사용자 (조회 전용) ----
  K.pages.users = async function (view) {
    K.pageHead(view, '사용자', '이 콘솔에 등록된 계정과 역할 (조회 전용). 이메일은 서버에서 가려서 보내요.');
    var box = h('div', { class: 'table-wrap' }, h('div', { class: 'empty', text: '불러오는 중…' }));
    view.appendChild(box);
    var r = await K.api('GET', '/api/console-users');
    clear(box);
    if (!r.ok || !Array.isArray(r.data)) { box.appendChild(h('div', { class: 'empty', text: '사용자 목록을 불러오지 못했어요: ' + K.errText(r) })); return; }
    var body = h('tbody');
    r.data.forEach(function (u) {
      body.appendChild(h('tr', {}, [h('td', { class: 'mono', text: u.user }), h('td', {}, h('span', { class: 'pill ' + (u.role === 'admin' ? 'pill-ok' : 'pill-muted'), text: u.role === 'admin' ? '관리자' : '뷰어' }))]));
    });
    box.appendChild(h('table', {}, [K.th(['사용자', '역할']), body]));
    view.appendChild(h('div', { class: 'hint-small', text: '사용자 추가·변경은 서버의 역할 파일에서 해요. 이 화면에서는 바꿀 수 없어요.' }));
  };
})();
