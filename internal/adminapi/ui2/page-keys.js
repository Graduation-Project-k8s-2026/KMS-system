// 키 목록, 키 생성, 키 상세
(function () {
  'use strict';
  var K = window.KMS, h = K.h, clear = K.clear;
  var STALE_DAYS = 90; // 마지막 교체가 이보다 오래되면 주황 경고

  function createKeyPanel(onDone, focusName) {
    var name = h('input', { type: 'text', placeholder: '예: campus-shipping', autocomplete: 'off' });
    var rot = K.numInput('', 0);
    var msg = K.msgBox();
    var form = h('form', { class: 'panel' }, [h('h2', { text: '새 키 만들기' }),
      K.lock(h('div', {}, [h('div', { class: 'form-grid' }, [K.field('키 이름', name), K.rotateField(rot)]),
        h('div', { class: 'row' }, [h('button', { type: 'submit', class: 'btn', text: '키 생성' })])])), msg]);
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var n = name.value.trim();
      if (!n) { K.showMsg(msg, '키 이름을 입력하세요.', 'bad'); return; }
      var body = { name: n };
      if (rot.value !== '') body.auto_rotate_period_sec = parseInt(rot.value, 10);
      var r = await K.api('POST', '/v1/keys', body);
      if (!r.ok) { K.showMsg(msg, K.failMsg('키 생성 실패: ', r), 'bad'); return; }
      onDone();
    });
    if (focusName && K.writable()) setTimeout(function () { name.focus(); }, 0);
    return form;
  }

  // ---- 키 목록 ----
  async function keyList(view) {
    K.pageHead(view, '키', '행을 클릭하면 상세 화면으로 이동해요');
    var wantNew = /\?new/.test(location.hash);
    view.appendChild(createKeyPanel(function () { K.route(); }, wantNew));
    var tools = h('div', { class: 'row top-gap' });
    var box = h('div', { class: 'table-wrap' }, h('div', { class: 'empty', text: '불러오는 중…' }));
    view.appendChild(tools); view.appendChild(box);
    await K.loadSeal();
    var list = await K.api('GET', '/v1/keys');
    if (!list.ok || !list.data) {
      clear(box); box.appendChild(h('div', { class: 'empty', text: K.seal && K.seal.sealed ? '봉인 중이라 키 목록을 볼 수 없어요. 봉인 화면에서 먼저 해제하세요.' : '키 목록을 불러오지 못했어요: ' + K.errText(list) }));
      return;
    }
    var names = list.data.keys || [];
    if (!names.length) { clear(box); box.appendChild(h('div', { class: 'empty', text: '등록된 키가 없어요' })); return; }
    var metas = (await Promise.all(names.map(function (n) { return K.api('GET', '/v1/keys/' + encodeURIComponent(n)); }))).filter(function (r) { return r.ok && r.data; }).map(function (r) { return r.data; });

    var sort = { col: 'Name', dir: 1 }, query = '';
    var search = h('input', { type: 'text', placeholder: '키 이름 검색', 'aria-label': '키 이름 검색' });
    search.addEventListener('input', function () { query = search.value.trim().toLowerCase(); draw(); });
    tools.appendChild(search);
    var COLS = [['Name', '이름'], ['LatestVersion', '최신 버전'], ['MinDecryptionVersion', '옛 버전 차단'], ['AutoRotatePeriodSec', '자동 교체 주기'], ['LastRotatedAt', '마지막 교체'], ['CreatedAt', '생성일']];
    var SORTABLE = { Name: 1, LatestVersion: 1, CreatedAt: 1 };
    function lastRotated(m) { return K.validDate(m.LastRotatedAt) ? m.LastRotatedAt : m.CreatedAt; }
    function draw() {
      var rows = metas.filter(function (m) { return m.Name.toLowerCase().indexOf(query) >= 0; });
      rows.sort(function (a, b) {
        var x = a[sort.col], y = b[sort.col];
        if (sort.col === 'CreatedAt') { x = new Date(x); y = new Date(y); }
        return (x < y ? -1 : x > y ? 1 : 0) * sort.dir;
      });
      var heads = COLS.map(function (c) {
        if (!SORTABLE[c[0]]) return h('th', { text: c[1] });
        var on = sort.col === c[0];
        return h('th', { class: 'sortable', 'aria-sort': on ? (sort.dir > 0 ? 'ascending' : 'descending') : 'none', onclick: function () {
          if (sort.col === c[0]) sort.dir = -sort.dir; else { sort.col = c[0]; sort.dir = 1; }
          draw();
        } }, [c[1] + (on ? (sort.dir > 0 ? ' ▲' : ' ▼') : '')]);
      });
      var body = h('tbody');
      rows.forEach(function (m) {
        var days = K.daysAgo(lastRotated(m)), stale = days !== null && days > STALE_DAYS;
        var never = !K.validDate(m.LastRotatedAt);
        var ago = h('td', {}, days === null ? '—' : h('span', { class: stale ? 'stale' : '', title: stale ? STALE_DAYS + '일이 넘었어요. 새 버전으로 교체를 고려하세요' : '' },
          (stale ? '⚠ ' : '') + (days === 0 ? '오늘' : days + '일 전') + (never ? ' (생성 후 교체 없음)' : '')));
        body.appendChild(h('tr', { class: 'click', onclick: function () { location.hash = '#/keys/' + encodeURIComponent(m.Name); } }, [
          h('td', { class: 'mono', text: m.Name }), h('td', { text: 'v' + m.LatestVersion }),
          h('td', { text: m.MinDecryptionVersion <= 1 ? '차단 안 함' : 'v' + (m.MinDecryptionVersion - 1) + ' 이하 차단' }),
          h('td', { text: K.fmtPeriod(m.AutoRotatePeriodSec) }), ago, h('td', { text: K.fmtDate(m.CreatedAt) })]));
      });
      clear(box);
      if (!rows.length) { box.appendChild(h('div', { class: 'empty', text: '검색 결과가 없어요' })); return; }
      box.appendChild(h('table', {}, [h('thead', {}, h('tr', {}, heads)), body]));
    }
    draw();
  }

  // ---- 키 상세 ----
  async function keyDetail(view, args) {
    var name = args[0];
    view.appendChild(h('p', {}, h('a', { href: '#/keys', text: '← 키 목록' })));
    var r = await K.api('GET', '/v1/keys/' + encodeURIComponent(name));
    if (!r.ok || !r.data) { view.appendChild(K.note('키를 불러오지 못했어요: ' + K.errText(r))); return; }
    var m = r.data;
    view.appendChild(h('h1', { class: 'mono', text: m.Name }));
    view.appendChild(h('p', { class: 'page-sub', text: '종류: ' + m.Type + ' · 생성 ' + K.fmtDate(m.CreatedAt) + ' · 마지막 교체 ' + K.fmtDate(m.LastRotatedAt) }));
    var minV = m.MinDecryptionVersion;
    view.appendChild(h('div', { class: 'cards three' }, [K.card('최신 버전', 'v' + m.LatestVersion, '새 암호화에 쓰는 버전'),
      K.card('옛 버전 차단', minV <= 1 ? '차단 안 함' : 'v' + (minV - 1) + ' 이하', minV <= 1 ? '지금은 모든 버전의 암호문을 풀 수 있어요' : '지금은 v' + (minV - 1) + ' 이하로 만든 암호문은 거부돼요'),
      K.card('자동 교체 주기', K.fmtPeriod(m.AutoRotatePeriodSec), m.AutoRotatePeriodSec ? m.AutoRotatePeriodSec + '초마다' : '수동으로만 교체')]));

    // 버전 표 + 교체 이력 타임라인(최신순). 키 응답의 Versions[].CreatedAt을 쓴다.
    var versions = (m.Versions || []).slice().sort(function (a, b) { return b.Version - a.Version; });
    var vb = h('tbody');
    versions.forEach(function (v) {
      var blocked = v.Version < minV;
      var st = v.Version === m.LatestVersion ? h('span', { class: 'pill pill-ok', text: '최신' }) : blocked ? h('span', { class: 'pill pill-bad', text: '복호화 차단' }) : h('span', { class: 'pill pill-muted', text: '복호화 가능' });
      vb.appendChild(h('tr', {}, [h('td', { text: 'v' + v.Version }), h('td', { text: K.fmtDate(v.CreatedAt) }), h('td', {}, st)]));
    });
    var tl = h('ol', { class: 'timeline' });
    versions.forEach(function (v) {
      tl.appendChild(h('li', {}, [h('span', { class: 'dot' + (v.Version === m.LatestVersion ? ' on' : '') }), h('b', { text: 'v' + v.Version }),
        h('span', { class: 'muted', text: ' ' + (K.validDate(v.CreatedAt) ? K.fmtDateSec(v.CreatedAt) : '생성 시각 정보 없음') + (v.Version === 1 ? ' · 키 생성' : ' · 새 버전으로 교체') })]));
    });
    view.appendChild(h('div', { class: 'two-col' }, [
      h('div', { class: 'panel' }, [h('h2', { text: '버전' }), K.tableWrap(h('table', {}, [K.th(['버전', '생성일', '상태']), vb]))]),
      h('div', { class: 'panel' }, [h('h2', { text: '교체 이력' }), tl])]));

    var msg = K.msgBox();
    var rotate = h('button', { class: 'btn', text: '새 버전으로 교체', onclick: async function () {
      var ok = await K.confirm('새 버전으로 교체할까요?', ['새 버전 v' + (m.LatestVersion + 1) + '이 만들어져요. 앞으로의 암호화는 새 버전으로 하고, 이전 버전 암호문은 계속 풀 수 있어요. (키 교체 = rotation)'], '교체');
      if (!ok) return;
      var res = await K.api('POST', '/v1/keys/' + encodeURIComponent(name) + '/rotate', {});
      if (!res.ok) { K.showMsg(msg, K.failMsg('교체 실패: ', res), 'bad'); return; }
      K.route();
    } });
    // 옛 버전 차단: 값은 min_decryption_version (차단 안 함 = 1, "v{k} 이하 거부" = k+1)
    var sel = h('select', { 'aria-label': '옛 버전 차단' });
    sel.appendChild(h('option', { value: '1', text: '차단 안 함 (모든 버전 허용)' }));
    for (var k = 1; k < m.LatestVersion; k++) sel.appendChild(h('option', { value: String(k + 1), text: 'v' + k + ' 암호문부터 거부 (v' + (k + 1) + ' 이상만 허용)' }));
    sel.value = String(minV);
    var rotIn = K.numInput(m.AutoRotatePeriodSec, 0);
    var save = h('button', { class: 'btn', text: '설정 저장', onclick: async function () {
      var body = {}, chosen = parseInt(sel.value, 10);
      if (chosen !== minV) body.min_decryption_version = chosen;
      if (rotIn.value !== '') body.auto_rotate_period_sec = parseInt(rotIn.value, 10);
      if (!Object.keys(body).length) { K.showMsg(msg, '변경할 값을 입력하세요.', 'bad'); return; }
      if (body.min_decryption_version > minV) {
        var ok = await K.confirm('옛 버전을 차단할까요?', ['v' + (chosen - 1) + ' 이하로 만든 암호문은 더 이상 복호화할 수 없어요.',
          '차단하기 전에 옛 암호문을 새 버전으로 옮겼는지(rewrap) 확인하세요. 옮기지 않은 데이터는 읽을 수 없게 돼요.'], '차단하고 저장', true);
        if (!ok) return;
      }
      var res = await K.api('POST', '/v1/keys/' + encodeURIComponent(name) + '/config', body);
      if (!res.ok) { K.showMsg(msg, K.failMsg('저장 실패: ', res), 'bad'); return; }
      K.route();
    } });
    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '관리' }), K.lock(h('div', {}, [
      h('div', { class: 'row' }, [rotate, h('span', { class: 'muted', text: '새 키 버전을 만들어요. 앞으로의 암호화는 새 버전으로 하고, 이전 버전 암호문은 계속 풀 수 있어요. (키 교체 = rotation)' })]),
      h('div', { class: 'form-grid top-gap' }, [
        K.field('옛 버전 차단', sel, minV <= 1 ? '지금은 모든 버전의 암호문을 풀 수 있어요' : '지금은 v' + (minV - 1) + ' 이하로 만든 암호문은 거부돼요'), K.rotateField(rotIn)]),
      h('div', { class: 'warn-line', text: '차단하기 전에 옛 암호문을 새 버전으로 옮겼는지(rewrap) 확인하세요. 옮기지 않은 데이터는 읽을 수 없게 돼요.' }),
      h('div', { class: 'row top-gap' }, [save])])), msg]));
  }
  // #/keys → 목록, #/keys/<이름> → 상세
  K.pages.keys = function (view, args) { return args && args.length ? keyDetail(view, args) : keyList(view); };
})();
