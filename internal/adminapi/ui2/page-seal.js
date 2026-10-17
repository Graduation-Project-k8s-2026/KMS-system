// 봉인 화면
(function () {
  'use strict';
  var K = window.KMS, h = K.h;

  // 특성 표는 관리 소켓의 GET /v1/sys/seal-profile 값을 보여 준다. 그 호출이 실패하면 seal_type 기준의 아래 정적 표로 대신한다.
  // true/false는 예/아니요, null은 모르는 값(—), 문자열은 그대로 표시.
  var SEAL_PROFILES = {
    shamir: { name: 'Shamir (조각 입력)', humans: true, count: '3명 (5개 중)', spof: false, hw: false, auto: false, note: '' },
    tpm: { name: 'TPM', humans: false, count: '0명', spof: '예 (VM·TPM이 사라지면 복구 조각으로 복원)', hw: true, auto: '예 (향후 지원)', note: '' },
    k8s: { name: 'Kubernetes Secret', humans: false, count: '0명', spof: '예 (etcd)', hw: false, auto: true,
      note: '클러스터 Secret을 이 KMS가 암호화하므로 순환 의존 — 이 배포에서는 사용 안 함' },
    dev: { name: '개발용(dev)', humans: false, count: '0명', spof: null, hw: false, auto: null, note: '개발용, 운영 사용 금지' }
  };
  function cell(v) { return document.createTextNode(v === null ? '—' : v === true ? '예' : v === false ? '아니요' : String(v)); }

  K.pages.seal = async function (view) {
    K.pageHead(view, '봉인', '루트 키 보호 상태와 해제');
    if (K.flash) { view.appendChild(h('div', { class: 'msg warn', text: K.flash })); K.flash = ''; }
    await K.loadSeal();
    var seal = K.seal, v = K.sealView(seal);
    var top = h('div', { class: 'panel' }, [h('h2', { text: '상태' }), h('span', { class: 'pill ' + v.cls, text: v.label }), h('p', { class: 'muted', text: v.sub })]);
    if (seal) top.appendChild(h('div', { class: 'raw mono', text: Object.keys(seal).map(function (k) { return k + '=' + seal[k]; }).join(' · ') }));
    view.appendChild(top);

    if (seal && !seal.sealed) {
      var smsg = K.msgBox();
      view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '봉인하기' }),
        h('p', { class: 'muted', text: '봉인하면 KMS가 잠기고 클러스터 Secret 읽기가 멈춥니다. 해제하려면 조각 3개가 필요합니다.' }),
        K.lock(h('div', { class: 'row' }, h('button', { class: 'btn danger', text: '봉인하기', onclick: async function () {
          var ok = await K.confirm('KMS를 봉인할까요?', ['봉인하면 KMS가 잠기고 클러스터 Secret 읽기가 멈춥니다. 해제하려면 조각 3개가 필요합니다.'], '봉인', true, 'seal');
          if (!ok) return;
          var r = await K.api('POST', '/v1/sys/seal', {});
          if (!r.ok) { K.showMsg(smsg, K.failMsg('봉인 실패: ', r), 'bad'); return; }
          K.route();
        } }))), smsg]));
    }

    if (seal && seal.sealed) {
      var msg = K.msgBox();
      var panel = h('div', { class: 'panel' }, [h('h2', { text: '봉인 해제' })]);
      if (seal.seal_type === 'shamir') {
        var inp = h('input', { type: 'text', placeholder: '조각(share)을 붙여 넣으세요', autocomplete: 'off' });
        var f = h('form', { class: 'row' }, [inp, h('button', { class: 'btn', type: 'submit', text: '조각 제출' })]);
        f.addEventListener('submit', async function (e) {
          e.preventDefault();
          var share = inp.value.trim(); if (!share) return;
          var r = await K.api('POST', '/v1/sys/unseal', { share: share });
          if (!r.ok) { K.showMsg(msg, K.failMsg('조각 제출 실패: ', r), 'bad'); return; }
          K.route();
        });
        panel.appendChild(h('p', { class: 'muted', text: seal.progress ? '제출된 조각: ' + seal.progress : '조각 3개를 입력하면 해제돼요' }));
        panel.appendChild(K.lock(f));
      } else {
        panel.appendChild(K.lock(h('div', { class: 'row' }, h('button', { class: 'btn', text: '봉인 해제', onclick: async function () {
          var r = await K.api('POST', '/v1/sys/unseal', {});
          if (!r.ok) { K.showMsg(msg, K.failMsg('해제 실패: ', r), 'bad'); return; }
          K.route();
        } }))));
      }
      panel.appendChild(msg);
      view.appendChild(panel);
    }

    // 봉인 방식: 전환·조각 재발급 버튼은 이 화면에 없다. TPM 배포는 보류(ADR-010)이고, seal-migrate는 관리 API 허용 목록에도 없다.
    // (조각 재발급도 init 기록을 v2로 올려 이전 서버 이미지로 되돌릴 수 없게 되므로 이번 운영 적용 동안은 실행하지 않는다.)
    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '봉인 방식' }),
      h('p', { text: '지금 방식: ' + (seal ? seal.seal_type : '알 수 없음') + (seal && seal.recovery_available ? ' (복구 조각 사용 가능)' : '') }),
      h('div', { class: 'note', text: 'TPM 전환은 배포 보류 중이에요 (ADR-010). 운영 클러스터의 컨테이너가 TPM 장치를 열 수 없는 문제(장치 cgroup)가 풀리기 전에는 전환하지 않아요. 그래서 이 화면에는 전환·조각 재발급 버튼이 없어요.' }),
      h('div', { class: 'hint-small', text: '꼭 필요하면 서버에서 관리 소켓으로 직접 실행해요 (docs/usage.md의 "봉인 방식 이전" 참고). 조각 재발급도 저장소 기록 형식을 올리므로 이전 서버 이미지로 되돌릴 계획이 있으면 하지 마세요.' })]));

    var prof = h('div', { class: 'panel' }, [h('h2', { text: '현재 Seal 특성' })]);
    view.appendChild(prof);
    var live = seal ? await K.api('GET', '/v1/sys/seal-profile') : null, d = seal && SEAL_PROFILES[seal.seal_type];
    if (live && live.ok && live.data && live.data.Type) { // 서버가 알려 준 실제 값
      var lp = live.data;
      d = { name: (SEAL_PROFILES[lp.Type] || {}).name || lp.Type, humans: !!lp.RequiresHumans, count: lp.HumanCount ? lp.HumanCount + '명' : '0명',
        spof: !!lp.SinglePointOfFailure, hw: !!lp.HardwareDependent, auto: !!lp.AutoUnsealCapable, note: lp.Notes || '' };
    }
    if (!d) { prof.appendChild(K.note(seal ? '알 수 없는 seal 종류(' + seal.seal_type + ')라 특성 표를 보여 줄 수 없어요.' : 'seal 종류를 알 수 없어요')); return; }
    var rows = [['종류', d.name], ['사람 필요', d.humans], ['필요 인원', d.count], ['단일 장애점(SPOF)', d.spof], ['하드웨어 의존', d.hw], ['자동 해제', d.auto]];
    if (d.note) rows.push(['비고', d.note]);
    var tb = h('tbody');
    rows.forEach(function (x) { tb.appendChild(h('tr', {}, [h('th', { text: x[0] }), h('td', {}, cell(x[1]))])); });
    prof.appendChild(K.tableWrap(h('table', { class: 'kv' }, tb)));
    prof.appendChild(h('div', { class: 'hint-small', text: '서버(seal-profile)가 알려 준 설계상 특성이에요. 서버에서 못 가져오면 seal 종류 기준의 참고용 표를 보여 줘요.' }));
  };
})();
