// 봉인 화면
(function () {
  'use strict';
  var K = window.KMS, h = K.h;

  // seal-profile API는 관리 소켓에 없다(internal/api/admin). seal_type 값으로 화면에서 정적 표를 보여 준다.
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

    // 봉인 방식 선택지(비활성): 현재는 방식 이전 기능이 없어 보여 주기만 한다
    view.appendChild(h('div', { class: 'panel' }, [h('h2', { text: '봉인 방식' }),
      h('div', { class: 'radio-list' }, [
        h('label', { class: 'radio on' }, [h('input', { type: 'radio', checked: 'checked', disabled: 'disabled' }), ' ● Shamir (사용 중)']),
        h('label', { class: 'radio off', title: '봉인 방식 이전 기능을 추가한 뒤에 쓸 수 있어요' }, [h('input', { type: 'radio', disabled: 'disabled' }), ' ○ TPM (준비 중 — 봉인 방식 이전 기능 추가 후)'])]),
      h('div', { class: 'hint-small', text: '봉인 방식은 지금 바꿀 수 없어요. 아래는 참고용 설명이에요.' })]));

    var prof = h('div', { class: 'panel' }, [h('h2', { text: '현재 Seal 특성' })]);
    view.appendChild(prof);
    var d = seal && SEAL_PROFILES[seal.seal_type];
    if (!d) { prof.appendChild(K.note(seal ? '알 수 없는 seal 종류(' + seal.seal_type + ')라 특성 표를 보여 줄 수 없어요.' : 'seal 종류를 알 수 없어요')); return; }
    var rows = [['종류', d.name], ['사람 필요', d.humans], ['필요 인원', d.count], ['단일 장애점(SPOF)', d.spof], ['하드웨어 의존', d.hw], ['자동 해제', d.auto]];
    if (d.note) rows.push(['비고', d.note]);
    var tb = h('tbody');
    rows.forEach(function (x) { tb.appendChild(h('tr', {}, [h('th', { text: x[0] }), h('td', {}, cell(x[1]))])); });
    prof.appendChild(K.tableWrap(h('table', { class: 'kv' }, tb)));
    prof.appendChild(h('div', { class: 'hint-small', text: '설계상 특성을 보여 주는 참고용 표예요(seal 종류 기준). —는 이 화면이 아직 정하지 않은 값이에요.' }));
  };
})();
