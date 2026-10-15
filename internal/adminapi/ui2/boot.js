// 시작: 세션을 읽고, 해시 라우팅을 연결한다. 해시: #/home, #/keys, #/keys/<이름> ...
(function () {
  'use strict';
  var K = window.KMS;
  (async function init() {
    var s = await fetch('/api/session').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
    if (s) K.session = s;
    K.renderTopbar();
    window.addEventListener('hashchange', K.route);
    K.route();
  })();
})();
