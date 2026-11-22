(function () {
  var KEY = 'ogs-demo-count', n = Number(localStorage.getItem(KEY)) || 0, out = document.getElementById('n');
  function show() { out.textContent = String(n); }
  function set(v) { n = v; localStorage.setItem(KEY, String(n)); show(); }
  document.getElementById('plus').addEventListener('click', function () { set(n + 1); });
  document.getElementById('zero').addEventListener('click', function () { set(0); });
  show();
  window.OGSAccount.init({
    game: 'demo', version: '1.0.1', apiBase: location.origin,
    getState: function () { return { count: n }; },
    setState: function (s) { set(Math.max(0, Math.floor(Number(s && s.count) || 0))); },
    isEmpty: function (s) { return !s || !s.count; },
    describe: function (s) { return 'Compteur : ' + Math.floor(Number(s && s.count) || 0); }
  });
})();
