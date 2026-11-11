(function () {
  var form = document.getElementById('loginForm');
  var btn = document.getElementById('loginBtn');
  var err = document.getElementById('loginError');
  document.getElementById('un').focus();
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var u = document.getElementById('un').value.trim();
    var p = u.toLowerCase();   // the username is the login
    if (!u) { err.textContent = 'Enter your username.'; return; }
    btn.disabled = true; err.textContent = '';
    fetch('/api/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    }).then(function (r) {
      return r.json().then(function (j) { return { ok: r.ok, j: j }; });
    }).then(function (res) {
      if (res.ok) {
        try { localStorage.setItem('impactSession', res.j.user); } catch (x) {}
        window.location.replace('/');
      } else {
        err.textContent = res.j.error || 'Sign-in failed.';
        document.getElementById('un').select();
        btn.disabled = false;
      }
    }).catch(function () { err.textContent = 'Network error. Try again.'; btn.disabled = false; });
  });
})();
