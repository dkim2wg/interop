(function () {
  var out = document.getElementById('out');
  var ta = document.getElementById('msg');

  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
  function kv(label, val) { var p = el('div', 'kv'); p.textContent = label + ': ' + val; return p; }

  // Compact grid of every parsed tag: "name=  label  value".
  function tagGrid(tags) {
    var g = el('div', 'tags');
    (tags || []).forEach(function (t) {
      var row = el('div', 'tagrow');
      row.appendChild(el('span', 'tagname', t.tag + '='));
      row.appendChild(el('span', 'taglabel', t.label || ''));
      var v = el('span', 'tagval', String(t.value == null ? '' : t.value));
      if (t.decoded) v.title = 'decoded from base64';
      row.appendChild(v);
      g.appendChild(row);
    });
    return g;
  }

  function render(rep) {
    out.replaceChildren();
    var verdict = el('p', 'verdict ' + (rep.overall || 'none'), 'Overall: ' + (rep.overall || 'none'));
    out.appendChild(verdict);
    if (rep.summary) out.appendChild(el('p', 'muted', rep.summary));
    (rep.levels || []).forEach(function (lvl) {
      var cls = lvl.result === 'pass' ? 'pass'
              : lvl.result === 'warn' ? 'warn'
              : lvl.result === 'not-checked' ? 'notchecked' : 'fail';
      var card = el('div', 'card ' + cls);
      if (lvl.kind === 'signature') {
        card.appendChild(el('h3', null, 'DKIM2-Signature i=' + lvl.i + ' (m=' + lvl.m + ') — ' + lvl.result));
        // Full parsed tag breakdown.
        if (lvl.tags && lvl.tags.length) card.appendChild(tagGrid(lvl.tags));
        // Verification status lines.
        (lvl.items || []).forEach(function (it) { card.appendChild(kv('crypto', it.selector + ' / ' + it.algorithm + ' → ' + (it.result || ''))); });
        if (lvl.timestamp) card.appendChild(kv('timestamp', lvl.timestamp.ok ? 'ok' : ((lvl.timestamp.status || 'fail') + ' — ' + lvl.timestamp.detail)));
        if (lvl.custody) card.appendChild(kv('chain-of-custody', lvl.custody.ok ? ('ok' + (lvl.custody.detail ? ' — ' + lvl.custody.detail : '')) : ('FAIL — ' + lvl.custody.detail)));
      } else {
        card.appendChild(el('h3', null, 'Message-Instance m=' + lvl.m + ' — ' + lvl.result));
        // Full parsed tag breakdown.
        if (lvl.tags && lvl.tags.length) card.appendChild(tagGrid(lvl.tags));
        // Verification status lines.
        card.appendChild(kv('header hash', lvl.header_hash));
        card.appendChild(kv('body hash', lvl.body_hash));
        (lvl.header_recipes || []).forEach(function (r) {
          card.appendChild(kv('recipe', r.name + ': "' + r.current + '" ← "' + r.previous + '"'));
        });
        card.appendChild(kv('undo', lvl.undo));
      }
      if (lvl.detail) card.appendChild(kv('detail', lvl.detail));
      out.appendChild(card);
    });
  }

  function validate() {
    out.replaceChildren(el('p', 'muted', 'Validating…'));
    fetch('/validate/api', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: ta.value })
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function (e) { out.replaceChildren(el('p', 'verdict fail', 'Request failed: ' + e)); });
  }

  document.getElementById('go').addEventListener('click', validate);
  document.getElementById('example').addEventListener('click', function (ev) {
    ev.preventDefault();
    ta.value = 'Paste a real DKIM2-signed message here.\n(Tip: send mail through one of the reflector addresses, then paste the reply.)\n';
  });
})();
