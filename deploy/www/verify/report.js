// DOM renderer for the verification report. Adapted from validate.js render().
function el(tag, cls, txt) { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
function kv(label, val) { const p = el('div', 'kv'); p.textContent = label + ': ' + val; return p; }

function tagGrid(tags) {
  const g = el('div', 'tags');
  (tags || []).forEach((t) => {
    const row = el('div', 'tagrow');
    row.appendChild(el('span', 'tagname', t.tag + '='));
    row.appendChild(el('span', 'tagval', String(t.value == null ? '' : t.value)));
    g.appendChild(row);
  });
  return g;
}

export function renderReport(rep, out) {
  out.replaceChildren();
  out.appendChild(el('p', 'verdict ' + (rep.overall || 'none'), 'Overall: ' + (rep.overall || 'none')));
  if (rep.summary) out.appendChild(el('p', 'muted', rep.summary));
  (rep.levels || []).forEach((lvl) => {
    const cls = lvl.result === 'pass' ? 'pass'
      : lvl.result === 'warn' ? 'warn'
      : lvl.result === 'not-checked' ? 'notchecked' : 'fail';
    const card = el('div', 'card ' + cls);
    if (lvl.kind === 'signature') {
      card.appendChild(el('h3', null, 'DKIM2-Signature i=' + lvl.i + ' (m=' + lvl.m + ') — ' + lvl.result));
      if (lvl.tags && lvl.tags.length) card.appendChild(tagGrid(lvl.tags));
      (lvl.items || []).forEach((it) => card.appendChild(kv('crypto', it.selector + ' / ' + it.algorithm + ' → ' + (it.result || ''))));
      if (lvl.timestamp) card.appendChild(kv('timestamp', lvl.timestamp.ok ? 'ok' : ((lvl.timestamp.status || 'fail') + ' — ' + lvl.timestamp.detail)));
      if (lvl.custody) card.appendChild(kv('chain-of-custody', lvl.custody.ok ? ('ok' + (lvl.custody.detail ? ' — ' + lvl.custody.detail : '')) : ('FAIL — ' + lvl.custody.detail)));
    } else {
      card.appendChild(el('h3', null, 'Message-Instance m=' + lvl.m + ' — ' + lvl.result));
      if (lvl.tags && lvl.tags.length) card.appendChild(tagGrid(lvl.tags));
      card.appendChild(kv('header hash', lvl.header_hash));
      card.appendChild(kv('body hash', lvl.body_hash));
      (lvl.header_recipes || []).forEach((r) => card.appendChild(kv('recipe', r.name + ': "' + r.current + '" ← "' + r.previous + '"')));
      if (lvl.recipe_json !== undefined) {
        card.appendChild(kv('recipe (decoded)', ''));
        card.appendChild(el('pre', 'recipejson', JSON.stringify(lvl.recipe_json, null, 2)));
      }
      card.appendChild(kv('undo', lvl.undo));
    }
    if (lvl.detail) card.appendChild(kv('detail', lvl.detail));
    out.appendChild(card);
  });
}
