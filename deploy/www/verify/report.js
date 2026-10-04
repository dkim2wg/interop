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

// Decoded view of the Recipe's "b" steps (base64 literals for octets that
// are not JSON text, §5 extension): one line per item, as text with U+FFFD
// where the octets are not UTF-8. The JSON view above keeps the base64.
function bStepLines(rec) {
  const lines = [];
  const dec = new TextDecoder();
  const add = (where, steps) => {
    if (!Array.isArray(steps)) return;
    steps.forEach((st) => {
      if (!st || typeof st !== 'object' || !Array.isArray(st.b)) return;
      st.b.forEach((item) => {
        let text;
        try { text = dec.decode(Uint8Array.from(atob(String(item)), (c) => c.charCodeAt(0))); } catch (e) { text = '(not base64)'; }
        lines.push(where + ': "' + text + '"');
      });
    });
  };
  if (rec && typeof rec === 'object') {
    if (rec.h && typeof rec.h === 'object') Object.keys(rec.h).sort().forEach((n) => add(n, rec.h[n]));
    add('body', rec.b);
  }
  return lines;
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
        bStepLines(lvl.recipe_json).forEach((line) => card.appendChild(kv('recipe "b" (decoded)', line)));
      }
      card.appendChild(kv('undo', lvl.undo));
    }
    if (lvl.detail) card.appendChild(kv('detail', lvl.detail));
    out.appendChild(card);
  });
}
