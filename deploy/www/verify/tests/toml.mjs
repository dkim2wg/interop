// Minimal TOML reader for the dkim2tests fixture subset. TEST-ONLY.
// Supports: Key = 'single', Key = """multiline""", Key = ['a','b'],
// and [Table] sections with 'quoted.key' = 'value'. Not a general parser.
export function parseToml(text) {
  const lines = text.split('\n');
  const root = {};
  let target = root;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const tableMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (tableMatch) { target = root[tableMatch[1]] = {}; continue; }

    const eq = line.indexOf('=');
    if (eq < 0) continue;
    let key = line.slice(0, eq).trim();
    if (key.startsWith("'") && key.endsWith("'")) key = key.slice(1, -1);
    let rhs = line.slice(eq + 1).trim();

    if (rhs.startsWith('"""')) {
      // Multiline: content runs until a line that is exactly """.
      const buf = [];
      for (i++; i < lines.length; i++) {
        if (lines[i].trim() === '"""') break;
        buf.push(lines[i]);
      }
      // Fixture multiline lines already end with a literal \r; join with \n
      // and append a trailing \n for the final line.
      target[key] = buf.join('\n') + '\n';
    } else if (rhs.startsWith('[')) {
      const inner = rhs.replace(/^\[/, '').replace(/\]$/, '').trim();
      target[key] = inner === '' ? [] : inner.split(',').map((s) => unquote(s.trim()));
    } else {
      target[key] = unquote(rhs);
    }
  }
  return root;
}

function unquote(s) {
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
    return s.slice(1, -1);
  }
  return s;
}
