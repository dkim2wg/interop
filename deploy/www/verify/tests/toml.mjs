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
      // A """...""" block is a TOML multi-line basic string: real newlines in
      // the file are literal, and backslash escapes (\r \n \t \\ \" ...) are
      // decoded. The fixtures encode CRLF as `\r` + a real newline, so decode
      // escapes over the joined content. Trailing \n restores the final line.
      target[key] = unescapeBasic(buf.join('\n') + '\n');
    } else if (rhs.startsWith('[')) {
      const inner = rhs.replace(/^\[/, '').replace(/\]$/, '').trim();
      target[key] = inner === '' ? [] : inner.split(',').map((s) => unquote(s.trim()));
    } else {
      target[key] = unquote(rhs);
    }
  }
  return root;
}

// Decode TOML basic-string backslash escapes. Left alone: any char that is
// not part of a recognized escape (kept verbatim, backslash included).
function unescapeBasic(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '\\') { out += s[i]; continue; }
    const c = s[++i];
    switch (c) {
      case 'r': out += '\r'; break;
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case 'u': out += String.fromCharCode(parseInt(s.slice(i + 1, i + 5), 16)); i += 4; break;
      case 'U': out += String.fromCodePoint(parseInt(s.slice(i + 1, i + 9), 16)); i += 8; break;
      default: out += '\\' + (c ?? ''); break;
    }
  }
  return out;
}

function unquote(s) {
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
    return s.slice(1, -1);
  }
  return s;
}
