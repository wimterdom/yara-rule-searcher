/* =========================================================
   yara-lang.js — YARA 語法斷詞、著色與輕量檢查（純前端）
   ========================================================= */
(function (global) {
  'use strict';

  var KEYWORDS = ('all and any at by condition contains defined endswith entrypoint false filesize for ' +
    'global icontains iendswith iequals import in include istartswith matches meta none not of or ' +
    'percent private rule startswith strings them true with').split(' ');
  var MODIFIERS = 'ascii wide nocase fullword xor base64 base64wide private'.split(' ');
  var FUNCS = ('int8 int16 int32 uint8 uint16 uint32 int8be int16be int32be uint8be uint16be uint32be').split(' ');
  var MODULES = 'pe elf math hash dotnet console string time magic cuckoo macho dex lnk vt'.split(' ');
  var SECTIONS = ['meta', 'strings', 'condition'];
  var RESERVED = KEYWORDS.concat(MODIFIERS, FUNCS);

  var kwSet = new Set(KEYWORDS), modSet = new Set(MODIFIERS), fnSet = new Set(FUNCS),
      moduleSet = new Set(MODULES), reservedSet = new Set(RESERVED);

  function isIdStart(c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_'; }
  function isId(c) { return isIdStart(c) || (c >= '0' && c <= '9'); }
  function isDigit(c) { return c >= '0' && c <= '9'; }

  /**
   * 斷詞：回傳 [{t:type, s:start, e:end, v:value, sec, line}]
   * type: ws com str hex re var num kw mod fn module sec name tag meta id op punct bad
   */
  function tokenize(src) {
    var toks = [];
    var i = 0, n = src.length, line = 1;
    var section = null;          // meta / strings / condition / null
    var prevSig = null;          // 上一個非空白非註解 token
    var expectRuleName = false, inHeader = false;

    function push(t, s, e, extra) {
      var tok = { t: t, s: s, e: e, v: src.slice(s, e), sec: section, line: line };
      if (extra) for (var k in extra) tok[k] = extra[k];
      toks.push(tok);
      for (var p = s; p < e; p++) if (src.charCodeAt(p) === 10) line++;
      if (t !== 'ws' && t !== 'com') prevSig = tok;
      return tok;
    }

    while (i < n) {
      var c = src[i], s = i;
      // 空白
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        while (i < n && /[ \t\r\n]/.test(src[i])) i++;
        push('ws', s, i); continue;
      }
      // 註解
      if (c === '/' && src[i + 1] === '/') {
        while (i < n && src[i] !== '\n') i++;
        push('com', s, i); continue;
      }
      if (c === '/' && src[i + 1] === '*') {
        var endc = src.indexOf('*/', i + 2);
        i = endc < 0 ? n : endc + 2;
        push('com', s, i, endc < 0 ? { unterminated: true } : null); continue;
      }
      // 字串
      if (c === '"') {
        i++;
        var closed = false;
        while (i < n && src[i] !== '\n') {
          if (src[i] === '\\') { i += 2; continue; }
          if (src[i] === '"') { i++; closed = true; break; }
          i++;
        }
        push('str', s, i, closed ? null : { unterminated: true }); continue;
      }
      // 十六進位字串：= 之後的 {
      if (c === '{' && prevSig && prevSig.v === '=' && section === 'strings') {
        i++;
        var closedH = false;
        while (i < n) {
          if (src[i] === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
          if (src[i] === '/' && src[i + 1] === '*') { var ec = src.indexOf('*/', i + 2); i = ec < 0 ? n : ec + 2; continue; }
          if (src[i] === '}') { i++; closedH = true; break; }
          i++;
        }
        push('hex', s, i, closedH ? null : { unterminated: true }); continue;
      }
      // 正規表示式：= 或 matches 之後的 /
      if (c === '/' && prevSig && (prevSig.v === '=' || prevSig.v === 'matches')) {
        i++;
        var closedR = false;
        while (i < n && src[i] !== '\n') {
          if (src[i] === '\\') { i += 2; continue; }
          if (src[i] === '/') { i++; closedR = true; break; }
          i++;
        }
        while (i < n && /[isx]/.test(src[i])) i++;
        push('re', s, i, closedR ? null : { unterminated: true }); continue;
      }
      // 變數 $a #a @a !a（注意 != 運算子）
      if ((c === '$' || c === '#' || c === '@' || (c === '!' && src[i + 1] !== '=')) ) {
        i++;
        while (i < n && isId(src[i])) i++;
        if (src[i] === '*') i++;
        push('var', s, i); continue;
      }
      // 數字
      if (isDigit(c)) {
        if (c === '0' && (src[i + 1] === 'x' || src[i + 1] === 'X')) { i += 2; while (i < n && /[0-9a-fA-F]/.test(src[i])) i++; }
        else if (c === '0' && src[i + 1] === 'o') { i += 2; while (i < n && /[0-7]/.test(src[i])) i++; }
        else {
          while (i < n && isDigit(src[i])) i++;
          if (src[i] === '.' && isDigit(src[i + 1] || '')) { i++; while (i < n && isDigit(src[i])) i++; }
          if (/^(KB|MB)/.test(src.slice(i, i + 2))) i += 2;
        }
        push('num', s, i); continue;
      }
      // 識別字
      if (isIdStart(c)) {
        while (i < n && isId(src[i])) i++;
        var w = src.slice(s, i);
        var after = src.slice(i).match(/^[ \t]*(.)/);
        var nextCh = after ? after[1] : '';
        var t = 'id';
        if (expectRuleName) { t = 'name'; expectRuleName = false; inHeader = true; }
        else if (inHeader && w !== 'rule') { t = 'tag'; }
        else if (SECTIONS.indexOf(w) >= 0 && nextCh === ':') { t = 'sec'; section = w; }
        else if (w === 'rule') { t = 'kw'; expectRuleName = true; section = null; }
        else if (section === 'meta' && nextCh === '=') { t = 'meta'; }
        else if (moduleSet.has(w) && src[i] === '.') { t = 'module'; }
        else if (prevSig && prevSig.v === '.') { t = 'member'; }
        else if (kwSet.has(w)) { t = 'kw'; }
        else if (section === 'strings' && modSet.has(w)) { t = 'mod'; }
        else if (fnSet.has(w)) { t = 'fn'; }
        else if (w === 'private' || w === 'global') { t = 'kw'; }
        push(t, s, i); continue;
      }
      // 規則開頭的 { 結束標頭
      if (c === '{') { inHeader = false; expectRuleName = false; }
      if (c === '}' && section !== null) {
        // 可能是規則結束；交由 lint 判斷
      }
      // 運算子
      var two = src.slice(i, i + 2);
      if (['==', '!=', '<=', '>=', '<<', '>>', '..'].indexOf(two) >= 0) { i += 2; push('op', s, i); continue; }
      i++;
      push('punct', s, i);
      if (c === '}' && section !== null) {
        // 判斷規則是否結束：大括號深度回到 0 時重設 section（在 lint 中會更精確）
      }
    }
    return toks;
  }

  var CLS = {
    com: 't-com', str: 't-str', hex: 't-hex', re: 't-re', var: 't-var', num: 't-num', kw: 't-kw',
    mod: 't-kw', fn: 't-fn', module: 't-mod', sec: 't-sec', name: 't-name', tag: 't-tag', meta: 't-meta'
  };

  function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function highlight(src) {
    var toks = tokenize(src), out = [];
    for (var k = 0; k < toks.length; k++) {
      var tk = toks[k], cls = CLS[tk.t];
      if (tk.unterminated) cls = (cls ? cls + ' ' : '') + 't-bad';
      if (tk.t === 'hex' && tk.v.indexOf('/') >= 0) {
        out.push('<span class="' + cls + '">' + esc(tk.v).replace(/(\/\/[^\n]*|\/\*[\s\S]*?\*\/)/g, '<span class="t-com">$1</span>') + '</span>');
        continue;
      }
      out.push(cls ? '<span class="' + cls + '">' + esc(tk.v) + '</span>' : esc(tk.v));
    }
    return out.join('');
  }

  /* ---------- 規則結構切分 ---------- */
  function splitRules(src, toks) {
    toks = toks || tokenize(src);
    var rules = [], imports = [], depth = 0, cur = null;
    for (var k = 0; k < toks.length; k++) {
      var tk = toks[k];
      if (tk.t === 'ws' || tk.t === 'com') continue;
      if (tk.t === 'kw' && tk.v === 'import' && depth === 0) {
        var nx = nextSig(toks, k);
        if (nx && toks[nx].t === 'str') imports.push({ name: toks[nx].v.replace(/"/g, ''), line: tk.line, tokIdx: k });
        continue;
      }
      if (tk.t === 'name' && depth === 0) {
        cur = { name: tk.v, line: tk.line, start: findRuleStart(toks, k), toks: [], sections: {}, strings: [], braceOpen: false, closed: false, nameTok: tk };
        rules.push(cur);
        continue;
      }
      if (tk.v === '{' && tk.t === 'punct') {
        depth++;
        if (cur && depth === 1) cur.braceOpen = true;
        continue;
      }
      if (tk.v === '}' && tk.t === 'punct') {
        depth--;
        if (depth === 0 && cur) { cur.closed = true; cur.endLine = tk.line; cur = null; }
        if (depth < 0) depth = 0;
        continue;
      }
      if (cur) {
        cur.toks.push(tk);
        if (tk.t === 'sec') cur.sections[tk.v] = tk.line;
      }
    }
    return { rules: rules, imports: imports, depthLeft: depth };
  }
  function nextSig(toks, k) {
    for (var j = k + 1; j < toks.length; j++) if (toks[j].t !== 'ws' && toks[j].t !== 'com') return j;
    return -1;
  }
  function findRuleStart(toks, k) {
    // 往回找 rule 關鍵字（及 private/global）
    var line = toks[k].line;
    for (var j = k - 1; j >= 0; j--) {
      if (toks[j].t === 'ws') continue;
      if (toks[j].t === 'kw' && (toks[j].v === 'rule' || toks[j].v === 'private' || toks[j].v === 'global')) { line = toks[j].line; continue; }
      break;
    }
    return line;
  }

  /**
   * 輕量檢查。knownRule(name) 可回傳外部資料庫中是否存在該規則（用於相依提示）
   * 回傳 [{level:'error'|'warning'|'info', line, msg, fix?:{type, data}}]
   */
  function lint(src, opts) {
    opts = opts || {};
    var issues = [];
    if (!src.trim()) return issues;
    var toks = tokenize(src);
    var info = splitRules(src, toks);

    toks.forEach(function (tk) {
      if (tk.unterminated) {
        var what = { str: '字串', hex: '十六進位字串', re: '正規表示式', com: '區塊註解' }[tk.t] || '內容';
        issues.push({ level: 'error', line: tk.line, msg: what + '未結束（缺少結尾符號）' });
      }
    });

    // 大括號平衡
    var bal = 0, lastOpen = 1;
    toks.forEach(function (tk) {
      if (tk.t !== 'punct') return;
      if (tk.v === '{') { bal++; lastOpen = tk.line; }
      if (tk.v === '}') { bal--; if (bal < 0) { issues.push({ level: 'error', line: tk.line, msg: '多出一個「}」' }); bal = 0; } }
    });
    if (bal > 0) issues.push({ level: 'error', line: lastOpen, msg: '大括號未閉合，缺少 ' + bal + ' 個「}」' });

    if (!info.rules.length) {
      issues.push({ level: 'error', line: 1, msg: '找不到任何 rule 定義' });
      return finish(issues);
    }

    var names = {};
    var definedRules = new Set(info.rules.map(function (r) { return r.name; }));
    var importSet = new Set(info.imports.map(function (x) { return x.name; }));
    var missingModules = {};

    info.rules.forEach(function (r) {
      if (names[r.name]) issues.push({ level: 'error', line: r.line, msg: '規則名稱重複：' + r.name });
      names[r.name] = true;
      if (reservedSet.has(r.name)) issues.push({ level: 'error', line: r.line, msg: '規則名稱不可使用保留字：' + r.name });
      if (r.name.length > 128) issues.push({ level: 'error', line: r.line, msg: '規則名稱超過 128 字元' });
      if (!r.sections.condition) issues.push({ level: 'error', line: r.line, msg: r.name + ' 缺少 condition: 區段' });

      // 區段順序
      var order = SECTIONS.filter(function (s) { return r.sections[s]; });
      for (var q = 1; q < order.length; q++) {
        if (r.sections[order[q]] < r.sections[order[q - 1]]) {
          issues.push({ level: 'error', line: r.sections[order[q]], msg: r.name + '：區段順序須為 meta → strings → condition' });
          break;
        }
      }

      // 字串定義與引用
      var defs = {}, refs = [], usesThem = false, metaKeys = {}, anon = 0, locals = new Set();
      var toksR = r.toks;
      // 先收集 for … in / with … = 的區域變數
      for (var a = 0; a < toksR.length; a++) {
        var ta = toksR[a];
        if (ta.sec !== 'condition' || ta.t !== 'kw') continue;
        if (ta.v === 'for') {
          for (var b = a + 1; b < toksR.length && b < a + 40; b++) {
            var tb = toksR[b];
            if (tb.t === 'kw' && (tb.v === 'in' || tb.v === 'of')) break;
            if (tb.v === ':') break;
            if (tb.t === 'id') locals.add(tb.v);
          }
        } else if (ta.v === 'with') {
          for (var c2 = a + 1; c2 < toksR.length; c2++) {
            var tc = toksR[c2];
            if (tc.v === ':') break;
            if (tc.t === 'id') {
              var nn = null;
              for (var c3 = c2 + 1; c3 < toksR.length; c3++) { if (toksR[c3].t !== 'ws' && toksR[c3].t !== 'com') { nn = toksR[c3]; break; } }
              if (nn && nn.v === '=') locals.add(tc.v);
            }
          }
        }
      }
      for (var k = 0; k < toksR.length; k++) {
        var tk = toksR[k];
        if (tk.sec === 'strings' && tk.t === 'var' && tk.v[0] === '$') {
          var nx = null;
          for (var j = k + 1; j < toksR.length; j++) { if (toksR[j].t !== 'ws' && toksR[j].t !== 'com') { nx = toksR[j]; break; } }
          if (nx && nx.v === '=') {
            var id = tk.v.slice(1);
            if (!id) anon++;
            if (id && defs[id]) issues.push({ level: 'error', line: tk.line, msg: r.name + '：字串識別字重複 $' + id });
            if (id) defs[id] = tk.line;
            var val = null;
            for (var j2 = j + 1; j2 < toksR.length; j2++) { if (toksR[j2].t !== 'ws' && toksR[j2].t !== 'com') { val = toksR[j2]; break; } }
            if (val && val.t === 'str' && val.v === '""') issues.push({ level: 'error', line: tk.line, msg: r.name + '：$' + id + ' 為空字串' });
          }
        }
        if (tk.sec === 'meta' && tk.t === 'meta') metaKeys[tk.v] = true;
        if (tk.sec === 'condition') {
          if (tk.t === 'var') refs.push(tk);
          if (tk.t === 'kw' && tk.v === 'them') usesThem = true;
          if (tk.t === 'module' && !importSet.has(tk.v)) {
            missingModules[tk.v] = missingModules[tk.v] || tk.line;
          }
          if (tk.t === 'id' && !locals.has(tk.v)) {
            if (!definedRules.has(tk.v)) {
              var known = opts.knownRule && opts.knownRule(tk.v);
              if (known) issues.push({ level: 'warning', line: tk.line, msg: r.name + ' 引用了規則 ' + tk.v + '，但它不在編輯器中', fix: { type: 'addRule', data: tk.v, label: '插入 ' + tk.v } });
              else issues.push({ level: 'warning', line: tk.line, msg: r.name + '：未定義的識別字「' + tk.v + '」（若為外部變數請於編譯時以 -d 指定）' });
            }
          }
        }
      }
      var wild = [], used = {};
      refs.forEach(function (rf) {
        var nm = rf.v.slice(1);
        if (!nm) return;                          // $ / # 匿名（for..of 迴圈內）
        if (nm.slice(-1) === '*') { wild.push(nm.slice(0, -1)); return; }
        used[nm] = true;
        if (!defs[nm] && !(nm in defs)) issues.push({ level: 'error', line: rf.line, msg: r.name + '：條件引用了未定義的字串 ' + rf.v[0] + nm });
      });
      if (!usesThem) {
        Object.keys(defs).forEach(function (d) {
          if (used[d]) return;
          if (wild.some(function (p) { return d.indexOf(p) === 0; })) return;
          issues.push({ level: 'error', line: defs[d], msg: r.name + '：字串 $' + d + ' 未在條件中使用（YARA 會拒絕編譯）' });
        });
      }
      if (r.sections.strings && !Object.keys(defs).length && !anon) {
        issues.push({ level: 'warning', line: r.sections.strings, msg: r.name + '：strings 區段是空的' });
      }
      if (!r.closed) issues.push({ level: 'error', line: r.line, msg: r.name + ' 沒有以「}」結束' });
      if (!metaKeys.description) issues.push({ level: 'info', line: r.line, msg: r.name + '：建議在 meta 加入 description' });
      if (!metaKeys.author) issues.push({ level: 'info', line: r.line, msg: r.name + '：建議在 meta 加入 author' });
    });

    var mm = Object.keys(missingModules);
    if (mm.length) {
      issues.push({ level: 'error', line: missingModules[mm[0]], msg: '使用了模組 ' + mm.join('、') + ' 但沒有 import', fix: { type: 'addImports', data: mm, label: '補上 import' } });
    }
    return finish(issues);

    function finish(list) {
      var w = { error: 0, warning: 1, info: 2 };
      return list.sort(function (a, b) { return (w[a.level] - w[b.level]) || (a.line - b.line); });
    }
  }

  global.YaraLang = {
    tokenize: tokenize, highlight: highlight, lint: lint, splitRules: splitRules,
    MODULES: MODULES, escape: esc
  };
})(window);
