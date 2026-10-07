/* =========================================================
   YARA Rule Searcher — 主程式
   資料：window.YARA_DB（data/yara-db.js）或 window.YARA_DB_GZ（獨立單檔版）
   ========================================================= */
(function () {
  'use strict';

  var Y = window.YaraLang;
  var F = { name: 0, tier: 1, repo: 2, score: 3, quality: 4, date: 5, modified: 6, author: 7, desc: 8, tags: 9,
            modules: 10, deps: 11, priv: 12, ref: 13, src: 14, lic: 15, id: 16, nstr: 17, text: 18 };
  var TIER_NAMES = ['Core', 'Extended', 'Full'];
  var PAGE = 100;

  var $ = function (id) { return document.getElementById(id); };
  var app = $('app');

  var db, R, repos, nameIndex = new Map();
  var hayL = [], nameL = [], bodyL = null;
  var state = {
    q: '', tier: 2, repo: '', minScore: 0, sort: 'auto', body: false,
    results: [], shown: 0, sel: -1, terms: []
  };

  /* ---------------- 小工具 ---------------- */
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function fmt(n) { return Number(n).toLocaleString('en-US'); }
  function reEsc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function isUrl(s) { return /^https?:\/\//i.test(s || ''); }
  function sevColor(score) { return score >= 80 ? 'var(--hi)' : score >= 60 ? 'var(--mid)' : 'var(--lo)'; }
  function debounce(fn, ms) { var t; return function () { var a = arguments, c = this; clearTimeout(t); t = setTimeout(function () { fn.apply(c, a); }, ms); }; }

  var toastTimer;
  function toast(msg) {
    var t = $('toast'); t.textContent = msg; t.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { t.classList.remove('show'); }, 2200);
  }

  function copyText(text) {
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', '');
      ta.style.position = 'fixed'; ta.style.top = '-1000px'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      return ok;
    }
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return fallback(); });
    }
    return Promise.resolve(fallback());
  }
  function flashButton(btn, label) {
    var span = btn.querySelector('span');
    var old = span ? span.textContent : btn.textContent;
    btn.classList.add('done');
    if (span) span.textContent = label; else btn.textContent = label;
    setTimeout(function () { btn.classList.remove('done'); if (span) span.textContent = old; else btn.textContent = old; }, 1500);
  }

  /* 下載：在 claude.ai Artifact 中使用 downloads 能力，其餘環境使用一般下載 */
  var downloadsCap;
  var downloadsReady = (window.claude && typeof window.claude.use === 'function')
    ? window.claude.use('downloads').then(function (c) { downloadsCap = c; return c; }, function () { downloadsCap = null; return null; })
    : Promise.resolve(null);
  function saveFile(filename, text) {
    return downloadsReady.then(function (cap) {
      if (cap) {
        var fn = /\.(txt|json|md)$/i.test(filename) ? filename : filename + '.txt';
        return cap.save({ filename: fn, data: text }).then(function () { toast('已下載 ' + fn); }, function (e) {
          if (e && e.code === 'declined') return;
          toast('無法下載：' + ((e && e.message) || '此環境不支援'));
        });
      }
      var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = filename;
      document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      toast('已下載 ' + filename);
    });
  }

  /* ---------------- 主題 ---------------- */
  function currentTheme() {
    var t = document.documentElement.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  $('themeBtn').addEventListener('click', function () {
    var next = currentTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    store('yrs-theme', next);
    toast(next === 'dark' ? '已切換為夜間模式' : '已切換為日間模式');
  });

  /* ---------------- 資料載入 ---------------- */
  function loadDB() {
    if (window.YARA_DB) return Promise.resolve(window.YARA_DB);
    if (window.YARA_DB_GZ) {
      $('loadingText').textContent = '正在解壓縮規則庫…';
      return new Promise(function (res) { setTimeout(res, 30); }).then(function () {
        var bin = atob(window.YARA_DB_GZ), u8 = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        window.YARA_DB_GZ = null;
        var stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip'));
        return new Response(stream).text();
      }).then(function (txt) { return JSON.parse(txt); });
    }
    return new Promise(function (res, rej) {
      var s = document.createElement('script');
      s.src = 'data/yara-db.js';
      s.onload = function () {
        if (!window.YARA_DB) return rej(new Error('資料檔內容不正確'));
        if (/^https?:$/.test(location.protocol)) $('offlineLink').hidden = false;
        res(window.YARA_DB);
      };
      s.onerror = function () { rej(new Error('找不到 data/yara-db.js')); };
      document.head.appendChild(s);
    });
  }

  function init(data) {
    db = data; R = db.rules; repos = db.repos;
    for (var i = 0; i < R.length; i++) {
      var r = R[i];
      nameIndex.set(r[F.name], i);
      nameL[i] = r[F.name].toLowerCase();
      hayL[i] = (r[F.name] + '\n' + r[F.desc] + '\n' + r[F.author] + '\n' + r[F.tags] + '\n' +
        (repos[r[F.repo]] ? repos[r[F.repo]].name : '') + '\n' + r[F.ref] + '\n' + r[F.id]).toLowerCase();
    }
    $('releaseLabel').textContent = 'YARA Forge 版本 ' + db.release + '，共 ' + fmt(R.length) + ' 條規則';
    document.querySelectorAll('.seg-n').forEach(function (el) {
      var n = db.tier_counts[['core', 'extended', 'full'][+el.dataset.n]];
      el.textContent = fmt(n);
    });
    var opts = repos.map(function (r, i) { return { i: i, name: r.name, c: r.count }; })
      .sort(function (a, b) { return b.c - a.c; });
    $('repoSel').insertAdjacentHTML('beforeend', opts.map(function (o) {
      return '<option value="' + o.i + '">' + esc(o.name) + '（' + fmt(o.c) + '）</option>';
    }).join(''));
    renderEmptyDetail();
    renderAbout();
    restorePrefs();
    route();
    runSearch();
    ed.refresh();
    var ld = $('loading'); ld.classList.add('gone'); setTimeout(function () { ld.remove(); }, 400);
  }

  /* ---------------- 搜尋 ---------------- */
  var FIELD_ALIAS = { name: 'name', repo: 'repo', source: 'repo', src: 'repo', author: 'author', tag: 'tag', tags: 'tag',
                      desc: 'desc', description: 'desc', mod: 'mod', module: 'mod', id: 'id', score: 'score', quality: 'quality' };
  var HASH_RE = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;

  function parseQuery(q) {
    var out = [], m;
    var re = /(-)?(?:([A-Za-z]+)(>=|<=|>|<|:|=))?(?:"([^"]*)"|(\S+))/g;
    while ((m = re.exec(q))) {
      var neg = !!m[1], field = m[2] ? FIELD_ALIAS[m[2].toLowerCase()] : null, op = m[3];
      var val = m[4] != null ? m[4] : (m[5] || '');
      if (m[2] && !field) { field = null; val = m[0].replace(/^-/, '').replace(/"/g, ''); }
      if (!val) continue;
      out.push({ neg: neg, field: field, op: op, v: val.toLowerCase(), raw: val });
    }
    return out;
  }
  function ensureBody() {
    if (bodyL) return;
    bodyL = new Array(R.length);
    for (var i = 0; i < R.length; i++) bodyL[i] = R[i][F.text].toLowerCase();
  }
  function cmpNum(a, op, b) {
    switch (op) { case '>': return a > b; case '<': return a < b; case '<=': return a <= b; case '=': return a === b; default: return a >= b; }
  }

  function runSearch() {
    if (!db) return;
    var terms = parseQuery(state.q);
    state.terms = terms.filter(function (t) { return !t.neg && (!t.field || t.field === 'name' || t.field === 'desc'); }).map(function (t) { return t.raw; });
    var needBody = state.body || terms.some(function (t) { return !t.field && HASH_RE.test(t.v); });
    if (needBody) ensureBody();
    var plain = terms.some(function (t) { return !t.field && !t.neg; });
    var res = [], rel = [];
    var repoF = state.repo === '' ? -1 : +state.repo;

    for (var i = 0; i < R.length; i++) {
      var r = R[i];
      if (r[F.tier] > state.tier) continue;
      if (repoF >= 0 && r[F.repo] !== repoF) continue;
      if (r[F.score] < state.minScore) continue;
      var ok = true, score = 0;
      for (var k = 0; k < terms.length && ok; k++) {
        var t = terms[k], hit = false, v = t.v;
        switch (t.field) {
          case 'name': hit = nameL[i].indexOf(v) >= 0; if (hit) score += 30; break;
          case 'repo': hit = repos[r[F.repo]] && repos[r[F.repo]].name.toLowerCase().indexOf(v) >= 0; break;
          case 'author': hit = r[F.author].toLowerCase().indexOf(v) >= 0; break;
          case 'tag': hit = (' ' + r[F.tags].toLowerCase() + ' ').indexOf(v) >= 0; break;
          case 'desc': hit = r[F.desc].toLowerCase().indexOf(v) >= 0; if (hit) score += 10; break;
          case 'mod': hit = r[F.modules].indexOf(v) >= 0; break;
          case 'id': hit = r[F.id].toLowerCase().indexOf(v) >= 0; break;
          case 'score': hit = cmpNum(r[F.score], t.op, parseFloat(v)); break;
          case 'quality': hit = cmpNum(r[F.quality], t.op, parseFloat(v)); break;
          default:
            if (nameL[i] === v) { hit = true; score += 100; }
            else if (nameL[i].indexOf(v) >= 0) { hit = true; score += nameL[i].indexOf(v) === 0 ? 60 : 40; }
            else if (hayL[i].indexOf(v) >= 0) { hit = true; score += r[F.desc].toLowerCase().indexOf(v) >= 0 ? 15 : 8; }
            else if (needBody && bodyL[i].indexOf(v) >= 0) { hit = true; score += 3; }
        }
        ok = t.neg ? !hit : hit;
      }
      if (!ok) continue;
      res.push(i);
      rel[i] = score + r[F.score] / 25;
    }

    var mode = state.sort === 'auto' ? (plain ? 'rel' : 'modified') : state.sort;
    res.sort(function (a, b) {
      var ra = R[a], rb = R[b];
      if (mode === 'rel') return (rel[b] - rel[a]) || (rb[F.score] - ra[F.score]) || (ra[F.name] < rb[F.name] ? -1 : 1);
      if (mode === 'score') return (rb[F.score] - ra[F.score]) || (ra[F.name] < rb[F.name] ? -1 : 1);
      if (mode === 'modified') return (rb[F.modified] || rb[F.date]).localeCompare(ra[F.modified] || ra[F.date]) || (ra[F.name] < rb[F.name] ? -1 : 1);
      return ra[F.name].localeCompare(rb[F.name]);
    });
    state.results = res;
    state.shown = 0;
    $('results').innerHTML = '';
    renderCount();
    renderMore();
    if (!res.length) renderNoResult();
  }

  function renderCount() {
    var n = state.results.length;
    var scope = TIER_NAMES[state.tier] + ' 套件';
    $('resultCount').innerHTML = n ? '<b>' + fmt(n) + '</b> 條規則符合（' + scope + '）' : '沒有符合的規則（' + scope + '）';
    $('exportBtn').hidden = !n;
  }

  function renderNoResult() {
    var hint = state.tier < 2 ? '目前只搜尋 ' + TIER_NAMES[state.tier] + ' 套件，切換到 Full 可搜尋全部規則。'
      : (!state.body ? '試著勾選「一併搜尋規則內容」，或減少關鍵字。' : '試著減少關鍵字，或移除來源與分數篩選。');
    $('results').innerHTML = '';
    var box = document.createElement('div');
    box.className = 'no-result'; box.id = 'noResult';
    box.innerHTML = '<h3>找不到「' + esc(state.q) + '」</h3><p>' + hint + '</p>';
    var old = $('noResult'); if (old) old.remove();
    $('results').after(box);
  }

  function markText(text, terms) {
    if (!terms.length || !text) return esc(text);
    var re = new RegExp('(' + terms.map(reEsc).join('|') + ')', 'ig');
    return String(text).split(re).map(function (part, i) { return i % 2 ? '<mark>' + esc(part) + '</mark>' : esc(part); }).join('');
  }

  function rowHTML(i) {
    var r = R[i], sev = sevColor(r[F.score]);
    var repo = repos[r[F.repo]] ? repos[r[F.repo]].name : '';
    return '<li class="r-item" role="option" id="ri-' + i + '" data-i="' + i + '" style="--sev:' + sev + '" aria-selected="' + (i === state.sel) + '">' +
      '<div class="r-name">' + markText(r[F.name], state.terms) + '</div>' +
      (r[F.desc] ? '<p class="r-desc">' + markText(r[F.desc], state.terms) + '</p>' : '') +
      '<div class="r-row"><span class="r-score" title="分數">' + r[F.score] + '</span>' +
      '<span class="chip">' + esc(repo) + '</span>' +
      '<span class="chip tier-' + r[F.tier] + '">' + TIER_NAMES[r[F.tier]] + '</span>' +
      (r[F.modified] ? '<span>' + esc(r[F.modified]) + '</span>' : '') +
      '</div></li>';
  }

  function renderMore() {
    var old = $('noResult'); if (old) old.remove();
    var from = state.shown, to = Math.min(state.results.length, from + PAGE);
    var html = '';
    for (var k = from; k < to; k++) html += rowHTML(state.results[k]);
    $('results').insertAdjacentHTML('beforeend', html);
    state.shown = to;
    var left = state.results.length - to;
    $('moreBtn').hidden = left <= 0;
    $('moreBtn').textContent = '顯示更多（尚有 ' + fmt(left) + ' 條）';
  }

  /* ---------------- 規則組合（含 import 與相依規則） ---------------- */
  function collectOrder(list) {
    var seen = new Set(), order = [];
    function visit(k) {
      if (seen.has(k)) return; seen.add(k);
      R[k][F.deps].forEach(visit);
      order.push(k);
    }
    list.forEach(visit);
    return order;
  }
  function bundleText(list, withExtras, header) {
    var order = withExtras ? collectOrder(list) : list.slice();
    var mods = new Set();
    if (withExtras) order.forEach(function (k) { R[k][F.modules].forEach(function (m) { mods.add(m); }); });
    var parts = [];
    if (header) parts.push(header);
    if (mods.size) parts.push(Array.from(mods).sort().map(function (m) { return 'import "' + m + '"'; }).join('\n'));
    parts.push(order.map(function (k) { return R[k][F.text]; }).join('\n\n'));
    return parts.join('\n\n') + '\n';
  }
  function ruleBundle(i) { return bundleText([i], $('bundleChk').checked); }

  /* ---------------- 詳細資料 ---------------- */
  function select(i, opts) {
    opts = opts || {};
    var prev = document.querySelector('.r-item[aria-selected="true"]');
    if (prev) prev.setAttribute('aria-selected', 'false');
    state.sel = i;
    var el = $('ri-' + i);
    if (el) { el.setAttribute('aria-selected', 'true'); if (opts.scroll) el.scrollIntoView({ block: 'nearest' }); }
    renderDetail(i);
    if (!opts.noHash) setHash('#/rule/' + encodeURIComponent(R[i][F.name]));
    if (opts.openSheet && window.matchMedia('(max-width: 860px)').matches) app.classList.add('show-detail');
  }

  function renderDetail(i) {
    var r = R[i], repo = repos[r[F.repo]] || { name: '', url: '' };
    $('detailEmpty').hidden = true; $('detailBody').hidden = false;
    $('detail').scrollTop = 0;
    $('dName').textContent = r[F.name];
    var b = '<span class="score-pill" style="--sev:' + sevColor(r[F.score]) + '"><b>' + r[F.score] + '</b>分數</span>' +
      '<span class="chip tier-' + r[F.tier] + '" title="最小可取得的套件">' + TIER_NAMES[r[F.tier]] + '</span>' +
      '<span class="chip">' + esc(repo.name) + '</span>' +
      '<span class="chip" title="YARA Forge 品質評分">品質 ' + r[F.quality] + '</span>';
    if (r[F.priv]) b += '<span class="chip priv">private 規則</span>';
    r[F.modules].forEach(function (m) { b += '<span class="chip mod">' + esc(m) + '</span>'; });
    r[F.tags].split(' ').filter(Boolean).forEach(function (t) { b += '<span class="chip">#' + esc(t) + '</span>'; });
    $('dBadges').innerHTML = b;
    $('dDesc').textContent = r[F.desc] || '（此規則沒有描述）';
    $('dDesc').style.color = r[F.desc] ? '' : 'var(--muted)';

    var order = collectOrder([i]);
    var deps = order.filter(function (k) { return k !== i; });
    var note = '';
    if (deps.length) {
      note = '此規則引用了 ' + deps.map(function (k) { return R[k][F.name]; }).join('、') + '。' +
        ($('bundleChk').checked ? '複製與下載時會一併附上，可直接編譯。' : '目前未附上相依規則，單獨編譯會失敗。');
    } else if (r[F.modules].length && !$('bundleChk').checked) {
      note = '此規則使用 ' + r[F.modules].join('、') + ' 模組，目前未附上 import 陳述式。';
    }
    $('dNote').hidden = !note; $('dNote').textContent = note;

    var meta = [];
    function row(k, v, cls) { if (v) meta.push('<dt>' + k + '</dt><dd' + (cls ? ' class="' + cls + '"' : '') + '>' + v + '</dd>'); }
    function link(u, label) { return isUrl(u) ? '<a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(label || u) + '</a>' : esc(u); }
    row('作者', esc(r[F.author]));
    row('建立日期', esc(r[F.date]));
    row('修改日期', esc(r[F.modified]));
    row('參考資料', r[F.ref] ? link(r[F.ref]) : '');
    row('來源專案', link(repo.url, repo.name));
    row('原始檔', r[F.src] ? link(r[F.src], '在 GitHub 檢視原始規則') : '');
    row('授權', r[F.lic] ? link(r[F.lic], '檢視授權條款') : '');
    row('規則 ID', esc(r[F.id]), 'mono');
    row('字串數', String(r[F.nstr]));
    $('dMeta').innerHTML = meta.join('');

    var text = r[F.text];
    var lines = text.split('\n').length;
    $('dLines').textContent = lines + ' 行，' + fmt(text.length) + ' 字元';
    var g = []; for (var n = 1; n <= lines; n++) g.push(n);
    $('dGutter').textContent = g.join('\n');
    $('dSrc').innerHTML = Y.highlight(text);
  }

  function renderEmptyDetail() {
    var ex = [
      ['Cobalt Strike', 'Cobalt Strike'],
      ['ransomware score>=80', '高分勒索軟體'],
      ['repo:LOLDrivers', '易受攻擊驅動程式'],
      ['mod:dotnet', '使用 dotnet 模組'],
      ['tag:MEMORY', '記憶體掃描'],
      ['webshell -php', '非 PHP 的 Webshell'],
      ['09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669', '以樣本雜湊反查']
    ];
    $('examples').innerHTML = ex.map(function (e) {
      return '<button class="ex-btn" type="button" data-q="' + esc(e[0]) + '" title="' + esc(e[0]) + '">' + esc(e[1]) + '</button>';
    }).join('');
    var tc = db.tier_counts;
    $('stats').innerHTML =
      '<div><dt>Core 套件</dt><dd>' + fmt(tc.core) + '</dd></div>' +
      '<div><dt>Extended 套件</dt><dd>' + fmt(tc.extended) + '</dd></div>' +
      '<div><dt>Full 套件</dt><dd>' + fmt(tc.full) + '</dd></div>' +
      '<div><dt>來源專案</dt><dd>' + repos.length + '</dd></div>' +
      '<div><dt>釋出日期</dt><dd>' + esc(db.creation_date || db.release) + '</dd></div>';
    var top = repos.map(function (r, i) { return { i: i, r: r }; }).sort(function (a, b) { return b.r.count - a.r.count; }).slice(0, 8);
    var max = top[0].r.count;
    var list = document.createElement('ul');
    list.className = 'top-repos';
    list.innerHTML = top.map(function (t) {
      return '<li><button type="button" data-repo="' + t.i + '" title="只看 ' + esc(t.r.name) + ' 的規則">' + esc(t.r.name) + '</button>' +
        '<span class="bar"><span style="width:' + (t.r.count / max * 100).toFixed(1) + '%"></span></span><span class="n">' + fmt(t.r.count) + '</span></li>';
    }).join('');
    $('stats').after(list);
    $('detailEmpty').addEventListener('click', function (e) {
      var q = e.target.closest('[data-q]');
      if (q) { $('q').value = q.dataset.q; state.q = q.dataset.q; runSearch(); if (state.results.length) select(state.results[0], { scroll: true, openSheet: true }); return; }
      var rp = e.target.closest('[data-repo]');
      if (rp) { $('repoSel').value = rp.dataset.repo; state.repo = rp.dataset.repo; runSearch(); }
    });
  }

  function renderAbout() {
    $('aboutIntro').innerHTML = '本站的規則來自 <a href="https://github.com/YARAHQ/yara-forge/releases/tag/' + esc(db.release) + '" target="_blank" rel="noopener">YARA Forge ' + esc(db.release) +
      '</a>（YARA-Forge ' + esc(db.forge_version) + '），已預先下載並儲存在網站本地的資料檔中，搜尋時不需連網。' +
      '各規則依其來源專案的授權條款使用；轉用或再散布前請確認授權。資料建立時間：' + esc(db.built) + '。';
    $('repoRows').innerHTML = repos.map(function (r) {
      return '<tr><td><a href="' + esc(r.url) + '" target="_blank" rel="noopener">' + esc(r.name) + '</a></td><td>' + fmt(r.count) + '</td><td>' +
        (r.license ? '<details><summary>' + esc(r.license.split('\n')[0].slice(0, 60)) + '</summary><pre>' + esc(r.license) + '</pre></details>' : '—') + '</td></tr>';
    }).join('');
  }
  $('aboutBtn').addEventListener('click', function () { var d = $('aboutDlg'); if (d.showModal) d.showModal(); });

  /* ---------------- 事件：搜尋頁 ---------------- */
  var onQuery = debounce(function () { state.q = $('q').value.trim(); runSearch(); }, 140);
  $('q').addEventListener('input', onQuery);
  $('q').addEventListener('keydown', function (e) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); moveSel(e.key === 'ArrowDown' ? 1 : -1); }
    else if (e.key === 'Enter') { if (state.results.length) { var i = state.sel >= 0 ? state.sel : state.results[0]; select(i, { scroll: true, openSheet: true }); } }
    else if (e.key === 'Escape') { $('q').value = ''; state.q = ''; runSearch(); }
  });
  function moveSel(d) {
    if (!state.results.length) return;
    var pos = state.results.indexOf(state.sel);
    pos = pos < 0 ? 0 : Math.max(0, Math.min(state.results.length - 1, pos + d));
    while (pos >= state.shown) renderMore();
    select(state.results[pos], { scroll: true });
  }
  $('results').addEventListener('click', function (e) {
    var li = e.target.closest('.r-item'); if (!li) return;
    select(+li.dataset.i, { openSheet: true });
  });
  $('moreBtn').addEventListener('click', renderMore);
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (en) { if (en[0].isIntersecting && !$('moreBtn').hidden && state.shown < 600) renderMore(); }, { rootMargin: '200px' }).observe($('moreBtn'));
  }
  $('tierSeg').addEventListener('click', function (e) {
    var b = e.target.closest('button'); if (!b) return;
    state.tier = +b.dataset.tier; syncTier(); store('yrs-tier', String(state.tier)); runSearch();
  });
  function syncTier() { document.querySelectorAll('#tierSeg button').forEach(function (x) { x.setAttribute('aria-checked', String(+x.dataset.tier === state.tier)); }); }
  $('repoSel').addEventListener('change', function () { state.repo = this.value; runSearch(); });
  $('scoreSel').addEventListener('change', function () { state.minScore = +this.value; runSearch(); });
  $('sortSel').addEventListener('change', function () { state.sort = this.value; runSearch(); });
  $('bodyChk').addEventListener('change', function () {
    state.body = this.checked;
    if (this.checked && !bodyL) toast('正在建立規則內容索引…');
    setTimeout(runSearch, 20);
  });
  $('bundleChk').addEventListener('change', function () { store('yrs-bundle', this.checked ? '1' : '0'); if (state.sel >= 0) renderDetail(state.sel); });
  $('wrapBtn').addEventListener('click', function () {
    var on = !$('dCode').classList.contains('wrap');
    $('dCode').classList.toggle('wrap', on); this.setAttribute('aria-pressed', String(on)); store('yrs-wrap', on ? '1' : '0');
  });
  $('backBtn').addEventListener('click', function () { app.classList.remove('show-detail'); });

  $('copyBtn').addEventListener('click', function () {
    if (state.sel < 0) return;
    var btn = this, text = ruleBundle(state.sel);
    lastCopied = { text: text, name: R[state.sel][F.name] };
    copyText(text).then(function (ok) {
      if (ok) { flashButton(btn, '已複製'); toast('已複製 ' + R[state.sel][F.name]); }
      else toast('瀏覽器拒絕存取剪貼簿，請改用「在編輯器開啟」後手動複製');
    });
  });
  $('downloadBtn').addEventListener('click', function () {
    if (state.sel < 0) return;
    saveFile(R[state.sel][F.name] + '.yar', ruleBundle(state.sel));
  });
  $('toEditorBtn').addEventListener('click', function () {
    if (state.sel < 0) return;
    openInEditor(ruleBundle(state.sel), R[state.sel][F.name] + '.yar');
  });
  $('exportBtn').addEventListener('click', function () {
    var list = state.results;
    if (!list.length) return;
    var header = '/*\n * YARA Rule Searcher 匯出\n * 搜尋條件：' + (state.q || '（全部）') + '，套件：' + TIER_NAMES[state.tier] +
      '\n * 規則數：' + list.length + '\n * 資料來源：YARA Forge ' + db.release + '（https://github.com/YARAHQ/yara-forge）' +
      '\n * 匯出時間：' + new Date().toISOString() + '\n * 各規則授權請見其 meta 中的 license_url\n */';
    saveFile('yara-search-' + db.release + '.yar', bundleText(list, true, header));
  });

  /* ---------------- 路由 ---------------- */
  function setHash(h) { try { history.replaceState(null, '', h); } catch (e) { /* 部分沙箱環境不允許 */ } }
  function setView(v, noHash) {
    app.dataset.view = v;
    $('viewSearch').hidden = v !== 'search';
    $('viewEditor').hidden = v !== 'editor';
    document.querySelectorAll('.vs-btn').forEach(function (b) { b.setAttribute('aria-selected', String(b.dataset.go === v)); });
    if (v === 'editor') { app.classList.remove('show-detail'); ed.refresh(); if (!noHash) setHash('#/editor'); setTimeout(function () { $('edText').focus(); }, 30); }
    else if (!noHash) setHash(state.sel >= 0 ? '#/rule/' + encodeURIComponent(R[state.sel][F.name]) : '#/');
  }
  document.querySelectorAll('.vs-btn').forEach(function (b) { b.addEventListener('click', function () { setView(b.dataset.go); }); });
  function route() {
    var h = location.hash || '';
    var m = h.match(/^#\/rule\/(.+)$/);
    if (m) {
      var i = nameIndex.get(decodeURIComponent(m[1]));
      if (i != null) { setView('search', true); setTimeout(function () { select(i, { noHash: true, scroll: true }); }, 0); return; }
    }
    if (h === '#/editor') { setView('editor', true); return; }
    setView('search', true);
  }
  window.addEventListener('hashchange', function () { if (db) route(); });

  document.addEventListener('keydown', function (e) {
    var tag = (e.target.tagName || '').toLowerCase();
    var typing = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable;
    if (!typing && e.key === '/' && app.dataset.view === 'search') { e.preventDefault(); $('q').focus(); $('q').select(); }
    else if (!typing && app.dataset.view === 'search' && (e.key === 'ArrowDown' || e.key === 'ArrowUp') && !e.target.closest('dialog')) { e.preventDefault(); moveSel(e.key === 'ArrowDown' ? 1 : -1); }
    else if (e.key === 'Escape' && app.classList.contains('show-detail')) app.classList.remove('show-detail');
  });

  function restorePrefs() {
    var t = store('yrs-tier'); if (t === '0' || t === '1' || t === '2') { state.tier = +t; }
    syncTier();
    var b = store('yrs-bundle'); if (b === '0') $('bundleChk').checked = false;
    if (store('yrs-wrap') === '1') { $('dCode').classList.add('wrap'); $('wrapBtn').setAttribute('aria-pressed', 'true'); }
  }

  /* =========================================================
     規則編輯器
     ========================================================= */
  var lastCopied = null;
  var ed = (function () {
    var ta = $('edText'), hl = $('edHl'), gut = $('edGutter');
    var original = '', lintIssues = [], errLines = new Set();
    var find = { q: '', matches: [], cur: -1, open: false };
    var rafId = 0;
    var lineH = 0;

    function lh() { if (!lineH) lineH = parseFloat(getComputedStyle(ta).lineHeight) || 21.6; return lineH; }

    function load() {
      var saved = null;
      try { saved = JSON.parse(store('yrs-editor') || 'null'); } catch (e) { saved = null; }
      if (saved && typeof saved.text === 'string') {
        ta.value = saved.text; original = saved.original || ''; $('edName').value = saved.name || 'custom_rule.yar';
      } else {
        ta.value = ''; original = '';
      }
      ta.placeholder = '在搜尋頁選擇一條規則，按「在編輯器開啟」即可載入；也可以直接貼上或按「新範本」開始撰寫。';
    }
    var persist = debounce(function () {
      store('yrs-editor', JSON.stringify({ text: ta.value, original: original, name: $('edName').value }));
    }, 400);

    function render() {
      rafId = 0;
      var text = ta.value;
      hl.innerHTML = (find.open && find.matches.length ? highlightMarks(text) : Y.highlight(text)) + '\n ';
      var lines = text.split('\n').length, cur = curLine(), out = [];
      for (var n = 1; n <= lines; n++) {
        if (n === cur) out.push('<span class="cur">' + n + '</span>');
        else if (errLines.has(n)) out.push('<span class="err">' + n + '</span>');
        else out.push(String(n));
      }
      gut.innerHTML = out.join('\n') + '\n\n';
      sync();
      status();
    }
    function schedule() { if (!rafId) rafId = requestAnimationFrame(render); }
    function sync() {
      hl.style.transform = 'translate(' + (-ta.scrollLeft) + 'px,' + (-ta.scrollTop) + 'px)';
      gut.scrollTop = ta.scrollTop;
    }
    function curLine() { return ta.value.slice(0, ta.selectionStart).split('\n').length; }
    function status() {
      var before = ta.value.slice(0, ta.selectionStart);
      var ln = before.split('\n').length, col = before.length - before.lastIndexOf('\n');
      $('stPos').textContent = '行 ' + ln + '，欄 ' + col;
      $('stSize').textContent = fmt(ta.value.split('\n').length) + ' 行，' + fmt(ta.value.length) + ' 字元';
      var dirty = ta.value !== original && ta.value.trim() !== '';
      $('edState').textContent = !ta.value.trim() ? '空白' : dirty ? '已修改' : '未修改';
      $('edState').classList.toggle('dirty', dirty);
      $('editorDot').hidden = !dirty;
    }

    function highlightMarks(src) {
      var toks = Y.tokenize(src), out = [], mk = find.matches, mi = 0, L = find.q.length;
      var CLS = { com: 't-com', str: 't-str', hex: 't-hex', re: 't-re', var: 't-var', num: 't-num', kw: 't-kw', mod: 't-kw', fn: 't-fn', module: 't-mod', sec: 't-sec', name: 't-name', tag: 't-tag', meta: 't-meta' };
      toks.forEach(function (tk) {
        var cls = CLS[tk.t], s = tk.s, segs = [];
        while (mi < mk.length && mk[mi] + L <= s) mi++;
        var j = mi, pos = s;
        while (j < mk.length && mk[j] < tk.e) {
          var ms = Math.max(mk[j], tk.s), me = Math.min(mk[j] + L, tk.e);
          if (ms > pos) segs.push(Y.escape(src.slice(pos, ms)));
          segs.push('<mark class="' + (j === find.cur ? 'fm cur' : 'fm') + '">' + Y.escape(src.slice(ms, me)) + '</mark>');
          pos = me;
          if (mk[j] + L > tk.e) break;
          j++;
        }
        if (pos < tk.e) segs.push(Y.escape(src.slice(pos, tk.e)));
        var h = segs.join('');
        out.push(cls ? '<span class="' + cls + '">' + h + '</span>' : h);
      });
      return out.join('');
    }

    /* 以 execCommand 插入以保留復原（Ctrl+Z）紀錄 */
    function replaceRange(start, end, text, selS, selE) {
      ta.focus();
      ta.setSelectionRange(start, end);
      var ok = false;
      try { ok = document.execCommand('insertText', false, text); } catch (e) { ok = false; }
      if (!ok || ta.value.slice(start, start + text.length) !== text) {
        ta.setRangeText(text, start, end, 'end');
      }
      if (selS != null) ta.setSelectionRange(selS, selE != null ? selE : selS);
      onChange();
    }
    function setText(text, keepOriginal) {
      ta.value = text;
      if (!keepOriginal) original = text;
      ta.setSelectionRange(0, 0); ta.scrollTop = 0; ta.scrollLeft = 0;
      onChange();
    }

    var doLint = debounce(function () {
      lintIssues = Y.lint(ta.value, { knownRule: function (n) { return nameIndex.has(n); } });
      errLines = new Set(lintIssues.filter(function (x) { return x.level === 'error'; }).map(function (x) { return x.line; }));
      renderLint(); renderOutline(); schedule();
    }, 260);
    function onChange() { schedule(); doLint(); persist(); if (find.open) computeFind(); }

    function renderLint() {
      var list = $('lintList'), st = $('stLint');
      var errs = lintIssues.filter(function (x) { return x.level === 'error'; }).length;
      var warns = lintIssues.filter(function (x) { return x.level === 'warning'; }).length;
      if (!ta.value.trim()) { list.innerHTML = '<li class="empty">編輯區是空的。</li>'; st.textContent = ''; st.className = 'st-lint'; return; }
      st.className = 'st-lint ' + (errs ? 'bad' : warns ? 'warn' : 'ok');
      st.textContent = errs ? errs + ' 個錯誤' + (warns ? '、' + warns + ' 個警告' : '') : warns ? warns + ' 個警告' : '檢查通過';
      if (!lintIssues.length) { list.innerHTML = '<li class="ok"><span class="dot"></span><span>沒有發現問題。</span></li>'; return; }
      list.innerHTML = lintIssues.map(function (x, k) {
        return '<li class="' + x.level + '" data-line="' + x.line + '"><span class="dot"></span><span><span class="ln">第 ' + x.line + ' 行</span>' + esc(x.msg) +
          (x.fix ? '<br><button class="text-btn fix" type="button" data-fix="' + k + '">' + esc(x.fix.label) + '</button>' : '') + '</span></li>';
      }).join('');
    }
    function renderOutline() {
      var info = Y.splitRules(ta.value);
      $('stRules').textContent = info.rules.length + ' 條規則';
      $('outline').innerHTML = info.rules.length ? info.rules.map(function (r) {
        return '<li><button type="button" data-line="' + r.start + '">' + esc(r.name) + '</button></li>';
      }).join('') : '<li class="empty">尚無規則。</li>';
    }

    function goToLine(n, select) {
      var lines = ta.value.split('\n'), off = 0;
      for (var k = 0; k < n - 1 && k < lines.length; k++) off += lines[k].length + 1;
      ta.focus();
      ta.setSelectionRange(off, select ? off + (lines[n - 1] || '').length : off);
      scrollToLine(n);
      schedule();
    }
    function scrollToLine(n) {
      var y = (n - 1) * lh();
      if (y < ta.scrollTop + 20 || y > ta.scrollTop + ta.clientHeight - 40) ta.scrollTop = Math.max(0, y - ta.clientHeight / 3);
    }

    function applyFix(fix) {
      if (fix.type === 'addImports') {
        var info = Y.splitRules(ta.value), text = ta.value;
        var lines = fix.data.map(function (m) { return 'import "' + m + '"'; }).join('\n') + '\n';
        var insertAt = 0;
        if (info.imports.length) {
          var lastLine = info.imports[info.imports.length - 1].line;
          var arr = text.split('\n'); for (var k = 0; k < lastLine; k++) insertAt += arr[k].length + 1;
        } else lines += '\n';
        replaceRange(insertAt, insertAt, lines);
        toast('已補上 import ' + fix.data.join('、'));
      } else if (fix.type === 'addRule') {
        var i = nameIndex.get(fix.data); if (i == null) return;
        var have = new Set(Y.splitRules(ta.value).rules.map(function (r) { return r.name; }));
        var order = collectOrder([i]).filter(function (k) { return !have.has(R[k][F.name]); });
        var add = order.map(function (k) { return R[k][F.text]; }).join('\n\n');
        // 相依規則須在使用它的規則之前定義：插入到第一條規則前
        var first = Y.splitRules(ta.value).rules[0];
        var pos = 0;
        if (first) { var arr2 = ta.value.split('\n'); for (var q = 0; q < first.start - 1; q++) pos += arr2[q].length + 1; }
        replaceRange(pos, pos, add + '\n\n');
        var mods = new Set(); order.forEach(function (k) { R[k][F.modules].forEach(function (m) { mods.add(m); }); });
        toast('已插入 ' + order.length + ' 條相依規則' + (mods.size ? '，請確認 import' : ''));
      }
    }

    /* ---------- 鍵盤操作 ---------- */
    function lineBounds(s, e) {
      var v = ta.value;
      var ls = v.lastIndexOf('\n', s - 1) + 1;
      var le = v.indexOf('\n', e > s && v[e - 1] === '\n' ? e - 1 : e);
      if (le < 0) le = v.length;
      return [ls, le];
    }
    ta.addEventListener('keydown', function (e) {
      var v = ta.value, s = ta.selectionStart, en = ta.selectionEnd, mod = e.ctrlKey || e.metaKey;
      if (e.key === 'Tab') {
        e.preventDefault();
        if (s === en && !e.shiftKey) { replaceRange(s, en, '\t', s + 1); return; }
        var b = lineBounds(s, en), block = v.slice(b[0], b[1]), lines = block.split('\n');
        var out = e.shiftKey ? lines.map(function (l) { return l.replace(/^(\t| {1,4})/, ''); }) : lines.map(function (l) { return '\t' + l; });
        var nb = out.join('\n');
        if (s === en) {
          // 游標未選取文字：維持游標在原本相對位置
          var delta = nb.length - block.length;
          var caret = Math.max(b[0], s + delta);
          replaceRange(b[0], b[1], nb, caret);
        } else {
          replaceRange(b[0], b[1], nb, b[0], b[0] + nb.length);
        }
        return;
      }
      if (e.key === 'Enter' && !mod && !e.altKey) {
        e.preventDefault();
        var ls = v.lastIndexOf('\n', s - 1) + 1, cur = v.slice(ls, s);
        var indent = (cur.match(/^[\t ]*/) || [''])[0];
        var trimmed = cur.trim();
        if (/^(meta|strings|condition)\s*:$/.test(trimmed) || trimmed === '{' || /\{\s*$/.test(trimmed) && !/=\s*\{/.test(trimmed)) indent += '\t';
        replaceRange(s, en, '\n' + indent, s + 1 + indent.length);
        return;
      }
      if (e.key === '}' && !mod && s === en) {
        var ls2 = v.lastIndexOf('\n', s - 1) + 1, before = v.slice(ls2, s);
        if (before && /^[\t ]+$/.test(before)) {
          e.preventDefault();
          var ni = before.replace(/(\t| {1,4})$/, '');
          replaceRange(ls2, s, ni + '}', ls2 + ni.length + 1);
          return;
        }
      }
      if (mod && e.key === '/') {
        e.preventDefault();
        var b2 = lineBounds(s, en), blk = v.slice(b2[0], b2[1]).split('\n');
        var allC = blk.filter(function (l) { return l.trim(); }).every(function (l) { return /^\s*\/\//.test(l); });
        var res = blk.map(function (l) {
          if (!l.trim()) return l;
          return allC ? l.replace(/^(\s*)\/\/ ?/, '$1') : l.replace(/^(\s*)/, '$1// ');
        }).join('\n');
        replaceRange(b2[0], b2[1], res, b2[0], b2[0] + res.length);
        return;
      }
      if (mod && (e.key === 'd' || e.key === 'D') && !e.shiftKey) {
        e.preventDefault();
        var b3 = lineBounds(s, en), ln = v.slice(b3[0], b3[1]);
        replaceRange(b3[1], b3[1], '\n' + ln, s + ln.length + 1, en + ln.length + 1);
        return;
      }
      if (mod && (e.key === 'f' || e.key === 'F') && !e.shiftKey) { e.preventDefault(); openFind(v.slice(s, en)); return; }
      if (mod && e.shiftKey && (e.key === 'c' || e.key === 'C')) { e.preventDefault(); $('edCopy').click(); return; }
      if (mod && (e.key === 's' || e.key === 'S')) { e.preventDefault(); $('edDownload').click(); return; }
      if (e.key === 'Escape' && find.open) { closeFind(); }
    });
    ta.addEventListener('input', onChange);
    ta.addEventListener('scroll', sync);
    ['keyup', 'click', 'select'].forEach(function (ev) { ta.addEventListener(ev, function () { schedule(); }); });
    $('edName').addEventListener('input', persist);

    /* ---------- 尋找與取代 ---------- */
    function openFind(seed) {
      find.open = true; $('findbar').hidden = false;
      if (seed && seed.indexOf('\n') < 0) $('findIn').value = seed;
      $('findIn').focus(); $('findIn').select();
      computeFind(); schedule();
    }
    function closeFind() { find.open = false; $('findbar').hidden = true; find.matches = []; schedule(); ta.focus(); }
    function computeFind() {
      var q = $('findIn').value, cs = $('findCase').checked;
      find.q = q; find.matches = [];
      if (q) {
        var hay = cs ? ta.value : ta.value.toLowerCase(), nd = cs ? q : q.toLowerCase(), p = 0;
        while ((p = hay.indexOf(nd, p)) >= 0 && find.matches.length < 5000) { find.matches.push(p); p += nd.length || 1; }
      }
      if (find.cur >= find.matches.length) find.cur = find.matches.length - 1;
      if (find.cur < 0 && find.matches.length) {
        var c = ta.selectionStart, k = find.matches.findIndex(function (m) { return m >= c; });
        find.cur = k < 0 ? 0 : k;
      }
      $('findCount').textContent = q ? (find.matches.length ? (find.cur + 1) + ' / ' + find.matches.length : '無結果') : '';
      schedule();
    }
    function step(d) {
      if (!find.matches.length) return;
      find.cur = (find.cur + d + find.matches.length) % find.matches.length;
      var pos = find.matches[find.cur];
      ta.setSelectionRange(pos, pos + find.q.length);
      scrollToLine(ta.value.slice(0, pos).split('\n').length);
      $('findCount').textContent = (find.cur + 1) + ' / ' + find.matches.length;
      schedule();
    }
    $('findIn').addEventListener('input', function () { find.cur = -1; computeFind(); });
    $('findCase').addEventListener('change', function () { find.cur = -1; computeFind(); });
    $('findIn').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); step(e.shiftKey ? -1 : 1); }
      if (e.key === 'Escape') closeFind();
    });
    $('replIn').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); $('replOne').click(); } if (e.key === 'Escape') closeFind(); });
    $('findNext').addEventListener('click', function () { step(1); });
    $('findPrev').addEventListener('click', function () { step(-1); });
    $('findClose').addEventListener('click', closeFind);
    $('replOne').addEventListener('click', function () {
      if (!find.matches.length) return;
      if (find.cur < 0) find.cur = 0;
      var pos = find.matches[find.cur], r = $('replIn').value;
      replaceRange(pos, pos + find.q.length, r, pos + r.length);
      computeFind();
      if (find.matches.length) { find.cur = find.cur % find.matches.length; }
      $('replIn').focus();
    });
    $('replAll').addEventListener('click', function () {
      if (!find.matches.length) return;
      var n = find.matches.length, r = $('replIn').value, v = ta.value, out = '', last = 0;
      find.matches.forEach(function (m) { out += v.slice(last, m) + r; last = m + find.q.length; });
      out += v.slice(last);
      replaceRange(0, v.length, out, 0);
      computeFind();
      toast('已取代 ' + n + ' 處');
      $('replIn').focus();
    });

    /* ---------- 工具列 ---------- */
    $('edCopy').addEventListener('click', function () {
      var btn = this;
      if (!ta.value.trim()) { toast('編輯區是空的'); return; }
      copyText(ta.value).then(function (ok) {
        if (ok) { flashButton(btn, '已複製'); toast(errLines.size ? '已複製（注意：仍有 ' + errLines.size + ' 行有錯誤）' : '已複製修正後的規則'); }
        else { ta.focus(); ta.select(); toast('瀏覽器拒絕存取剪貼簿，內容已全選，請按 Ctrl+C'); }
      });
    });
    $('edDownload').addEventListener('click', function () {
      if (!ta.value.trim()) { toast('編輯區是空的'); return; }
      var name = ($('edName').value || 'custom_rule.yar').trim();
      if (!/\.(yar|yara)$/i.test(name)) name += '.yar';
      saveFile(name, ta.value);
    });
    $('edPaste').addEventListener('click', function () {
      if (navigator.clipboard && navigator.clipboard.readText) {
        navigator.clipboard.readText().then(function (t) {
          if (!t) { toast('剪貼簿是空的'); return; }
          var s = ta.selectionStart, e2 = ta.selectionEnd;
          replaceRange(s, e2, t, s + t.length);
          toast('已貼上');
        }, function () {
          if (lastCopied) { insertOrReplace(lastCopied.text, lastCopied.name + '.yar'); return; }
          ta.focus(); toast('瀏覽器不允許讀取剪貼簿，請在編輯區按 Ctrl+V');
        });
      } else { ta.focus(); toast('請在編輯區按 Ctrl+V 貼上'); }
    });
    $('edFind').addEventListener('click', function () { find.open ? closeFind() : openFind(ta.value.slice(ta.selectionStart, ta.selectionEnd)); });
    $('edTemplate').addEventListener('click', function () {
      var d = new Date().toISOString().slice(0, 10);
      var tpl = 'rule New_Detection_Rule : FILE\n{\n\tmeta:\n\t\tdescription = "說明此規則要偵測的威脅"\n\t\tauthor = "your_name"\n\t\tdate = "' + d + '"\n\t\treference = "https://"\n\t\tscore = 70\n\n' +
        '\tstrings:\n\t\t$s1 = "suspicious_string" ascii wide\n\t\t$s2 = "another_indicator" ascii\n\t\t$h1 = { 4D 5A 90 00 03 00 }\n\n' +
        '\tcondition:\n\t\tuint16(0) == 0x5A4D and filesize < 5MB and $h1 and any of ($s*)\n}\n';
      var s = ta.selectionStart, v = ta.value;
      var prefix = v && s > 0 && v[s - 1] !== '\n' ? '\n\n' : (v && s > 0 && v.slice(s - 2, s) !== '\n\n' ? '\n' : '');
      replaceRange(s, ta.selectionEnd, prefix + tpl, s + prefix.length + 5, s + prefix.length + 23);
      toast('已插入規則範本，先改規則名稱吧');
    });
    $('edRevert').addEventListener('click', function () {
      if (!original) { toast('沒有可還原的原始內容'); return; }
      if (ta.value === original) { toast('內容與原始規則相同'); return; }
      replaceRange(0, ta.value.length, original, 0);
      ta.scrollTop = 0;
      toast('已還原為載入時的內容（可按 Ctrl+Z 復原）');
    });
    $('edClear').addEventListener('click', function () {
      if (!ta.value) return;
      replaceRange(0, ta.value.length, '', 0);
      toast('已清空（可按 Ctrl+Z 復原）');
    });
    $('lintList').addEventListener('click', function (e) {
      var fx = e.target.closest('[data-fix]');
      if (fx) { applyFix(lintIssues[+fx.dataset.fix].fix); return; }
      var li = e.target.closest('[data-line]'); if (li) goToLine(+li.dataset.line, true);
    });
    $('outline').addEventListener('click', function (e) {
      var b = e.target.closest('[data-line]'); if (b) { goToLine(+b.dataset.line, true); ta.scrollTop = Math.max(0, (+b.dataset.line - 1) * lh() - 12); sync(); }
    });

    function isDirty() { return ta.value.trim() !== '' && ta.value !== original; }
    function insertOrReplace(text, name) {
      function replace() { $('edName').value = name; setText(text); setView('editor'); toast('已載入編輯器'); }
      if (!isDirty() || ta.value === text) { replace(); return; }
      var dlg = $('mergeDlg');
      if (!dlg.showModal) { replace(); return; }
      dlg.returnValue = '';
      dlg.showModal();
      dlg.addEventListener('close', function h() {
        dlg.removeEventListener('close', h);
        if (dlg.returnValue === 'replace') replace();
        else if (dlg.returnValue === 'append') {
          var v = ta.value.replace(/\s*$/, '');
          // 已有的 import 不重複
          var have = new Set(Y.splitRules(v).imports.map(function (x) { return x.name; }));
          var addText = text.split('\n').filter(function (l) { var m = l.match(/^import "(\w+)"$/); return !(m && have.has(m[1])); }).join('\n').replace(/^\s+/, '');
          var newImports = addText.match(/^(import "\w+"\n)+/);
          var body = v;
          if (newImports) { body = newImports[0] + v; addText = addText.slice(newImports[0].length).replace(/^\s+/, ''); }
          setText(body + '\n\n' + addText, true);
          setView('editor');
          goToLine(body.split('\n').length + 2);
          toast('已附加到編輯器尾端');
        }
      });
    }

    return {
      load: function () { load(); onChange(); },
      refresh: function () { lineH = 0; render(); doLint(); },
      insertOrReplace: insertOrReplace
    };
  })();

  function openInEditor(text, name) {
    lastCopied = { text: text, name: name.replace(/\.yar$/, '') };
    ed.insertOrReplace(text, name);
  }

  /* ---------------- 啟動 ---------------- */
  ed.load();
  loadDB().then(init).catch(function (err) {
    $('loadingText').innerHTML = '無法載入規則資料：' + esc(err.message) +
      '。<br>請先執行 <code>python3 scripts/build_db.py</code> 產生 <code>data/yara-db.js</code>。';
    document.querySelector('.loading .bar').hidden = true;
  });
})();
