(function () {
  'use strict';

  var doc = document;
  var rootEl = doc.documentElement;
  var THEME_KEY = 'airworthy-theme';
  var SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  var SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  var GRADES = ['A', 'B', 'C', 'D', 'F'];
  var VERDICT = {
    'A': 'Strong configuration',
    'B': 'Good, with a few gaps',
    'C': 'Needs attention',
    'D': 'Weak configuration',
    'F': 'Unsafe configuration'
  };
  var CONFIDENCE_NOTE = {
    medium: 'medium: the documented behavior is only partly confirmed',
    low: 'low: heuristic check'
  };
  var HARNESS_LABEL = {
    'vscode-copilot': 'VS Code Copilot',
    'claude-code': 'Claude Code',
    'copilot-cli': 'Copilot CLI',
    'codex': 'Codex CLI',
    'mcp': 'MCP',
    'generic': 'Any harness'
  };
  var HARNESS_ORDER = ['vscode-copilot', 'claude-code', 'copilot-cli', 'codex', 'mcp', 'generic'];
  // References become links only when they are https URLs on one of these documentation hosts.
  var LINK_HOSTS = ['code.visualstudio.com', 'docs.github.com', 'github.com', 'docs.anthropic.com',
    'code.claude.com', 'genai.owasp.org', 'owasp.org', 'docs.oasis-open.org', 'modelcontextprotocol.io',
    'learn.microsoft.com', 'learn.chatgpt.com'];
  var GAUGE_LENGTH = 2 * Math.PI * 84;
  var PLAIN_TEXT = /^[\t\n\x20-\x7e]*$/;

  // ---- Theme: applied at once, since this script runs in <head> before the first paint ----
  function storedTheme() {
    try { var v = window.localStorage.getItem(THEME_KEY); return (v === 'light' || v === 'dark') ? v : null; } catch (e) { return null; }
  }
  function saveTheme(v) {
    try { window.localStorage.setItem(THEME_KEY, v); } catch (e) { /* storage blocked: the choice lasts for this page only */ }
  }
  function systemTheme() {
    try { return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; } catch (e) { return 'light'; }
  }
  function currentTheme() {
    var t = rootEl.getAttribute('data-theme');
    return (t === 'light' || t === 'dark') ? t : systemTheme();
  }
  var initialTheme = storedTheme();
  if (initialTheme) { rootEl.setAttribute('data-theme', initialTheme); }

  // ---- Small helpers. Data only ever reaches the page as text. ----
  function has(map, key) { return Object.prototype.hasOwnProperty.call(map, key); }
  function str(v) { return (v === null || v === undefined) ? '' : String(v); }
  function num(v) { var n = Number(v); return isFinite(n) ? n : 0; }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function obj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
  function clamp(n, lo, hi) { return Math.min(hi, Math.max(lo, n)); }
  function sevOf(v) { return SEVERITIES.indexOf(v) >= 0 ? v : 'info'; }
  function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }
  function byId(id) { return doc.getElementById(id); }
  function harnessLabel(h) { return has(HARNESS_LABEL, h) ? HARNESS_LABEL[h] : str(h); }
  function band(score) { return score >= 90 ? 'a' : score >= 80 ? 'b' : score >= 70 ? 'c' : score >= 60 ? 'd' : 'f'; }
  function reducedMotion() {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; }
  }

  // Shows control, invisible and direction-changing characters, Unicode tag characters (used to
  // smuggle hidden instructions) and lone surrogates as [U+XXXX], so that hostile text can
  // neither hide content nor visually reorder it.
  function isInvisible(c) {
    return (c < 32 && c !== 9 && c !== 10) || (c >= 127 && c < 160) || c === 0xad || c === 0x34f ||
      c === 0x61c || c === 0x115f || c === 0x1160 || c === 0x17b4 || c === 0x17b5 ||
      (c >= 0x180b && c <= 0x180f) || (c >= 0x200b && c <= 0x200f) || (c >= 0x2028 && c <= 0x202e) ||
      (c >= 0x2060 && c <= 0x206f) || c === 0x3164 || c === 0xfeff || c === 0xffa0 || (c >= 0xfff9 && c <= 0xfffb) ||
      (c >= 0xe0000 && c <= 0xe0fff);
  }
  function codeLabel(c) {
    var h = c.toString(16).toUpperCase();
    return '[U+' + (h.length < 4 ? ('000' + h).slice(-4) : h) + ']';
  }
  function visible(value) {
    var s = str(value);
    if (PLAIN_TEXT.test(s)) { return s; }
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      var width = 1;
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
        var low = s.charCodeAt(i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          c = (c - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000;
          width = 2;
        }
      }
      if ((width === 1 && c >= 0xd800 && c <= 0xdfff) || isInvisible(c)) {
        out += codeLabel(c);
      } else {
        out += s.substr(i, width);
      }
      i += width - 1;
    }
    return out;
  }
  function setText(node, value) { if (node) { node.textContent = visible(value); } }
  function el(tag, className, text) {
    var node = doc.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined) { node.textContent = visible(text); }
    return node;
  }
  function append(parent) {
    for (var i = 1; i < arguments.length; i++) { if (arguments[i]) { parent.appendChild(arguments[i]); } }
    return parent;
  }
  function button(className, text, onClick) {
    var b = el('button', className, text);
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }
  function cmpText(a, b) { a = a.toLowerCase(); b = b.toLowerCase(); return a < b ? -1 : (a > b ? 1 : 0); }
  function isEditable(t) {
    if (!t || !t.tagName) { return false; }
    var tag = t.tagName.toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select' || t.isContentEditable === true;
  }

  // A link is created only for an https URL on an allowlisted host, parsed by the URL constructor.
  function safeHref(ref) {
    if (typeof URL !== 'function' || !/^https:/i.test(ref)) { return null; }
    var u;
    try { u = new URL(ref); } catch (e) { return null; }
    if (u.protocol !== 'https:' || u.username || u.password || LINK_HOSTS.indexOf(u.hostname) < 0) { return null; }
    return u.href;
  }
  function refItem(ref) {
    var li = el('li');
    var href = safeHref(ref);
    if (href) {
      var a = el('a', null, ref);
      a.setAttribute('href', href);
      a.setAttribute('rel', 'noopener noreferrer');
      a.setAttribute('referrerpolicy', 'no-referrer');
      a.setAttribute('target', '_blank');
      li.appendChild(a);
    } else {
      li.appendChild(el('span', 'ref-text', ref));
    }
    return li;
  }

  function readData() {
    var node = byId('aw-data');
    if (!node) { return null; }
    try {
      var d = JSON.parse(node.textContent || '');
      return (d && typeof d === 'object' && !Array.isArray(d)) ? d : null;
    } catch (e) { return null; }
  }
  function showFatal(message) {
    var main = byId('aw-main');
    var p = el('p', 'note note-error', message);
    p.setAttribute('role', 'alert');
    if (main) { main.insertBefore(p, main.firstChild); }
  }
  function timeParts(iso) {
    var m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(:\d{2})?(\.\d+)?Z$/.exec(iso);
    return m ? { date: m[1], text: m[1] + ' ' + m[2] + ' UTC' } : { date: '', text: iso };
  }
  function countsSentence(counts) {
    var parts = [];
    var total = 0;
    SEVERITIES.forEach(function (s) {
      var n = Math.max(0, Math.floor(num(counts[s])));
      total += n;
      if (n) { parts.push(n + ' ' + s); }
    });
    if (!total) { return 'No findings'; }
    var last = parts.pop();
    return (parts.length ? parts.join(', ') + ' and ' + last : last) + (total === 1 ? ' finding' : ' findings');
  }

  function setupThemeToggle() {
    var b = byId('aw-theme');
    if (!b) { return; }
    function sync() { b.setAttribute('aria-pressed', currentTheme() === 'dark' ? 'true' : 'false'); }
    b.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      rootEl.setAttribute('data-theme', next);
      saveTheme(next);
      sync();
    });
    try {
      var mq = window.matchMedia('(prefers-color-scheme: dark)');
      if (mq.addEventListener) { mq.addEventListener('change', sync); } else if (mq.addListener) { mq.addListener(sync); }
    } catch (e) { /* no media query support: the button still works */ }
    sync();
  }

  function renderHeader(d) {
    var tool = obj(d.tool);
    var version = str(tool.version);
    var time = timeParts(str(d.scannedAt));
    setText(byId('aw-version'), version ? 'v' + version : '');
    setText(byId('aw-root'), str(d.root) || 'Unknown folder');
    var timeNode = byId('aw-time');
    if (d.scannedAt) { timeNode.setAttribute('datetime', str(d.scannedAt)); }
    setText(timeNode, time.text || 'Unknown');

    var harnesses = byId('aw-harnesses');
    var list = arr(d.harnesses).map(str).filter(Boolean);
    if (!list.length) { harnesses.appendChild(el('span', 'badge badge-quiet', 'None detected')); }
    list.forEach(function (h) { harnesses.appendChild(el('span', 'badge', harnessLabel(h))); });

    var o = obj(d.options);
    var notes = [];
    if (o.redact === true) { notes.push('Paths redacted'); }
    if (sevOf(o.minSeverity) !== 'info') { notes.push('Lists ' + sevOf(o.minSeverity) + ' and above'); }
    if (SEVERITIES.indexOf(o.failOn) >= 0) { notes.push('CI gate (fail on ' + o.failOn + '): ' + (num(o.exitCode) ? 'failed' : 'passed')); }
    if (!notes.length) { notes.push('Defaults'); }
    var opts = byId('aw-options');
    notes.forEach(function (n) { opts.appendChild(el('span', 'badge badge-quiet', n)); });

    setText(byId('aw-stamp-tool'), 'Checked by ' + (str(tool.name) || 'Airworthy') + (version ? ' ' + version : ''));
    setText(byId('aw-stamp-date'), time.date);
  }

  function renderScore(d) {
    var s = obj(d.score);
    var score = Math.round(clamp(num(s.score), 0, 100));
    var grade = GRADES.indexOf(s.grade) >= 0 ? s.grade : '';
    var counts = obj(d.counts);
    byId('aw-tag').className = 'tag grade-' + (grade ? grade.toLowerCase() : 'none');
    setText(byId('aw-grade'), grade || '?');
    setText(byId('aw-score'), score + ' / 100');
    byId('aw-gauge').setAttribute('aria-label', 'Overall score ' + score + ' out of 100, grade ' + (grade || 'unknown'));
    setText(byId('aw-verdict'), grade ? VERDICT[grade] : 'Not graded');
    setText(byId('aw-summary'), countsSentence(counts));
    if (num(counts.critical) > 0) {
      var cap = byId('aw-cap');
      setText(cap, 'A critical finding caps the score at 69.');
      cap.hidden = false;
    }
    var arc = byId('aw-arc');
    if (score === 0) { arc.classList.add('is-empty'); }
    if (!reducedMotion()) {
      void window.getComputedStyle(arc).strokeDashoffset; // commit the empty ring so the sweep animates
      arc.classList.add('is-animated');
    }
    arc.style.strokeDashoffset = (GAUGE_LENGTH * (1 - score / 100)).toFixed(2);
    doc.title = 'Airworthy report: grade ' + (grade || '?') + ', ' + score + '/100';
  }

  function renderCategories(d, findings, showCategory) {
    var host = byId('aw-categories');
    var cats = arr(d.categories).map(obj);
    var counts = Object.create(null);
    findings.forEach(function (f) { counts[f.category] = (counts[f.category] || 0) + 1; });
    var totalWeight = 0;
    cats.forEach(function (c) { if (c.applicable === true) { totalWeight += Math.max(0, num(c.weight)); } });
    cats.forEach(function (c) {
      var id = str(c.id);
      var applicable = c.applicable === true;
      var score = Math.round(clamp(num(c.score), 0, 100));
      var n = counts[id] || 0;
      var li = el('li', applicable ? 'cat band-' + band(score) : 'cat is-na');
      var scoreNode = el('span', 'cat-score', applicable ? String(score) : 'Not scored');
      if (applicable) { scoreNode.appendChild(el('span', 'sr-only', ' out of 100')); }
      li.appendChild(append(el('div', 'cat-head'), el('h4', 'cat-title', str(c.title) || id), scoreNode));
      if (applicable) {
        var bar = el('div', 'bar');
        var fill = el('span', 'bar-fill');
        bar.setAttribute('aria-hidden', 'true');
        fill.style.width = score + '%';
        li.appendChild(append(bar, fill));
        var share = totalWeight > 0 ? Math.round(100 * Math.max(0, num(c.weight)) / totalWeight) : 0;
        li.appendChild(el('p', 'cat-meta', (n ? plural(n, 'finding') : 'No findings') + ', ' + share + '% of the overall score'));
      } else {
        li.appendChild(el('p', 'cat-meta', 'No rule in this category applies to the detected harnesses.'));
      }
      if (n) {
        li.appendChild(button('link-btn', n === 1 ? 'Show this finding' : 'Show these ' + n + ' findings', function () { showCategory(id); }));
      }
      host.appendChild(li);
    });
  }

  function renderNotes(d, findings) {
    var host = byId('aw-notes');
    var counts = obj(d.counts);
    var minSev = sevOf(obj(d.options).minSeverity);
    var total = 0;
    SEVERITIES.forEach(function (s) { total += Math.max(0, Math.floor(num(counts[s]))); });
    var hiddenCount = total - findings.length;
    if (hiddenCount > 0 && minSev !== 'info') {
      host.appendChild(el('p', 'note', plural(hiddenCount, 'finding') + ' below ' + minSev + ' severity ' +
        (hiddenCount === 1 ? 'is' : 'are') + ' not listed. The score still counts ' + (hiddenCount === 1 ? 'it.' : 'them.')));
    }
    var errors = arr(d.errors).map(obj);
    if (errors.length) {
      var box = el('details', 'note note-warn');
      box.appendChild(el('summary', null, errors.length === 1 ? '1 file or rule could not be fully analyzed'
        : errors.length + ' files or rules could not be fully analyzed'));
      var ul = el('ul');
      errors.forEach(function (e) {
        ul.appendChild(append(el('li'),
          el('span', null, str(e.title) || str(e.ruleId)),
          e.path ? el('code', null, str(e.path)) : null,
          e.evidence ? el('span', 'note-detail', str(e.evidence)) : null));
      });
      box.appendChild(ul);
      host.appendChild(box);
    }
    host.hidden = !host.firstChild;
  }

  function normalizeFinding(raw, index) {
    var f = obj(raw);
    var line = Math.floor(num(f.line));
    var n = {
      index: index,
      ruleId: str(f.ruleId),
      title: str(f.title),
      severity: sevOf(f.severity),
      category: str(f.category),
      harness: str(f.harness),
      description: str(f.description),
      evidence: str(f.evidence),
      path: str(f.path),
      line: line > 0 ? line : 0,
      key: str(f.key),
      fix: str(f.fix),
      confidence: str(f.confidence),
      references: arr(f.references).map(str).filter(Boolean)
    };
    n.rank = SEVERITIES.length - SEVERITIES.indexOf(n.severity);
    return n;
  }

  function cmpFile(a, b) {
    if (!a.path !== !b.path) { return a.path ? -1 : 1; }
    return cmpText(a.path, b.path) || (a.line - b.line);
  }
  var SORTS = {
    severity: function (a, b) { return (b.rank - a.rank) || cmpText(a.ruleId, b.ruleId) || cmpFile(a, b) || (a.index - b.index); },
    rule: function (a, b) { return cmpText(a.ruleId, b.ruleId) || (b.rank - a.rank) || cmpFile(a, b) || (a.index - b.index); },
    file: function (a, b) { return cmpFile(a, b) || (b.rank - a.rank) || cmpText(a.ruleId, b.ruleId) || (a.index - b.index); }
  };

  function fact(dl, label, value, className) {
    if (!value) { return; }
    append(dl, el('dt', null, label), el('dd', className || null, value));
  }

  function buildFinding(f, catTitles) {
    var id = 'aw-f' + f.index;
    var categoryTitle = catTitles[f.category] || f.category;
    var where = f.path ? f.path + (f.line ? ':' + f.line : '') : f.key;
    var li = el('li', 'finding sev-' + f.severity);

    var btn = el('button', 'f-toggle');
    btn.type = 'button';
    btn.id = id + '-btn';
    btn.setAttribute('aria-expanded', 'false');
    btn.setAttribute('aria-controls', id + '-body');
    var chev = el('span', 'chev');
    chev.setAttribute('aria-hidden', 'true');
    append(btn,
      el('span', 'sev-badge', SEV_LABEL[f.severity]),
      append(el('span', 'f-main'),
        el('span', 'f-title', f.title || f.ruleId || 'Finding'),
        append(el('span', 'f-meta'), el('span', 'f-rule', f.ruleId), where ? el('span', 'f-where', where) : null)),
      chev);

    var body = el('div', 'f-body');
    body.id = id + '-body';
    body.hidden = true;
    if (f.description) { body.appendChild(el('p', 'f-desc', f.description)); }
    var facts = el('dl', 'facts');
    fact(facts, 'Rule', f.ruleId);
    fact(facts, 'Category', categoryTitle);
    fact(facts, 'Harness', harnessLabel(f.harness));
    fact(facts, 'Confidence', has(CONFIDENCE_NOTE, f.confidence) ? CONFIDENCE_NOTE[f.confidence] : f.confidence);
    fact(facts, 'File', f.path, 'code');
    fact(facts, 'Line', f.line ? String(f.line) : '');
    fact(facts, 'Setting', f.key, 'code');
    body.appendChild(facts);
    if (f.evidence) {
      append(body, el('h4', 'f-label', 'Evidence'), append(el('pre', 'evidence'), el('code', null, f.evidence)));
    }
    if (f.fix) { append(body, el('h4', 'f-label', 'How to fix'), el('p', 'f-fix', f.fix)); }
    if (f.references.length) {
      var refs = el('ul', 'refs');
      f.references.forEach(function (r) { refs.appendChild(refItem(r)); });
      append(body, el('h4', 'f-label', 'References'), refs);
    }
    append(li, append(el('h3', 'f-head'), btn), body);

    var item = {
      f: f, li: li, btn: btn, body: body,
      hay: [f.ruleId, f.title, f.severity, f.category, categoryTitle, f.harness, harnessLabel(f.harness), f.description,
        f.evidence, f.path, f.key, f.fix, f.confidence, f.references.join(' ')].map(visible).join('\n').toLowerCase()
    };
    btn.addEventListener('click', function () { setOpen(item, btn.getAttribute('aria-expanded') !== 'true'); });
    return item;
  }
  function setOpen(item, open) {
    item.btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    item.body.hidden = !open;
  }

  function keyCounts(findings, field, preferred) {
    var counts = Object.create(null);
    var keys = [];
    findings.forEach(function (f) {
      var k = f[field];
      if (!k) { return; }
      if (!(k in counts)) { counts[k] = 0; keys.push(k); }
      counts[k]++;
    });
    keys.sort(function (a, b) {
      var ia = preferred.indexOf(a);
      var ib = preferred.indexOf(b);
      if (ia < 0) { ia = preferred.length; }
      if (ib < 0) { ib = preferred.length; }
      return (ia - ib) || cmpText(a, b);
    });
    return { keys: keys, counts: counts };
  }
  function fillSelect(select, info, label) {
    info.keys.forEach(function (k) {
      var option = el('option', null, label(k) + ' (' + info.counts[k] + ')');
      option.value = k;
      select.appendChild(option);
    });
  }
  function buildChips(findings, onToggle) {
    var host = byId('aw-chips');
    var counts = Object.create(null);
    var chips = Object.create(null);
    SEVERITIES.forEach(function (s) { counts[s] = 0; });
    findings.forEach(function (f) { counts[f.severity]++; });
    SEVERITIES.forEach(function (s) {
      var b = el('button', 'chip sev-' + s);
      var dot = el('span', 'dot');
      b.type = 'button';
      b.setAttribute('aria-pressed', 'false');
      dot.setAttribute('aria-hidden', 'true');
      append(b, dot, el('span', null, SEV_LABEL[s]), el('span', 'chip-count', String(counts[s])),
        el('span', 'sr-only', counts[s] === 1 ? ' finding' : ' findings'));
      b.disabled = counts[s] === 0;
      b.addEventListener('click', function () { onToggle(s); });
      host.appendChild(b);
      chips[s] = b;
    });
    return chips;
  }

  function setupFindings(findings, catTitles, catOrder) {
    var list = byId('aw-findings');
    var search = byId('aw-search');
    var catSelect = byId('aw-category');
    var harnessSelect = byId('aw-harness');
    var sortSelect = byId('aw-sort');
    var status = byId('aw-status');
    var empty = byId('aw-empty');
    var resetButton = byId('aw-reset');
    var view = { showCategory: function () {}, showRule: function () {} };
    var items = findings.map(function (f) { return buildFinding(f, catTitles); });
    function freshState(sort) { return { sev: Object.create(null), category: '', harness: '', query: '', sort: sort || 'severity' }; }
    var state = freshState();

    // Undo any form state the browser restored on reload.
    search.value = '';
    sortSelect.value = 'severity';

    if (!items.length) {
      byId('aw-filters').hidden = true;
      setText(status, 'No findings');
      setText(byId('aw-empty-text'), 'No findings: every rule that applies to the detected harnesses passed.');
      byId('aw-empty-reset').hidden = true;
      empty.hidden = false;
      return view;
    }

    var chips = buildChips(findings, function (s) {
      if (state.sev[s]) { delete state.sev[s]; } else { state.sev[s] = true; }
      apply();
    });
    fillSelect(catSelect, keyCounts(findings, 'category', catOrder), function (k) { return catTitles[k] || k; });
    fillSelect(harnessSelect, keyCounts(findings, 'harness', HARNESS_ORDER), harnessLabel);
    catSelect.value = '';
    harnessSelect.value = '';

    function apply() {
      var terms = state.query.toLowerCase().split(/\s+/).filter(Boolean);
      var anySev = SEVERITIES.some(function (s) { return state.sev[s] === true; });
      var shown = 0;
      items.forEach(function (it) {
        var f = it.f;
        var ok = (!anySev || state.sev[f.severity] === true) &&
          (!state.category || f.category === state.category) &&
          (!state.harness || f.harness === state.harness) &&
          terms.every(function (t) { return it.hay.indexOf(t) >= 0; });
        it.li.hidden = !ok;
        if (ok) { shown++; }
      });
      SEVERITIES.forEach(function (s) { chips[s].setAttribute('aria-pressed', state.sev[s] === true ? 'true' : 'false'); });
      resetButton.hidden = !(anySev || state.category || state.harness || terms.length);
      setText(status, shown === items.length ? 'Showing all ' + plural(items.length, 'finding')
        : 'Showing ' + shown + ' of ' + plural(items.length, 'finding'));
      setText(byId('aw-empty-text'), 'No findings match these filters.');
      empty.hidden = shown > 0;
    }
    function order() {
      var compare = has(SORTS, state.sort) ? SORTS[state.sort] : SORTS.severity;
      var frag = doc.createDocumentFragment();
      items.slice().sort(function (a, b) { return compare(a.f, b.f); }).forEach(function (it) { frag.appendChild(it.li); });
      list.appendChild(frag);
    }
    function reset() {
      state = freshState(state.sort);
      search.value = '';
      catSelect.value = '';
      harnessSelect.value = '';
      apply();
    }
    function focusList() { var h = byId('findings-title'); if (h) { h.focus(); } }

    search.addEventListener('input', function () { state.query = search.value; apply(); });
    search.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && search.value) { search.value = ''; state.query = ''; apply(); e.preventDefault(); }
    });
    catSelect.addEventListener('change', function () { state.category = catSelect.value; apply(); });
    harnessSelect.addEventListener('change', function () { state.harness = harnessSelect.value; apply(); });
    sortSelect.addEventListener('change', function () { state.sort = sortSelect.value; order(); });
    byId('aw-expand').addEventListener('click', function () { items.forEach(function (it) { setOpen(it, true); }); });
    byId('aw-collapse').addEventListener('click', function () { items.forEach(function (it) { setOpen(it, false); }); });
    resetButton.addEventListener('click', function () { reset(); search.focus(); });
    byId('aw-empty-reset').addEventListener('click', function () { reset(); search.focus(); });
    doc.addEventListener('keydown', function (e) {
      if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey || isEditable(e.target)) { return; }
      e.preventDefault();
      search.focus();
    });

    view.showCategory = function (id) { reset(); state.category = id; catSelect.value = id; apply(); focusList(); };
    view.showRule = function (id) { reset(); state.query = id; search.value = id; apply(); focusList(); };
    order();
    apply();
    return view;
  }

  function cell(tr, tag, label, content) {
    var c = el(tag);
    c.setAttribute('data-label', label);
    if (tag === 'th') { c.setAttribute('scope', 'row'); }
    if (typeof content === 'string') { c.textContent = visible(content); } else if (content) { c.appendChild(content); }
    tr.appendChild(c);
  }
  function renderRules(d, findings, catTitles, showRule) {
    var rules = arr(d.rules).map(obj);
    var tbody = byId('aw-rules');
    var minSev = sevOf(obj(d.options).minSeverity);
    var hits = Object.create(null);
    var perHarness = Object.create(null);
    var withFindings = 0;
    findings.forEach(function (f) { hits[f.ruleId] = (hits[f.ruleId] || 0) + 1; });
    rules.forEach(function (r) {
      var id = str(r.id);
      var h = str(r.harness);
      var s = sevOf(r.severity);
      var n = hits[id] || 0;
      if (n) { withFindings++; }
      perHarness[h] = (perHarness[h] || 0) + 1;
      var tr = el('tr');
      cell(tr, 'th', 'Rule', id);
      cell(tr, 'td', 'Title', str(r.title));
      cell(tr, 'td', 'Category', catTitles[str(r.category)] || str(r.category));
      cell(tr, 'td', 'Harness', harnessLabel(h));
      cell(tr, 'td', 'Severity', el('span', 'sev-badge sev-' + s, SEV_LABEL[s]));
      cell(tr, 'td', 'Confidence', str(r.confidence));
      cell(tr, 'td', 'Result', n ? button('link-btn', 'Show ' + plural(n, 'finding'), function () { showRule(id); })
        : el('span', 'pass', minSev === 'info' ? 'Passed' : 'Nothing at ' + minSev + ' or above'));
      tbody.appendChild(tr);
    });
    var coverage = byId('aw-coverage');
    if (!rules.length) {
      setText(coverage, 'No rule applies to the detected harnesses, so no rule was evaluated.');
      byId('aw-rules-wrap').hidden = true;
      return;
    }
    var extra = Object.keys(perHarness).filter(function (h) { return HARNESS_ORDER.indexOf(h) < 0; }).sort(cmpText);
    var perHarnessText = HARNESS_ORDER.concat(extra)
      .filter(function (h) { return perHarness[h]; })
      .map(function (h) { return harnessLabel(h) + ' ' + perHarness[h]; })
      .join(', ');
    setText(coverage, plural(rules.length, 'rule') + ' evaluated: ' + (rules.length - withFindings) +
      (minSev === 'info' ? ' passed, ' : ' without reported findings, ') + withFindings + ' with findings. Rules per harness: ' +
      perHarnessText + '.');
  }

  function start() {
    setupThemeToggle();
    var data = readData();
    if (!data) {
      showFatal('The report data could not be read. The file may be damaged or truncated: run Airworthy again to regenerate it.');
      return;
    }
    var catTitles = Object.create(null);
    var catOrder = [];
    arr(data.categories).forEach(function (c) {
      c = obj(c);
      catTitles[str(c.id)] = str(c.title) || str(c.id);
      catOrder.push(str(c.id));
    });
    var findings = arr(data.findings).map(normalizeFinding);
    renderHeader(data);
    renderScore(data);
    var view = setupFindings(findings, catTitles, catOrder);
    renderCategories(data, findings, view.showCategory);
    renderNotes(data, findings);
    renderRules(data, findings, catTitles, view.showRule);
  }

  if (doc.readyState === 'loading') { doc.addEventListener('DOMContentLoaded', start); } else { start(); }
})();
