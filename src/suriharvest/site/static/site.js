// suriharvest static site: theme switch and the client-side search over search-index.json.
// No inline scripts (CSP); results are built with textContent only, never innerHTML.
(function () {
  "use strict";
  var root = document.documentElement;

  function themeLabel() {
    var t = root.getAttribute("data-theme") || "auto";
    document.querySelectorAll("[data-theme-label]").forEach(function (el) { el.textContent = "Theme: " + t; });
  }
  function cycleTheme() {
    var order = ["auto", "light", "dark"], cur = root.getAttribute("data-theme") || "auto";
    var next = order[(order.indexOf(cur) + 1) % order.length];
    if (next === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", next);
    try { if (next === "auto") localStorage.removeItem("suriharvest-theme"); else localStorage.setItem("suriharvest-theme", next); } catch (e) { /* ignore */ }
    themeLabel();
  }

  var MAX = 500;

  function parse(q) {
    var f = { words: [], sid: null, source: null, licence: null, engine: null };
    (q.toLowerCase().match(/\S+/g) || []).forEach(function (tok) {
      var m = /^(sid|source|licence|license|engine):(.+)$/.exec(tok);
      if (!m) { f.words.push(tok); return; }
      var k = m[1] === "license" ? "licence" : m[1];
      f[k] = m[2];
    });
    return f;
  }

  function matches(r, f) {
    // r = [msg, gid, sid, source, licence, engines]
    if (f.sid !== null && String(r[2]) !== f.sid && (r[1] + ":" + r[2]) !== f.sid) return false;
    if (f.source !== null && String(r[3]).toLowerCase() !== f.source) return false;
    if (f.licence !== null && String(r[4] || "").toLowerCase().indexOf(f.licence) < 0) return false;
    if (f.engine !== null && r[5].indexOf(f.engine) < 0) return false;
    var hay = (r[0] + " " + r[2] + " " + r[3]).toLowerCase();
    for (var i = 0; i < f.words.length; i++) if (hay.indexOf(f.words[i]) < 0) return false;
    return true;
  }

  function cell(tr, text, cls) {
    var td = document.createElement("td");
    if (cls) td.className = cls;
    td.textContent = text;
    tr.appendChild(td);
  }

  // A licence expression with each SPDX id linked to its text ("BSD-3-Clause AND GPL-2.0-only").
  function licenceCell(tr, expr) {
    var td = document.createElement("td");
    td.className = "small";
    if (!expr) { td.textContent = "unknown"; tr.appendChild(td); return; }
    String(expr).split(/(\s+|[()])/).forEach(function (part) {
      if (/^[A-Za-z][A-Za-z0-9.+-]*$/.test(part) && !/^(AND|OR|WITH)$/.test(part) && part.indexOf("LicenseRef-") !== 0) {
        var a = document.createElement("a");
        a.href = "https://spdx.org/licenses/" + part + ".html";
        a.rel = "noopener";
        a.textContent = part;
        td.appendChild(a);
      } else if (part) {
        td.appendChild(document.createTextNode(part));
      }
    });
    tr.appendChild(td);
  }

  function search(table, status, rules, q) {
    var tbody = table.querySelector("tbody");
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    if (!q.trim()) { table.hidden = true; status.textContent = rules.length.toLocaleString() + " rules indexed. Type to search."; return; }
    var f = parse(q), n = 0;
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      if (!matches(r, f)) continue;
      n++;
      if (n > MAX) continue;
      var tr = document.createElement("tr");
      cell(tr, r[1] + ":" + r[2], "num mono");
      cell(tr, r[0]);
      cell(tr, r[3]);
      licenceCell(tr, r[4]);
      cell(tr, r[5].map(function (e) { return "Suricata " + e; }).join(", "), "small");
      tbody.appendChild(tr);
    }
    table.hidden = n === 0;
    status.textContent = n.toLocaleString() + " rule" + (n === 1 ? "" : "s") + (n > MAX ? " (first " + MAX + " shown)" : "");
  }

  function initSearch() {
    var table = document.getElementById("search-results");
    var input = document.getElementById("q");
    var status = document.getElementById("search-status");
    if (!table || !input || !status) return;
    var q = new URLSearchParams(location.search).get("q") || "";
    input.value = q;
    status.textContent = "Loading the index...";
    fetch(table.getAttribute("data-index"), { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (idx) {
        var rules = idx.rules || [], timer = null;
        search(table, status, rules, input.value);
        input.addEventListener("input", function () {
          clearTimeout(timer);
          timer = setTimeout(function () {
            search(table, status, rules, input.value);
            var u = new URL(location.href);
            if (input.value) u.searchParams.set("q", input.value); else u.searchParams.delete("q");
            history.replaceState(null, "", u);
          }, 150);
        });
      })
      .catch(function () { status.textContent = "The search index could not be loaded."; });
  }

  document.addEventListener("DOMContentLoaded", function () {
    themeLabel();
    document.addEventListener("click", function (ev) {
      var a = ev.target.closest("[data-action]");
      if (a && a.getAttribute("data-action") === "theme") cycleTheme();
    });
    initSearch();
  });
})();
