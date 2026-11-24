/* Certificate issuer — local UI. Talks only to this binary's own /api endpoints. */
(function () {
  "use strict";

  /* ---------------------------------------------------------------- helpers */

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = text; }
    return n;
  }

  function clear(node) { while (node && node.firstChild) { node.removeChild(node.firstChild); } }

  function button(cls, label, onClick) {
    var b = el("button", cls, label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  function dash(v) { return (v === undefined || v === null || v === "") ? "—" : String(v); }

  // A certificate code is one long unbreakable run of characters. Left whole it
  // would set the minimum width of whatever column holds it and push the layout
  // off the screen, so it is shown in short lines. The breaks are display only:
  // whitespace is ignored when a code or a key is read back, and the copy
  // buttons always hand over the unbroken string.
  var CHUNK = 28;

  function chunked(text, size) {
    var out = [];
    var s = String(text || "");
    for (var i = 0; i < s.length; i += size) { out.push(s.slice(i, i + size)); }
    return out.join("\n");
  }

  function codeBlock(text) { return el("pre", null, chunked(text, CHUNK)); }

  /* ------------------------------------------------------------------ theme */

  var root = document.documentElement;

  function storedTheme() { try { return localStorage.getItem("omsme-theme"); } catch (e) { return null; } }

  function currentTheme() {
    var t = root.getAttribute("data-theme");
    if (t) { return t; }
    return (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
  }

  function paintThemer(b) {
    if (!b) { return; }
    var dark = currentTheme() === "dark";
    b.textContent = dark ? "Light" : "Dark";
    b.setAttribute("aria-label", dark ? "Switch to the light theme" : "Switch to the dark theme");
  }

  var themer = document.querySelector("[data-themer]");
  if (themer) {
    paintThemer(themer);
    themer.addEventListener("click", function () {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("omsme-theme", next); } catch (e) { /* private browsing */ }
      paintThemer(themer);
    });
    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
        if (!storedTheme()) { paintThemer(themer); }
      });
    }
  }

  /* -------------------------------------------------------------------- api */

  function api(path, body) {
    var opts = { method: "GET", headers: {} };
    if (body !== undefined) {
      opts.method = "POST";
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (r) {
      return r.json().then(
        function (j) { return { ok: r.ok, status: r.status, body: j }; },
        function () { return { ok: false, status: r.status, body: { problems: ["The reply could not be read."] } }; }
      );
    }, function () {
      return { ok: false, status: 0, body: { problems: ["The tool is no longer running. Start it again and reload this page."] } };
    });
  }

  function notes(target, messages) {
    clear(target);
    if (!messages || !messages.length) { return; }
    messages.forEach(function (m) { target.appendChild(el("div", "note", m)); });
  }

  function copyText(text, btn, label) {
    function done(ok) {
      if (!btn) { return; }
      btn.textContent = ok ? "Copied" : "Select it and press Ctrl+C";
      window.setTimeout(function () { btn.textContent = label; }, 1800);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    } else {
      done(false);
    }
  }

  /* ------------------------------------------------------------------ views */

  var lastView = "issue";

  function go(name) {
    var views = document.querySelectorAll("[data-view]");
    var i;
    for (i = 0; i < views.length; i++) {
      views[i].hidden = views[i].getAttribute("data-view") !== name;
    }
    var btns = document.querySelectorAll("#nav button[data-goto]");
    for (i = 0; i < btns.length; i++) {
      btns[i].setAttribute("aria-pressed", btns[i].getAttribute("data-goto") === name ? "true" : "false");
    }
    if (name !== "sheet") { lastView = name; }
    window.scrollTo(0, 0);
  }

  $("nav").addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("button[data-goto]") : null;
    if (b) { go(b.getAttribute("data-goto")); }
  });

  /* ------------------------------------------------------------------ state */

  var batchHeaderLine = "learner_name,course,hours,grade,issued_on";

  var state = { institute: {}, certificates: [], covered: [], keyStatus: {}, today: "", dataFile: "" };

  function loadState() {
    return api("api/state").then(function (r) {
      if (!r.ok) { notes($("inst-msg"), r.body.problems); return; }
      state = r.body;
      renderInstitute();
      renderIssued();
      if (!$("iss-date").value) { $("iss-date").value = state.today || ""; }
      if (!$("batch-date").value) { $("batch-date").value = state.today || ""; }
      if (state.batchHeader) {
        batchHeaderLine = state.batchHeader;
        $("batch-header").textContent = batchHeaderLine.split(",").join("\n");
      }
    });
  }

  /* -------------------------------------------------------------- institute */

  function renderInstitute() {
    var inst = state.institute || {};
    var ks = state.keyStatus || {};

    if (document.activeElement !== $("inst-name")) { $("inst-name").value = inst.name || ""; }
    if (document.activeElement !== $("inst-prefix")) { $("inst-prefix").value = inst.idPrefix || ""; }
    if (document.activeElement !== $("inst-keyfile")) { $("inst-keyfile").value = inst.keyFile || ks.path || ""; }

    $("pubkey-out").textContent = inst.publicKey ? chunked(inst.publicKey, CHUNK) : "Not set up yet.";
    $("pubkey-dl").hidden = !inst.publicKey;
    $("pubkey-copy").hidden = !inst.publicKey;

    var messages = [];
    if (!ks.exists) {
      messages.push("There is no key file at " + dash(ks.path) + " yet. Generate one to start issuing.");
    } else {
      if (ks.permsTooWide) {
        messages.push("The key file " + ks.path + " has permissions " + ks.mode +
          ", so other users of this machine can read it. Anyone who reads it can issue certificates in your name. Tighten it to 0600.");
      }
      if (ks.problem) {
        messages.push(ks.problem);
      }
      if (!ks.permsTooWide && !ks.problem) {
        messages.push("Key file " + ks.path + ", permissions " + ks.mode + ", owner only. Back this file up somewhere safe.");
      }
    }
    notes($("key-status"), messages);
  }

  function setUp(mode) {
    api("api/institute", {
      name: $("inst-name").value,
      idPrefix: $("inst-prefix").value,
      keyFile: $("inst-keyfile").value,
      mode: mode,
      replaceKey: $("inst-replace").checked
    }).then(function (r) {
      if (!r.ok) { notes($("inst-msg"), r.body.problems); return; }
      var messages = (r.body.warnings || []).slice();
      messages.unshift(mode === "generate"
        ? "A new signing key was generated and saved with owner-only permissions. Back up that file: without it you cannot issue any more certificates under this public key."
        : "The key in that file was loaded. You can issue certificates.");
      notes($("inst-msg"), messages);
      $("inst-replace").checked = false;
      loadState();
    });
  }

  $("inst-generate").addEventListener("click", function () { setUp("generate"); });
  $("inst-load").addEventListener("click", function () { setUp("load"); });
  $("pubkey-copy").addEventListener("click", function () {
    copyText((state.institute || {}).publicKey || "", $("pubkey-copy"), "Copy the key");
  });

  /* ------------------------------------------------------------------ issue */

  function detailsTable(c) {
    var t = el("table", "breakdown");
    var tb = el("tbody");
    [
      ["Certificate number", c.id],
      ["Learner", c.learnerName],
      ["Course", c.course],
      ["Course hours", String(c.hours)],
      ["Grade or result", dash(c.grade)],
      ["Issue date", c.issuedOn],
      ["Institute", c.issuerName]
    ].forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("th", null, row[0]));
      tr.appendChild(el("td", null, dash(row[1])));
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    return t;
  }

  function renderIssueResult(c) {
    var out = $("iss-out");
    clear(out);

    var card = el("div", "result-primary");
    card.appendChild(el("div", "k", "Signed and issued"));
    card.appendChild(el("div", "v", c.id));
    card.appendChild(el("div", "sub", c.learnerName + " · " + c.course));
    out.appendChild(card);

    out.appendChild(detailsTable(c));
    out.appendChild(el("h3", null, "Verification code"));
    out.appendChild(codeBlock(c.code));

    var row = el("div", "btnrow");
    row.appendChild(button("btn primary", "Printable certificate", function () { openSheet(c); }));
    var copy = button("btn ghost", "Copy the code", function () { copyText(c.code, copy, "Copy the code"); });
    row.appendChild(copy);
    out.appendChild(row);
    out.appendChild(el("p", "assumptions",
      "Give the learner the code along with the certificate. An employer checks it on the Verify screen, or with the command line, using your published public key."));
  }

  $("iss-go").addEventListener("click", function () {
    api("api/issue", {
      learnerName: $("iss-learner").value,
      course: $("iss-course").value,
      hours: parseInt($("iss-hours").value, 10) || 0,
      grade: $("iss-grade").value,
      issuedOn: $("iss-date").value
    }).then(function (r) {
      if (!r.ok) { notes($("iss-msg"), r.body.problems); return; }
      clear($("iss-msg"));
      renderIssueResult(r.body.certificate);
      $("iss-learner").value = "";
      $("iss-grade").value = "";
      $("iss-learner").focus();
      loadState();
    });
  });

  $("iss-clear").addEventListener("click", function () {
    ["iss-learner", "iss-course", "iss-grade"].forEach(function (id) { $(id).value = ""; });
    $("iss-hours").value = "0";
    $("iss-date").value = state.today || "";
    clear($("iss-msg"));
  });

  /* ----------------------------------------------------------------- verify */

  function renderVerify(res) {
    var out = $("ver-out");
    clear(out);

    var verdict = res.pass ? "PASS" : (res.checkedAgainst ? "FAIL" : "NOT CHECKED");
    if (res.pass) {
      var card = el("div", "result-primary");
      card.appendChild(el("div", "k", "Verified against the public key you supplied"));
      card.appendChild(el("div", "v", verdict));
      card.appendChild(el("div", "sub", res.reason));
      out.appendChild(card);
    } else {
      var box = el("div", "note");
      box.appendChild(el("strong", null, verdict + " — "));
      box.appendChild(document.createTextNode(res.reason));
      out.appendChild(box);
    }

    if (res.certificate) {
      out.appendChild(el("h3", null, "What the code says"));
      out.appendChild(detailsTable(res.certificate));
      out.appendChild(el("h3", null, "Signed with public key"));
      out.appendChild(codeBlock(res.certificate.issuerPubKey));
    }

    if (res.covered && res.covered.length) {
      var d = el("details", "assumptions");
      d.appendChild(el("summary", null, "Which details this signature covers (" + res.covered.length + ")"));
      var ul = el("ul");
      res.covered.forEach(function (f) { ul.appendChild(el("li", null, f.label)); });
      d.appendChild(ul);
      d.appendChild(el("p", null,
        "Nothing outside this list is covered: not a photograph, not a letterhead, not any claim of accreditation."));
      out.appendChild(d);
    }

    if (!res.pass && res.selfConsistent) {
      out.appendChild(el("div", "note",
        "The code is internally consistent — it was signed by the key printed inside it. That proves nothing about who issued it, " +
        "because anyone can make a key and sign their own text with it. Compare that key against the one the institute published."));
    }
  }

  $("ver-go").addEventListener("click", function () {
    api("api/verify", { code: $("ver-code").value, publicKey: $("ver-key").value })
      .then(function (r) {
        if (!r.ok) { notes($("ver-out"), r.body.problems); return; }
        renderVerify(r.body);
      });
  });

  $("ver-mine").addEventListener("click", function () {
    $("ver-key").value = (state.institute || {}).publicKey || "";
  });

  $("ver-clear").addEventListener("click", function () {
    $("ver-code").value = "";
    $("ver-key").value = "";
    clear($("ver-out"));
    $("ver-out").appendChild(el("p", "assumptions",
      "Paste a code and the institute's public key to see whether the certificate is genuine and unaltered."));
  });

  /* ------------------------------------------------------------------ batch */

  function renderBatch(b) {
    var out = $("batch-out");
    clear(out);

    var card = el("div", "result-primary");
    card.appendChild(el("div", "k", "Signed and issued"));
    card.appendChild(el("div", "v", String(b.issued)));
    card.appendChild(el("div", "sub", b.skipped + " row(s) skipped because of a problem"));
    out.appendChild(card);

    var t = el("table", "breakdown");
    var head = el("tr");
    ["Line", "Learner", "Outcome", ""].forEach(function (h) { head.appendChild(el("th", null, h)); });
    var thead = el("thead");
    thead.appendChild(head);
    t.appendChild(thead);

    var tb = el("tbody");
    (b.results || []).forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("td", "num", String(r.line)));
      tr.appendChild(el("td", null, dash(r.learnerName)));
      if (r.issued) {
        tr.appendChild(el("td", null, r.certificate.id));
        var td = el("td");
        td.appendChild(button("btn ghost", "Open", function () { openSheet(r.certificate); }));
        tr.appendChild(td);
      } else {
        tr.appendChild(el("td", null, (r.problems || []).join(" ")));
        tr.appendChild(el("td", null, ""));
      }
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    out.appendChild(t);
  }

  $("batch-go").addEventListener("click", function () {
    var input = $("batch-file");
    var file = input.files && input.files[0];
    if (!file) {
      notes($("batch-msg"), ["Choose a CSV file first."]);
      return;
    }
    var reader = new FileReader();
    reader.onerror = function () { notes($("batch-msg"), ["That file could not be read."]); };
    reader.onload = function () {
      api("api/issue-batch", { csv: String(reader.result), issuedOn: $("batch-date").value })
        .then(function (r) {
          if (!r.ok) { notes($("batch-msg"), r.body.problems); clear($("batch-out")); return; }
          clear($("batch-msg"));
          renderBatch(r.body);
          loadState();
        });
    };
    reader.readAsText(file);
  });

  $("batch-copy-header").addEventListener("click", function () {
    copyText(batchHeaderLine, $("batch-copy-header"), "Copy the header line");
  });

  /* ----------------------------------------------------------------- issued */

  function renderIssued() {
    var out = $("issued-out");
    clear(out);
    var list = state.certificates || [];
    if (!list.length) {
      out.appendChild(el("p", "assumptions", "Nothing issued yet."));
      return;
    }
    out.appendChild(el("p", "assumptions",
      list.length + " certificate(s), newest first, stored in " + dash(state.dataFile)));

    var t = el("table", "breakdown");
    var head = el("tr");
    ["Number", "Learner", "Issued", ""].forEach(function (h) { head.appendChild(el("th", null, h)); });
    var thead = el("thead");
    thead.appendChild(head);
    t.appendChild(thead);

    var tb = el("tbody");
    list.forEach(function (c) {
      var tr = el("tr");
      tr.appendChild(el("td", null, c.id));
      tr.appendChild(el("td", null, c.learnerName));
      tr.appendChild(el("td", "num", c.issuedOn));
      var td = el("td");
      td.appendChild(button("btn ghost", "Open", function () { openSheet(c); }));
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    out.appendChild(t);
  }

  /* ------------------------------------------------------------ print sheet */

  var sheetCode = "";

  function openSheet(c) {
    sheetCode = c.code;
    $("sheet-institute").textContent = c.issuerName;
    $("sheet-learner").textContent = c.learnerName;
    $("sheet-sub").textContent = "has completed " + c.course +
      (c.hours ? " · " + c.hours + " hours" : "") +
      (c.grade ? " · " + c.grade : "");

    var rows = $("sheet-rows");
    clear(rows);
    [
      ["Certificate number", c.id],
      ["Course", c.course],
      ["Course hours", String(c.hours)],
      ["Grade or result", dash(c.grade)],
      ["Issue date", c.issuedOn],
      ["Issued by", c.issuerName]
    ].forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("th", null, row[0]));
      tr.appendChild(el("td", null, dash(row[1])));
      rows.appendChild(tr);
    });

    $("sheet-code").textContent = chunked(c.code, CHUNK);
    $("sheet-key").textContent = chunked(c.issuerPubKey, CHUNK);
    $("sheet-howto").textContent =
      "To check this certificate, verify the code above against the institute public key above — on the Verify screen of this tool, " +
      "or by running verifiable-cert-issuer with -verify and -pubkey. Line breaks in the code and the key are there to make them readable " +
      "and are ignored. A valid result means the certificate was signed by the holder of that key and that none of the details above have " +
      "been altered since it was issued. It does not prove that the institute is accredited.";

    go("sheet");
  }

  $("sheet-copy").addEventListener("click", function () {
    copyText(sheetCode, $("sheet-copy"), "Copy the code");
  });

  $("sheet-back").addEventListener("click", function () { go(lastView); });

  // The page has no print stylesheet of its own, so the surrounding chrome is
  // hidden with the hidden attribute for the duration of the print and put
  // back afterwards. Only the certificate itself is left on the sheet.
  $("sheet-print").addEventListener("click", function () {
    var chrome = document.querySelectorAll("[data-chrome]");
    function restore() {
      for (var j = 0; j < chrome.length; j++) { chrome[j].hidden = false; }
      window.removeEventListener("afterprint", restore);
    }
    for (var i = 0; i < chrome.length; i++) { chrome[i].hidden = true; }
    window.addEventListener("afterprint", restore);
    window.setTimeout(restore, 20000);
    window.print();
  });

  /* ------------------------------------------------------------------ start */

  loadState().then(function () {
    if (!(state.institute || {}).publicKey) { go("institute"); }
  });
})();
