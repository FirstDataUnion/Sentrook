/*
 * Sentrook dashboard view (read-only). The same file ships in the OpenClaw plugin (dashboardView.js, drawn in a
 * Control UI tab) and the Hermes plugin (dashboard/dist/index.js, a Hermes dashboard tab); a test keeps the two
 * copies identical. It draws the model the plugin builds from its traffic log. All text goes in through
 * textContent, never as HTML. No network access of its own: OpenClaw embeds the model in the page, Hermes
 * fetches it with the dashboard SDK from the plugin's own API.
 */
(function () {
  "use strict";

  var TIER_INFO = {
    suspicion: {
      label: "Suspicion",
      help: "How much the call looks like it serves a goal the owner did not set. Higher is worse.",
      combine: "Any one signal can raise it: each adds to what the others leave.",
      worse: "high",
    },
    consequence: {
      label: "Consequence",
      help: "The worst harm if the call runs. Higher is worse.",
      combine: "The largest of sensitivity × reach, irreversibility × reach, and self-modification.",
      worse: "high",
    },
    confidence: {
      label: "Confidence",
      help: "How much to trust the other two scores. Higher is better; low confidence adds risk on its own.",
      combine: "The lowest of agreement, coverage and model certainty.",
      worse: "low",
    },
  };

  var LEAF_INFO = {
    misalignment: ["Misalignment", "The call does not fit what the owner asked for"],
    concealment: ["Concealment", "The call hides or disguises what it does"],
    overreach: ["Overreach", "The call acts on more than the request covers"],
    distrust: ["Distrust", "The destination or target is not trusted"],
    request_origin: ["Request origin", "The request did not come from the owner"],
    retry_after_denial: ["Retry after denial", "The agent is retrying something that was refused"],
    untrusted_origin: ["Untrusted origin", "Part of the call comes from untrusted content"],
    exposure: ["Exposure", "This scan's new untrusted inputs carried instructions for the agent"],
    session_exposure: ["Session exposure", "Earlier in this session the agent read content carrying instructions"],
    sensitivity: ["Sensitivity", "How sensitive the data or resource is"],
    reach: ["Reach", "How far the effect goes beyond this machine"],
    irreversibility: ["Irreversibility", "How hard the effect is to undo"],
    self_modification: ["Self-modification", "The call changes the agent's own skills, memory or config"],
    agreement: ["Agreement", "How far the scanner's checks agree with each other"],
    coverage: ["Coverage", "How much of the call the checks could see"],
    model_certainty: ["Model certainty", "How sure the model check was"],
  };

  var TAINT = ["untrusted_origin", "exposure", "session_exposure"];

  var BUCKETS = [
    ["blocked", "Blocked"],
    ["review", "Review"],
    ["observed", "Observed"],
    ["allowed", "Allowed"],
    ["scan_error", "Scan error"],
  ];

  var CSS = [
    ".srk{--srk-fg:currentColor;--srk-muted:var(--color-muted-foreground,#7b828c);",
    "--srk-card:var(--color-card,#ffffff);--srk-soft:var(--color-muted,#f2f3f5);--srk-border:var(--color-border,#dfe2e6);",
    "--srk-low:var(--color-success,#2f9e6b);--srk-mid:var(--color-warning,#d9930d);--srk-high:var(--color-destructive,#d64545);",
    "--srk-accent:var(--color-primary,#3b6fd9);--srk-radius:var(--radius,10px);",
    "color:inherit;font:14px/1.45 system-ui,-apple-system,'Segoe UI',sans-serif;max-width:1100px;margin:0 auto;padding:16px;box-sizing:border-box}",
    ".srk *{box-sizing:border-box}",
    // Hosts style code elements page-wide; start ours from nothing.
    ".srk code{all:unset;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}",
    ".srk-standalone{--srk-fg:#1c1e21;--srk-muted:#646b75;--srk-card:#ffffff;--srk-soft:#f2f3f5;--srk-border:#dfe2e6;",
    "--srk-low:#2f9e6b;--srk-mid:#c98a0b;--srk-high:#d64545;--srk-accent:#3b6fd9;--srk-radius:10px;color:var(--srk-fg)}",
    "@media (prefers-color-scheme:dark){.srk-standalone{--srk-fg:#e6e8eb;--srk-muted:#9aa1ab;--srk-card:#1b1e23;",
    "--srk-soft:#252a31;--srk-border:#323840;--srk-low:#4cc38a;--srk-mid:#e5a93a;--srk-high:#f06a6a;--srk-accent:#7aa2ff}}",
    "html.srk-page,html.srk-page body{margin:0;background:#f7f8fa}",
    "@media (prefers-color-scheme:dark){html.srk-page,html.srk-page body{background:#121418}}",
    ".srk h1{font-size:20px;margin:0}.srk h2{font-size:15px;margin:22px 0 8px}",
    ".srk-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px 16px;margin-bottom:6px}",
    ".srk-sub{color:var(--srk-muted);font-size:13px}",
    ".srk-bar-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0}",
    ".srk-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--srk-border);border-radius:999px;",
    "padding:2px 10px;font-size:12px;background:var(--srk-card);white-space:nowrap}",
    ".srk-chip b{font-variant-numeric:tabular-nums}",
    ".srk-dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--srk-muted)}",
    ".srk-btn{font:inherit;font-size:12px;border:1px solid var(--srk-border);background:var(--srk-card);color:inherit;",
    "border-radius:6px;padding:3px 10px;cursor:pointer}.srk-btn[aria-pressed=true]{border-color:var(--srk-accent);color:var(--srk-accent)}",
    ".srk-spacer{flex:1}",
    ".srk-list{display:flex;flex-direction:column;gap:8px}",
    ".srk-scan{border:1px solid var(--srk-border);border-radius:var(--srk-radius);background:var(--srk-card);overflow:hidden}",
    ".srk-row{display:flex;gap:12px;align-items:center;width:100%;padding:10px 12px;background:none;border:0;color:inherit;",
    "font:inherit;text-align:left;cursor:pointer}.srk-row:hover{background:var(--srk-soft)}",
    ".srk-row:focus-visible{outline:2px solid var(--srk-accent);outline-offset:-2px}",
    ".srk-risk{flex:none;width:46px;height:46px;border-radius:50%;display:grid;place-items:center;font-weight:700;",
    "font-size:15px;font-variant-numeric:tabular-nums;border:3px solid var(--srk-muted)}",
    ".srk-main{flex:1;min-width:0}.srk-tool{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
    ".srk-meta{color:var(--srk-muted);font-size:12px;display:flex;flex-wrap:wrap;gap:4px 10px}",
    ".srk-action{flex:none;font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;background:var(--srk-soft)}",
    ".srk-caret{flex:none;color:var(--srk-muted);transition:transform .15s}.srk-open .srk-caret{transform:rotate(90deg)}",
    ".srk-detail{border-top:1px solid var(--srk-border);padding:14px 14px 16px}",
    ".srk-meter{position:relative;height:14px;border-radius:7px;overflow:hidden;display:flex;margin:6px 0 4px}",
    ".srk-zone{height:100%;opacity:.22}.srk-marker{position:absolute;top:-3px;bottom:-3px;width:4px;border-radius:2px;",
    "background:currentColor;box-shadow:0 0 0 2px var(--srk-card)}",
    ".srk-scale{display:flex;justify-content:space-between;color:var(--srk-muted);font-size:11px;font-variant-numeric:tabular-nums}",
    ".srk-formula{margin:12px 0;padding:8px 12px;border-radius:8px;background:var(--srk-soft);font-size:13px}",
    ".srk-formula code{font:600 13px ui-monospace,SFMono-Regular,Menlo,monospace}",
    ".srk-tiers{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px}",
    ".srk-tier{border:1px solid var(--srk-border);border-radius:var(--srk-radius);padding:10px 12px;background:var(--srk-card)}",
    ".srk-tier>summary{list-style:none;cursor:pointer}.srk-tier>summary::-webkit-details-marker{display:none}",
    ".srk-tier-top{display:flex;align-items:baseline;justify-content:space-between;gap:8px}",
    ".srk-tier-name{font-weight:700}.srk-tier-score{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}",
    ".srk-help{color:var(--srk-muted);font-size:12px;margin:2px 0 6px}",
    ".srk-track{height:8px;border-radius:4px;background:var(--srk-soft);overflow:hidden}",
    ".srk-fill{height:100%;border-radius:4px}",
    ".srk-leaves{margin-top:10px;display:flex;flex-direction:column;gap:8px}",
    ".srk-leaf-top{display:flex;justify-content:space-between;gap:8px;font-size:13px}",
    ".srk-leaf-val{font-variant-numeric:tabular-nums;font-weight:600}",
    ".srk-na .srk-leaf-val{font-weight:400;color:var(--srk-muted);font-style:italic}",
    ".srk-na .srk-track{background:repeating-linear-gradient(45deg,var(--srk-soft) 0 4px,transparent 4px 8px)}",
    ".srk-group{border-left:3px solid var(--srk-border);padding-left:8px;display:flex;flex-direction:column;gap:8px}",
    ".srk-group-title{font-size:12px;color:var(--srk-muted)}",
    ".srk-reasons{display:flex;flex-direction:column;gap:3px;margin-top:4px}",
    ".srk-reason{font-size:12px;padding:3px 8px;border-radius:6px;background:var(--srk-soft)}",
    ".srk-reason code{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--srk-muted);margin-right:6px}",
    ".srk-kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;font-size:13px}",
    ".srk-kv dt{color:var(--srk-muted)}.srk-kv dd{margin:0;overflow-wrap:anywhere}",
    ".srk-pre{color:inherit;white-space:pre-wrap;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--srk-card);",
    "border:1px solid var(--srk-border);border-radius:var(--srk-radius);padding:10px 12px;margin:0}",
    ".srk-empty{color:var(--srk-muted);padding:24px;text-align:center;border:1px dashed var(--srk-border);border-radius:var(--srk-radius)}",
    ".srk-note{color:var(--srk-muted);font-size:12px;margin-top:20px}",
    "@media (max-width:560px){.srk-caret{display:none}.srk-row{gap:10px}.srk-action{font-size:11px;padding:2px 8px;max-width:40%;white-space:normal;text-align:center}}",
  ].join("\n");

  function el(tag, attrs, kids) {
    var node = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k) || attrs[k] == null) continue;
        if (k === "class") node.className = attrs[k];
        else if (k === "text") node.textContent = String(attrs[k]);
        else if (k === "style") node.setAttribute("style", attrs[k]);
        else if (k.slice(0, 2) === "on") node.addEventListener(k.slice(2), attrs[k]);
        else node.setAttribute(k, String(attrs[k]));
      }
    }
    (kids || []).forEach(function (kid) {
      if (kid == null || kid === false) return;
      node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    });
    return node;
  }

  function ensureStyle(doc) {
    if (doc.getElementById("srk-style")) return;
    var s = doc.createElement("style");
    s.id = "srk-style";
    s.textContent = CSS;
    (doc.head || doc.documentElement).appendChild(s);
  }

  function pct(v) {
    return v == null ? null : Math.round(v * 100);
  }

  /** Colour for a 0-100 risk against the plugin's review and block lines. */
  function riskColour(risk, lines) {
    if (risk == null) return "var(--srk-muted)";
    if (risk >= lines.block_at) return "var(--srk-high)";
    if (risk >= lines.review_at) return "var(--srk-mid)";
    return "var(--srk-low)";
  }

  /** Colour for a 0-1 score; `worse` says whether high or low values are the bad end. */
  function scoreColour(v, worse) {
    if (v == null) return "var(--srk-muted)";
    var bad = worse === "low" ? 1 - v : v;
    if (bad >= 0.6) return "var(--srk-high)";
    if (bad >= 0.3) return "var(--srk-mid)";
    return "var(--srk-low)";
  }

  function bucketColour(bucket) {
    return {
      blocked: "var(--srk-high)",
      review: "var(--srk-mid)",
      observed: "var(--srk-accent)",
      allowed: "var(--srk-low)",
      scan_error: "var(--srk-muted)",
    }[bucket] || "var(--srk-muted)";
  }

  function when(ts) {
    if (!ts) return "unknown time";
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
  }

  function fill(text, entities) {
    if (!text) return text;
    return text.replace(/\{(E\d+)\}/g, function (m, id) {
      for (var i = 0; i < entities.length; i++) if (entities[i].id === id) return entities[i].display;
      return m;
    });
  }

  function bar(v, colour) {
    return el("div", { class: "srk-track" }, [
      el("div", { class: "srk-fill", style: "width:" + (v == null ? 0 : Math.max(2, pct(v))) + "%;background:" + colour }),
    ]);
  }

  function reasonList(reasons, entities) {
    if (!reasons.length) return null;
    return el(
      "div",
      { class: "srk-reasons" },
      reasons.map(function (r) {
        return el("div", { class: "srk-reason" }, [el("code", { text: r.code }), fill(r.text, entities) || ""]);
      }),
    );
  }

  function leafRow(tier, leaf, reasons, entities) {
    var info = LEAF_INFO[leaf.name] || [leaf.name.replace(/_/g, " "), ""];
    var colour = scoreColour(leaf.value, TIER_INFO[tier] ? TIER_INFO[tier].worse : "high");
    var mine = reasons.filter(function (r) {
      return r.signal === tier + "." + leaf.name;
    });
    return el("div", { class: "srk-leaf" + (leaf.value == null ? " srk-na" : ""), title: info[1] }, [
      el("div", { class: "srk-leaf-top" }, [
        el("span", { text: info[0] }),
        el("span", { class: "srk-leaf-val", text: leaf.value == null ? "not assessed" : String(pct(leaf.value)) }),
      ]),
      bar(leaf.value, colour),
      reasonList(mine, entities),
    ]);
  }

  function tierCard(tier, scan) {
    var info = TIER_INFO[tier.name] || { label: tier.name, help: "", combine: "", worse: "high" };
    var leaves = tier.leaves.filter(function (l) {
      return TAINT.indexOf(l.name) < 0 || tier.name !== "suspicion";
    });
    var taint = tier.name === "suspicion"
      ? tier.leaves.filter(function (l) {
          return TAINT.indexOf(l.name) >= 0;
        })
      : [];
    var rows = leaves.map(function (l) {
      return leafRow(tier.name, l, scan.reasons, scan.entities);
    });
    if (taint.length) {
      rows.push(
        el("div", { class: "srk-group" }, [
          el("div", { class: "srk-group-title", text: "Untrusted content: untrusted origin × the larger of exposure and session exposure" }),
        ].concat(
          taint.map(function (l) {
            return leafRow(tier.name, l, scan.reasons, scan.entities);
          }),
        )),
      );
    }
    var colour = scoreColour(tier.score, info.worse);
    return el("details", { class: "srk-tier", open: "" }, [
      el("summary", null, [
        el("div", { class: "srk-tier-top" }, [
          el("span", { class: "srk-tier-name", text: info.label }),
          el("span", { class: "srk-tier-score", style: "color:" + colour, text: tier.score == null ? "–" : String(pct(tier.score)) }),
        ]),
        el("div", { class: "srk-help", text: info.help }),
        bar(tier.score, colour),
      ]),
      el("div", { class: "srk-help", style: "margin-top:8px", text: info.combine }),
      el("div", { class: "srk-leaves" }, rows),
    ]);
  }

  function meter(scan, lines) {
    var risk = scan.risk;
    var r = Math.min(Math.max(lines.review_at, 0), 100);
    var b = Math.min(Math.max(lines.block_at, r), 100);
    return el("div", null, [
      el("div", { class: "srk-meter", role: "img", "aria-label": "Risk " + (risk == null ? "unknown" : Math.round(risk)) + " of 100" }, [
        el("div", { class: "srk-zone", style: "width:" + r + "%;background:var(--srk-low)" }),
        el("div", { class: "srk-zone", style: "width:" + (b - r) + "%;background:var(--srk-mid)" }),
        el("div", { class: "srk-zone", style: "width:" + (100 - b) + "%;background:var(--srk-high)" }),
        risk == null ? null : el("div", { class: "srk-marker", style: "left:calc(" + Math.min(Math.max(risk, 0), 100) + "% - 2px)" }),
      ]),
      el("div", { class: "srk-scale" }, [
        el("span", { text: "0" }),
        el("span", { text: "review at " + lines.review_at + " · block at " + lines.block_at }),
        el("span", { text: "100" }),
      ]),
    ]);
  }

  function chips(scan) {
    var out = [];
    scan.floors.forEach(function (f) {
      out.push(el("span", { class: "srk-chip", title: "A scanner floor raised the risk to at least this value" }, [
        el("span", { class: "srk-dot", style: "background:var(--srk-high)" }),
        "Floor: " + (f.floor || "?") + (f.min_risk == null ? "" : " ≥ " + pct(f.min_risk)),
      ]));
    });
    scan.relief.forEach(function (f) {
      out.push(el("span", { class: "srk-chip", title: "A grant or a destination named in the request lowered a score" }, [
        el("span", { class: "srk-dot", style: "background:var(--srk-low)" }),
        "Relief: " + (f.effect || "?") + (f.grant_ref ? " (grant " + f.grant_ref + ")" : ""),
      ]));
    });
    if (scan.enforced) out.push(el("span", { class: "srk-chip" }, ["Scanner requires: " + scan.enforced]));
    if (scan.ceiling) out.push(el("span", { class: "srk-chip", title: "The owner was present, so the plugin asks at most" }, ["At most: " + scan.ceiling]));
    scan.flags.forEach(function (f) {
      out.push(el("span", { class: "srk-chip" }, [f.replace(/_/g, " ")]));
    });
    return out.length ? el("div", { class: "srk-bar-row" }, out) : null;
  }

  function detail(scan, model) {
    var kids = [];
    if (scan.failure != null) {
      kids.push(el("p", { text: "The scan failed (" + scan.failure + "), so there are no scores. The plugin applied its scan-error setting." }));
    } else {
      kids.push(el("div", { class: "srk-tier-top" }, [
        el("span", { class: "srk-tier-name", text: "Risk" }),
        el("span", { class: "srk-tier-score", style: "color:" + riskColour(scan.risk, model.lines), text: scan.risk == null ? "–" : String(Math.round(scan.risk)) }),
      ]));
      kids.push(meter(scan, model.lines));
      kids.push(chips(scan));
      kids.push(el("div", { class: "srk-formula" }, [
        el("code", { text: "risk = consequence × max(suspicion, uncertainty)" }),
        el("div", { class: "srk-help", style: "margin:4px 0 0", text: "Uncertainty grows as confidence falls. Floors can raise the result; relief from grants can lower a score." }),
      ]));
      kids.push(el("div", { class: "srk-tiers" }, scan.tiers.map(function (t) {
        return tierCard(t, scan);
      })));
      var known = {};
      scan.tiers.forEach(function (t) {
        t.leaves.forEach(function (l) {
          known[t.name + "." + l.name] = true;
        });
      });
      var other = scan.reasons.filter(function (r) {
        return !r.signal || !known[r.signal];
      });
      if (other.length) {
        kids.push(el("h2", { text: "Other reasons" }));
        kids.push(reasonList(other, scan.entities));
      }
    }
    var facts = [
      ["Scan id", scan.id],
      ["Time", when(scan.ts)],
      ["Session", scan.session || "–"],
      ["Step", scan.step == null ? "–" : String(scan.step)],
      ["Mode", scan.mode || "–"],
      ["Action", scan.action],
      ["Review", scan.review],
    ];
    scan.entities.forEach(function (e) {
      facts.push([e.id + (e.kind ? " (" + e.kind + ")" : ""), e.display]);
    });
    kids.push(el("h2", { text: "Details" }));
    kids.push(el("dl", { class: "srk-kv" }, facts.reduce(function (acc, f) {
      acc.push(el("dt", { text: f[0] }), el("dd", { text: f[1] }));
      return acc;
    }, [])));
    return el("div", { class: "srk-detail" }, kids);
  }

  function scanCard(scan, model, open) {
    var card = el("div", { class: "srk-scan" + (open.has(scan.id) ? " srk-open" : "") });
    var body = null;
    var colour = riskColour(scan.risk, model.lines);
    var row = el("button", { class: "srk-row", type: "button", "aria-expanded": open.has(scan.id) ? "true" : "false" }, [
      el("span", { class: "srk-risk", style: "border-color:" + colour + ";color:" + colour, title: "Risk", text: scan.risk == null ? "–" : String(Math.round(scan.risk)) }),
      el("span", { class: "srk-main" }, [
        el("div", { class: "srk-tool", text: scan.tool || "unknown tool" }),
        el("div", { class: "srk-meta" }, [
          el("span", { text: when(scan.ts) }),
          scan.session ? el("span", { text: "session " + scan.session }) : null,
          scan.review !== "-" ? el("span", { text: "review: " + scan.review }) : null,
        ]),
      ]),
      el("span", { class: "srk-action", style: "color:" + bucketColour(scan.bucket), text: scan.action }),
      el("span", { class: "srk-caret", "aria-hidden": "true", text: "›" }),
    ]);
    function toggle() {
      if (open.has(scan.id)) {
        open.delete(scan.id);
        if (body) card.removeChild(body);
        body = null;
      } else {
        open.add(scan.id);
        body = detail(scan, model);
        card.appendChild(body);
      }
      card.className = "srk-scan" + (open.has(scan.id) ? " srk-open" : "");
      row.setAttribute("aria-expanded", open.has(scan.id) ? "true" : "false");
    }
    row.addEventListener("click", toggle);
    card.appendChild(row);
    if (open.has(scan.id)) {
      body = detail(scan, model);
      card.appendChild(body);
    }
    return card;
  }

  function render(root, model, opts) {
    ensureStyle(root.ownerDocument || document);
    opts = opts || {};
    model = model || {};
    model.scans = model.scans || [];
    model.totals = model.totals || {};
    model.lines = model.lines || { review_at: 45, block_at: 80 };
    var open = opts.open || new Set();
    // The newest scan opens on first draw; later draws keep what the viewer opened or closed.
    if (opts.openFirst !== false && !open.size && model.scans.length) open.add(model.scans[0].id);
    while (root.firstChild) root.removeChild(root.firstChild);
    root.className = "srk" + (opts.standalone ? " srk-standalone" : "");
    var c = model.commands || {};
    root.appendChild(el("div", { class: "srk-head" }, [
      el("h1", { text: "Sentrook" }),
      el("span", { class: "srk-sub", text: "Recent scans, newest first · read-only · mode: " + (model.mode || "?") }),
    ]));
    var counts = BUCKETS.filter(function (b) {
      return model.totals[b[0]];
    }).map(function (b) {
      return el("span", { class: "srk-chip" }, [el("span", { class: "srk-dot", style: "background:" + bucketColour(b[0]) }), b[1], el("b", { text: String(model.totals[b[0]]) })]);
    });
    var limits = [10, 25, 50].map(function (n) {
      return el("button", {
        class: "srk-btn",
        type: "button",
        "aria-pressed": model.limit === n ? "true" : "false",
        text: "Last " + n,
        onclick: function () {
          if (opts.setLimit) opts.setLimit(n);
        },
      });
    });
    root.appendChild(el("div", { class: "srk-bar-row" }, counts.concat([el("span", { class: "srk-spacer" })], limits)));
    if (model.log !== "on") {
      root.appendChild(el("div", { class: "srk-empty", text: "The traffic log is off, so there is no scan history." }));
    } else if (!model.scans.length) {
      root.appendChild(el("div", { class: "srk-empty", text: "No scans in the traffic log yet." }));
    } else {
      root.appendChild(el("div", { class: "srk-list" }, model.scans.map(function (s) {
        return scanCard(s, model, open);
      })));
    }
    var state = model.state || {};
    root.appendChild(el("h2", { text: "Grants" }));
    root.appendChild(el("pre", { class: "srk-pre", text: state.grants || "–" }));
    root.appendChild(el("h2", { text: "Snooze" }));
    root.appendChild(el("pre", { class: "srk-pre", text: state.snooze || "–" }));
    root.appendChild(el("p", {
      class: "srk-note",
      text: "This page only reads. To change grants or snooze, or to see a scan as text, use " +
        [c.grants, c.snooze, c.history, c.why].filter(Boolean).join(", ") + " in chat.",
    }));
  }

  function renderError(root, message) {
    ensureStyle(root.ownerDocument || document);
    while (root.firstChild) root.removeChild(root.firstChild);
    root.className = "srk";
    root.appendChild(el("div", { class: "srk-empty", text: message }));
  }

  var SDK = typeof window !== "undefined" ? window.__HERMES_PLUGIN_SDK__ : undefined;
  var HOST = typeof window !== "undefined" ? window.__HERMES_PLUGINS__ : undefined;

  if (SDK && HOST && typeof HOST.register === "function") {
    // Hermes dashboard tab: fetch the model from the plugin's own API through the SDK (it adds the session token).
    var React = SDK.React;
    var SentrookPage = function () {
      var ref = React.useRef(null);
      var openRef = React.useRef(new Set());
      var drawnRef = React.useRef(false);
      var limitState = React.useState(10);
      var limit = limitState[0];
      var setLimit = limitState[1];
      React.useEffect(function () {
        var alive = true;
        SDK.fetchJSON("/api/plugins/sentrook/model?n=" + limit)
          .then(function (model) {
            if (!alive || !ref.current) return;
            render(ref.current, model, { setLimit: setLimit, open: openRef.current, openFirst: !drawnRef.current });
            drawnRef.current = true;
          })
          .catch(function () {
            if (alive && ref.current) renderError(ref.current, "The Sentrook dashboard could not load its data. Check that the plugin is enabled.");
          });
        return function () {
          alive = false;
        };
      }, [limit]);
      return React.createElement("div", { ref: ref, className: "srk" });
    };
    HOST.register("sentrook", SentrookPage);
  } else if (typeof document !== "undefined") {
    // OpenClaw Control UI tab: the model is embedded in the page.
    var data = document.getElementById("sentrook-model");
    var root = document.getElementById("sentrook-root");
    if (data && root) {
      // `data-theme="host"`: take colours from the page's own theme variables (the local preview of Hermes).
      var standalone = root.getAttribute("data-theme") !== "host";
      if (standalone) document.documentElement.className = "srk-page";
      try {
        render(root, JSON.parse(data.textContent || "{}"), {
          standalone: standalone,
          setLimit: function (n) {
            window.location.search = "?n=" + n;
          },
        });
      } catch (e) {
        renderError(root, "The Sentrook dashboard could not draw its data.");
      }
    }
  }
})();
