/* ==========================================================================
   REDSTRIKE COCKPIT — CYBERSECURITY COMMAND & CONTROL CONTROLLER
   Unified SPA Engine: Attack DAG, Campaign Deck, Credential Vault,
   C2 Fleet, Live Journal Stream, Topology & Teardown
   ========================================================================== */
"use strict";

function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const state = {
  apiBase: sessionStorage.getItem("rs.apiBase") || "",
  apiKey: sessionStorage.getItem("rs.apiKey") || "",
  engagement: sessionStorage.getItem("rs.engage") || "demo",
  graphPath: sessionStorage.getItem("rs.graph") || "examples/generic-ad-recon.yaml",
  graph: null,
  live: {}, // node_id -> status ('pending'|'executing'|'verified'|'failed'|'gated'|'stub')
  nodeStartTs: {},
  lastEvents: {},
  journalEvents: [],
  credentials: [],
  c2Sessions: [],
  c2Endpoint: sessionStorage.getItem("rs.c2Endpoint") || "http://127.0.0.1:8000",
  teardownActions: [],
  topology: null,
  cy: null,
  sse: null,
  pulseTimer: null,
  activeTab: "graph",
  activeInspTab: "overview",
  selectedNodeId: null,
  layoutMode: "breadthfirst",
  soundEnabled: localStorage.getItem("rs.sound") !== "false",
  autoscroll: true,
  audioCtx: null,
};

const $ = (id) => document.getElementById(id);

/* ================= WEB AUDIO SYNTHESIZER ================= */
function initAudio() {
  if (!state.audioCtx && typeof window.AudioContext !== "undefined") {
    try {
      state.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    } catch {
      // AudioContext unavailable
    }
  }
}

function playSound(type) {
  if (!state.soundEnabled) return;
  initAudio();
  if (!state.audioCtx) return;
  try {
    const ctx = state.audioCtx;
    if (ctx.state === "suspended") {
      ctx.resume();
    }
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === "click") {
      osc.type = "sine";
      osc.frequency.setValueAtTime(750, now);
      gain.gain.setValueAtTime(0.04, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.04);
      osc.start(now);
      osc.stop(now + 0.04);
    } else if (type === "success") {
      osc.type = "triangle";
      osc.frequency.setValueAtTime(520, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.12);
      gain.gain.setValueAtTime(0.07, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
      osc.start(now);
      osc.stop(now + 0.18);
    } else if (type === "warn" || type === "gate") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.setValueAtTime(440, now + 0.08);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
      osc.start(now);
      osc.stop(now + 0.25);
    } else if (type === "error") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(320, now);
      osc.frequency.exponentialRampToValueAtTime(180, now + 0.2);
      gain.gain.setValueAtTime(0.09, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
      osc.start(now);
      osc.stop(now + 0.22);
    }
  } catch {
    // Ignore audio playback exceptions
  }
}

function updateSoundIcon() {
  if (state.soundEnabled) {
    $("soundOnIco")?.classList.remove("hidden");
    $("soundOffIco")?.classList.add("hidden");
  } else {
    $("soundOnIco")?.classList.add("hidden");
    $("soundOffIco")?.classList.remove("hidden");
  }
}

/* ================= TOAST NOTIFICATIONS ================= */
function showToast(message, type = "info", duration = 3500) {
  const container = $("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    toast.style.transition = "all 0.25s ease";
    setTimeout(() => toast.remove(), 250);
  }, duration);
}

/* ================= API CLIENT ================= */
async function api(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.apiKey) headers["X-API-Key"] = state.apiKey;
  const url = (state.apiBase || "") + path;
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`${res.status} ${detail}`.trim());
  }
  return res.json();
}

/* ================= CONNECTION & STATUS ================= */
async function connect() {
  const dot = $("healthDot");
  const label = $("connLabel");
  try {
    const health = await api("/health");
    if (dot) dot.className = "status-dot on";
    if (label) label.textContent = health.status === "ok" ? "Connected" : health.status;
    showToast("Connected to RedStrike API", "success");
    await fetchPresetGraphs();
    await loadGraph();
    await refreshStatus();
    await refreshTopology();
  } catch (e) {
    if (dot) dot.className = "status-dot off";
    if (label) label.textContent = "Offline";
    showToast("API unreachable: " + e.message, "error");
  }
}

async function fetchPresetGraphs() {
  try {
    const res = await api("/campaign/graphs");
    if (res.graphs && Array.isArray(res.graphs)) {
      const select = $("presetGraphSelect");
      if (select) {
        select.innerHTML = '<option value="">(Custom Path)</option>';
        res.graphs.forEach((g) => {
          const opt = document.createElement("option");
          opt.value = g.path;
          opt.textContent = `${g.name} (${g.filename})`;
          if (g.path === state.graphPath) opt.selected = true;
          select.appendChild(opt);
        });
      }
    }
  } catch {
    // If graphs listing is not available, keep bundled options
  }
}

/* ================= GRAPH VIEW & CYTOSCAPE (DAG) ================= */
const STATUS_COLORS = {
  pending: "#64748b",
  verified: "#10b981",
  executing: "#00f0ff",
  gated: "#f59e0b",
  failed: "#f43f5e",
  stub: "#a855f7",
};

function getNodeStatus(node) {
  return state.live[node.id] || node.status || "pending";
}

async function loadGraph() {
  state.graphPath = $("graphPath").value.trim();
  state.engagement = $("engageId").value.trim() || "demo";
  persist();

  try {
    const payload = await api("/campaign/graph", {
      method: "POST",
      body: { graph: state.graphPath || null, engagement_id: state.engagement },
    });
    state.graph = payload;
    populatePhaseFilter();
    renderGraph();
    updateGraphStats();
    updateCampaignDeck();
    showToast(`Loaded ${payload.nodes.length} nodes from ${payload.graph_name}`, "info");
  } catch (e) {
    showToast("Graph load error: " + e.message, "error");
  }
}

function populatePhaseFilter() {
  const sel = $("graphPhaseFilter");
  if (!sel || !state.graph) return;
  const phases = new Set();
  state.graph.nodes.forEach((n) => {
    if (n.phase !== undefined && n.phase !== null) phases.add(String(n.phase));
  });
  const current = sel.value;
  sel.innerHTML = '<option value="all">All Phases</option>';
  Array.from(phases).sort().forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p;
    opt.textContent = `Phase ${p}`;
    sel.appendChild(opt);
  });
  if (phases.has(current)) sel.value = current;
}

function renderGraph() {
  if (!state.graph || typeof cytoscape === "undefined") return;
  const g = state.graph;
  const elements = [];

  for (const n of g.nodes) {
    elements.push({
      data: {
        id: n.id,
        label: n.id,
        title: n.title,
        phase: String(n.phase || "1"),
        status: getNodeStatus(n),
      },
    });
    for (const dep of n.depends_on || []) {
      elements.push({ data: { source: dep, target: n.id } });
    }
  }

  if (state.cy) state.cy.destroy();

  const container = $("cy");
  state.cy = cytoscape({
    container,
    elements,
    style: [
      {
        selector: "node",
        style: {
          "background-color": "#0e1524",
          "border-color": "#64748b",
          "border-width": 2,
          shape: "round-rectangle",
          label: "data(label)",
          color: "#f1f5f9",
          "font-family": "monospace",
          "font-size": 10,
          "font-weight": 600,
          "text-valign": "center",
          "text-halign": "center",
          width: 86,
          height: 38,
          "text-outline-color": "#04060a",
          "text-outline-width": 2,
        },
      },
      ...Object.entries(STATUS_COLORS).map(([st, color]) => ({
        selector: `node[status="${st}"]`,
        style: {
          "border-color": color,
          "shadow-blur": 12,
          "shadow-color": color,
          "shadow-opacity": 0.45,
        },
      })),
      {
        selector: "edge",
        style: {
          width: 1.8,
          "line-color": "rgba(255, 255, 255, 0.15)",
          "target-arrow-color": "rgba(0, 240, 255, 0.6)",
          "target-arrow-shape": "triangle",
          "arrow-scale": 0.85,
          "curve-style": "bezier",
        },
      },
      {
        selector: "node:selected",
        style: {
          "border-color": "#ffffff",
          "border-width": 3,
          "shadow-blur": 20,
          "shadow-color": "#00f0ff",
        },
      },
    ],
    layout: getLayoutOptions(),
  });

  state.cy.on("tap", "node", (evt) => {
    playSound("click");
    openInspector(evt.target.id());
  });

  state.cy.on("tap", (evt) => {
    if (evt.target === state.cy) {
      closeInspector();
    }
  });

  applyGraphFilters();
  startPulse();
}

function getLayoutOptions() {
  if (state.layoutMode === "concentric") {
    return { name: "concentric", minNodeSpacing: 60, padding: 30 };
  } else if (state.layoutMode === "circle") {
    return { name: "circle", padding: 30 };
  } else if (state.layoutMode === "grid") {
    return { name: "grid", padding: 30 };
  }
  return {
    name: "breadthfirst",
    directed: true,
    padding: 30,
    spacingFactor: 1.25,
    avoidOverlap: true,
  };
}

function applyGraphFilters() {
  if (!state.cy) return;
  const search = ($("graphNodeSearch")?.value || "").toLowerCase().trim();
  const phase = $("graphPhaseFilter")?.value || "all";
  const status = $("graphStatusFilter")?.value || "all";

  state.cy.batch(() => {
    state.cy.nodes().forEach((node) => {
      const data = node.data();
      const matchSearch =
        !search ||
        data.id.toLowerCase().includes(search) ||
        (data.title && data.title.toLowerCase().includes(search));
      const matchPhase = phase === "all" || data.phase === phase;
      const matchStatus = status === "all" || data.status === status;

      if (matchSearch && matchPhase && matchStatus) {
        node.style({ display: "element", opacity: 1 });
      } else {
        node.style({ display: "element", opacity: 0.15 });
      }
    });
  });
}

function updateGraphStats() {
  if (!state.graph) return;
  const counts = { verified: 0, executing: 0, gated: 0, failed: 0, pending: 0, stub: 0 };
  state.graph.nodes.forEach((n) => {
    const s = getNodeStatus(n);
    counts[s] = (counts[s] || 0) + 1;
  });

  if ($("graphNameDisplay")) $("graphNameDisplay").textContent = state.graph.graph_name || "Attack Graph";
  if ($("cntVerified")) $("cntVerified").textContent = counts.verified;
  if ($("cntExecuting")) $("cntExecuting").textContent = counts.executing;
  if ($("cntGated")) $("cntGated").textContent = counts.gated;
  if ($("cntFailed")) $("cntFailed").textContent = counts.failed;
  if ($("cntPending")) $("cntPending").textContent = counts.pending;
  if ($("cntStub")) $("cntStub").textContent = counts.stub;
  if ($("cntTotal")) $("cntTotal").textContent = state.graph.nodes.length;
}

function startPulse() {
  if (state.pulseTimer) clearInterval(state.pulseTimer);
  let dim = false;
  state.pulseTimer = setInterval(() => {
    if (!state.cy) return;
    dim = !dim;
    const exec = state.cy.nodes('[status="executing"]');
    if (exec.length) {
      exec.animate({ style: { opacity: dim ? 0.35 : 1 } }, { duration: 550 });
    }
  }, 600);
}

function restyleGraph() {
  if (!state.graph || !state.cy) return;
  state.cy.batch(() => {
    state.graph.nodes.forEach((n) => {
      const el = state.cy.getElementById(n.id);
      if (el.length) el.data("status", getNodeStatus(n));
    });
  });
  updateGraphStats();
  updateCampaignDeck();
}

/* ================= NODE INSPECTOR DRAWER ================= */
function openInspector(nodeId) {
  state.selectedNodeId = nodeId;
  const node = (state.graph?.nodes || []).find((n) => n.id === nodeId);
  if (!node) return;

  const drawer = $("nodeDrawer");
  if (drawer) drawer.classList.remove("hidden");

  if ($("inspNodePhaseBadge")) $("inspNodePhaseBadge").textContent = `Phase ${node.phase || "1"}`;
  if ($("inspNodeId")) $("inspNodeId").textContent = node.id;
  if ($("inspNodeTitle")) $("inspNodeTitle").textContent = node.title || node.id;

  const status = getNodeStatus(node);
  const banner = $("inspNodeStatusBanner");
  if (banner) {
    banner.textContent = `Status: ${status.toUpperCase()}`;
    banner.className = `insp-status-banner text-${status === "verified" ? "green" : status === "failed" ? "red" : status === "executing" ? "cyan" : status === "gated" ? "amber" : "dim"}`;
  }

  // Populate Overview
  const dlOverview = $("inspOverviewDl");
  if (dlOverview) {
    dlOverview.innerHTML = `
      <dt>Node ID</dt><dd><code>${esc(node.id)}</code></dd>
      <dt>Title</dt><dd>${esc(node.title || "—")}</dd>
      <dt>Phase</dt><dd>Phase ${esc(node.phase ?? "—")}</dd>
      <dt>Path</dt><dd><code>${esc(node.path || "—")}</code></dd>
      <dt>Branch</dt><dd>${esc(node.branch || "—")}</dd>
      <dt>Beachheads</dt><dd>${(node.beachheads || []).map(esc).join(", ") || "—"}</dd>
      <dt>Targets</dt><dd>${(node.targets || []).map(esc).join(", ") || "—"}</dd>
      <dt>Depends On</dt><dd>${(node.depends_on || []).map((d) => `<code>${esc(d)}</code>`).join(", ") || "None (Root)"}</dd>
      <dt>Requires Cred</dt><dd>${esc(node.requires_cred || "None")}</dd>
      <dt>Produces Cred</dt><dd>${esc(node.produces_cred || "None")}</dd>
      <dt>HITL Gate</dt><dd>${node.hitl_gate ? `<span class="badge-tag">${esc(node.hitl_gate)}</span>` : "None"}</dd>
      <dt>Timeout</dt><dd>${node.timeout_seconds ? `${esc(node.timeout_seconds)}s` : "default"}</dd>
    `;
  }

  // Populate Intent
  const codeBlock = $("inspIntentCodeBlock");
  if (codeBlock) {
    if (node.intent_args) {
      codeBlock.textContent = JSON.stringify(node.intent_args, null, 2);
    } else if (node.script) {
      codeBlock.textContent = node.script;
    } else {
      codeBlock.textContent = "// No explicit intent arguments or script defined.";
    }
  }

  const dlIntent = $("inspIntentDl");
  if (dlIntent) {
    dlIntent.innerHTML = `
      <dt>Intent</dt><dd><code>${esc(node.intent || "custom")}</code></dd>
      <dt>Teardown Action</dt><dd>${node.teardown ? `<code>${esc(node.teardown.action)}</code>: ${esc(node.teardown.description || "")}` : "None"}</dd>
    `;
  }

  // Populate Verification
  const dlVerify = $("inspVerifyDl");
  if (dlVerify) {
    dlVerify.innerHTML = `
      <dt>Marker</dt><dd>${node.success_marker ? `<code>${esc(node.success_marker)}</code>` : "None"}</dd>
      <dt>JSON Validation</dt><dd>${node.success_json ? `<pre style="font-size:10px">${esc(JSON.stringify(node.success_json, null, 2))}</pre>` : "None"}</dd>
      <dt>Check Command</dt><dd>${node.check_command ? `<code>${esc(JSON.stringify(node.check_command))}</code>` : "None"}</dd>
    `;
  }

  // Populate Telemetry
  const ev = state.lastEvents[nodeId];
  const dlTelemetry = $("inspTelemetryDl");
  if (dlTelemetry) {
    if (ev) {
      const dur =
        ev.event === "step_end" && state.nodeStartTs[nodeId]
          ? `${((new Date(ev.ts) - new Date(state.nodeStartTs[nodeId])) / 1000).toFixed(2)}s`
          : "—";
      dlTelemetry.innerHTML = `
        <dt>Last Event</dt><dd><span class="badge-tag">${esc(ev.event)}</span></dd>
        <dt>Timestamp</dt><dd>${esc(ev.ts || "—")}</dd>
        <dt>Verified</dt><dd>${ev.verified !== undefined ? (ev.verified ? "✅ True" : "❌ False") : "—"}</dd>
        <dt>Status Code</dt><dd><code>${esc(ev.return_code ?? "—")}</code></dd>
        <dt>Duration</dt><dd>${esc(dur)}</dd>
        <dt>Tool / Version</dt><dd>${ev.tool ? `${esc(ev.tool)} ${esc(ev.tool_version || "")}` : "—"}</dd>
        <dt>Verify Reason</dt><dd>${esc(ev.verify_reason || "—")}</dd>
      `;
    } else {
      dlTelemetry.innerHTML = `<dt>Status</dt><dd>No live execution telemetry logged yet for this node.</dd>`;
    }
  }
}

function closeInspector() {
  const drawer = $("nodeDrawer");
  if (drawer) drawer.classList.add("hidden");
  state.selectedNodeId = null;
}

/* ================= CAMPAIGN DECK & STEPPER ================= */
function updateCampaignDeck() {
  if (!state.graph) return;
  const nodes = state.graph.nodes;
  let verified = 0;
  let failed = 0;
  let gated = 0;

  nodes.forEach((n) => {
    const s = getNodeStatus(n);
    if (s === "verified") verified++;
    else if (s === "failed") failed++;
    else if (s === "gated") gated++;
  });

  const total = nodes.length;
  const pct = total ? Math.round((verified / total) * 100) : 0;

  if ($("deckMetricTotal")) $("deckMetricTotal").textContent = total;
  if ($("deckMetricVerified")) $("deckMetricVerified").textContent = verified;
  if ($("deckMetricFailed")) $("deckMetricFailed").textContent = failed;
  if ($("deckMetricGated")) $("deckMetricGated").textContent = gated;
  if ($("deckMetricCreds")) $("deckMetricCreds").textContent = state.credentials.length;

  const bar = $("deckProgressBar");
  if (bar) bar.style.width = `${pct}%`;

  renderExecutionStepper();
  computeRecommendations();
}

function renderExecutionStepper() {
  const container = $("deckStepperTimeline");
  if (!container || !state.graph) return;
  const filter = ($("stepperSearch")?.value || "").toLowerCase().trim();

  container.innerHTML = "";
  let renderedCount = 0;

  state.graph.nodes.forEach((n, idx) => {
    if (filter && !n.id.toLowerCase().includes(filter) && !(n.title && n.title.toLowerCase().includes(filter))) {
      return;
    }
    renderedCount++;
    const s = getNodeStatus(n);
    const card = document.createElement("div");
    card.className = "step-card";

    let icon = String(idx + 1);
    if (s === "verified") icon = "✓";
    else if (s === "failed") icon = "✕";
    else if (s === "executing") icon = "⟳";

    card.innerHTML = `
      <div class="step-badge-indicator ${esc(s)}">${esc(icon)}</div>
      <div class="step-body">
        <div class="step-top">
          <span class="step-id">${esc(n.id)}</span>
          <span class="step-status-chip ${esc(s)}">${esc(s)}</span>
        </div>
        <div class="step-desc">${esc(n.title || n.intent || "Campaign attack step")}</div>
        ${n.intent_args ? `<div class="step-cmd">${esc(JSON.stringify(n.intent_args))}</div>` : ""}
      </div>
    `;
    card.addEventListener("click", () => {
      openInspector(n.id);
      switchTab("graph");
      if (state.cy) {
        const el = state.cy.getElementById(n.id);
        if (el.length) state.cy.center(el);
      }
    });
    container.appendChild(card);
  });

  if (renderedCount === 0) {
    container.innerHTML = '<p class="empty-hint">No execution steps match the current search filter.</p>';
  }
}

function computeRecommendations() {
  const container = $("deckRecommendationsList");
  if (!container || !state.graph) return;

  const verifiedSet = new Set(
    state.graph.nodes.filter((n) => getNodeStatus(n) === "verified").map((n) => n.id)
  );

  const candidates = [];
  state.graph.nodes.forEach((n) => {
    const s = getNodeStatus(n);
    if (s === "verified") return;
    const deps = n.depends_on || [];
    const depsMet = deps.every((d) => verifiedSet.has(d));
    if (depsMet) {
      candidates.push(n);
    }
  });

  if (candidates.length === 0) {
    container.innerHTML = '<p class="empty-hint">No next actions eligible. All available branches completed or awaiting prerequisites.</p>';
    return;
  }

  container.innerHTML = "";
  candidates.slice(0, 5).forEach((cand) => {
    const item = document.createElement("div");
    item.className = "rec-item";
    item.innerHTML = `
      <div>
        <div class="rec-title">${esc(cand.id)} &mdash; ${esc(cand.title || cand.intent)}</div>
        <div class="rec-reason">Prerequisites met (${(cand.depends_on || []).length} deps clear) &middot; Phase ${esc(cand.phase || 1)}</div>
      </div>
      <button class="btn btn-cyan btn-sm" data-cand-id="${esc(cand.id)}">Inspect</button>
    `;
    item.querySelector("button")?.addEventListener("click", () => {
      openInspector(cand.id);
      switchTab("graph");
      if (state.cy) {
        const el = state.cy.getElementById(cand.id);
        if (el.length) {
          state.cy.center(el);
          el.select();
        }
      }
    });
    container.appendChild(item);
  });
}

/* ================= CREDENTIAL VAULT ================= */
function renderCreds() {
  const tbody = $("credTableBody");
  const empty = $("credEmptyHint");
  const creds = state.credentials;
  const badge = $("credBadge");
  if (badge) badge.textContent = creds.length;

  if (!tbody) return;
  tbody.innerHTML = "";

  const filter = ($("credSearch")?.value || "").toLowerCase().trim();
  const activeChip = document.querySelector(".vault-filters .filter-chip.active")?.dataset.filter || "all";

  let visibleCount = 0;

  creds.forEach((c) => {
    const type = (c.cred_type || (c.has_token ? "token" : c.has_nt_hash ? "hash" : "password")).toLowerCase();

    if (activeChip !== "all" && !type.includes(activeChip)) return;

    if (
      filter &&
      !c.name.toLowerCase().includes(filter) &&
      !(c.username && c.username.toLowerCase().includes(filter)) &&
      !(c.domain && c.domain.toLowerCase().includes(filter))
    ) {
      return;
    }

    visibleCount++;
    const tr = document.createElement("tr");

    const materialParts = [];
    if (c.has_password) materialParts.push(`pwd: <span class="secret-mask">${esc(c.password_mask || "••••••••")}</span>`);
    if (c.has_nt_hash) materialParts.push(`nt: <span class="secret-mask">${esc(c.nt_hash_mask || "aad3b435b51404ee••••")}</span>`);
    if (c.has_token) materialParts.push(`token: <span class="secret-mask">${esc(c.token_mask || "eyJhbGciOi••••")}</span>`);

    tr.innerHTML = `
      <td><code>${esc(c.name)}</code></td>
      <td><strong>${esc(c.username || "—")}</strong></td>
      <td>${esc(c.domain || "—")}</td>
      <td><span class="badge-cred-type ${esc(type)}">${esc(type)}</span></td>
      <td>${esc(c.source || "ledger")}</td>
      <td>${materialParts.join(" &middot; ") || "—"}</td>
      <td>
        <button class="btn btn-ghost btn-sm" data-reveal="${esc(c.name)}">Reveal</button>
      </td>
    `;

    tr.querySelector("[data-reveal]")?.addEventListener("click", () => revealCredential(c.name));
    tbody.appendChild(tr);
  });

  if (empty) empty.style.display = visibleCount === 0 ? "flex" : "none";
}

async function revealCredential(name) {
  if (!confirm(`Reveal audited secret for credential '${name}'?\nThis action is cryptographically recorded in the engagement ledger.`)) {
    return;
  }
  try {
    playSound("click");
    const cred = await api("/campaign/credential/reveal", {
      method: "POST",
      body: { engagement_id: state.engagement, name },
    });
    const body = $("revealBody");
    if (body) body.textContent = JSON.stringify(cred, null, 2);
    $("revealModal")?.classList.remove("hidden");
    showToast(`Audited reveal recorded for ${name}`, "warning");
  } catch (e) {
    showToast("Reveal failed: " + e.message, "error");
  }
}

function exportCredentialsJSON() {
  const blob = new Blob([JSON.stringify(state.credentials, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `redstrike-creds-${state.engagement}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ================= C2 FLEET (C2STACK INTEGRATION) ================= */
async function refreshC2Fleet() {
  const endpoint = state.c2Endpoint || $("c2EndpointInput")?.value.trim() || undefined;
  showToast("Probing C2Stack Flight Control portal...", "info", 2000);
  try {
    const res = await api("/c2/stack/sessions", {
      method: "POST",
      body: { endpoint: endpoint || null },
    });
    if (res.sessions && Array.isArray(res.sessions)) {
      state.c2Sessions = res.sessions;
    }
    if (res.backends) {
      renderC2Backends(res.backends);
    }
    renderC2Fleet();
    showToast(`C2Stack: ${state.c2Sessions.length} active session(s) detected`, "success");
  } catch (e) {
    // If direct C2Stack portal query fails, try getting stack status or show offline
    renderC2Backends({
      sliver: { ok: false, error: "Unreachable" },
      havoc: { ok: false, error: "Unreachable" },
      adaptix: { ok: false, error: "Unreachable" },
      mythic: { ok: false, error: "Unreachable" },
      meridian: { ok: false, error: "Unreachable" },
    });
    renderC2Fleet();
    showToast(`C2Stack portal unreachable at ${endpoint || "default"}: ${e.message}`, "warning");
  }
}

function renderC2Backends(backends = {}) {
  const frameworks = ["sliver", "havoc", "adaptix", "mythic", "meridian"];
  frameworks.forEach((fw) => {
    const info = backends[fw];
    const card = $(`bcard-${fw}`);
    const dot = $(`bdot-${fw}`);
    const txt = $(`btxt-${fw}`);
    if (!card || !dot || !txt) return;

    if (info) {
      if (info.ok) {
        card.className = "c2-backend-card online";
        dot.className = "badge-dot dot-verified";
        txt.textContent = `Online (${info.count ?? 0} ses)`;
      } else {
        card.className = "c2-backend-card offline";
        dot.className = "badge-dot dot-failed";
        txt.textContent = info.error ? String(info.error).slice(0, 15) : "Offline";
      }
    } else {
      card.className = "c2-backend-card";
      dot.className = "badge-dot dot-pending";
      txt.textContent = "Unchecked";
    }
  });
}

function renderC2Fleet() {
  const tbody = $("c2TableBody");
  const empty = $("c2EmptyHint");
  const badge = $("c2Badge");
  const sessions = state.c2Sessions;
  if (badge) badge.textContent = sessions.length;

  if (!tbody) return;
  tbody.innerHTML = "";

  if (sessions.length === 0) {
    if (empty) {
      empty.style.display = "flex";
      empty.querySelector("p").textContent =
        `No active C2 implant sessions detected on C2Stack portal (${state.c2Endpoint || "http://127.0.0.1:8000"}). Launch C2Stack docker containers or deploy implants to populate fleet.`;
    }
    return;
  }
  if (empty) empty.style.display = "none";

  sessions.forEach((s) => {
    const tr = document.createElement("tr");
    const isAlive = s.is_alive !== undefined ? Boolean(s.is_alive) : true;
    tr.innerHTML = `
      <td><code>${esc(s.session_id || s.id)}</code></td>
      <td><span class="badge-tag">${esc(s.backend || "sliver")}</span></td>
      <td><strong>${esc(s.hostname || "UNKNOWN")}</strong></td>
      <td>${esc(s.username || "NT AUTHORITY\\SYSTEM")}</td>
      <td>${esc(s.os || "Windows")} (${esc(s.arch || "x64")})</td>
      <td><code>${esc(s.transport || "mtls:8888")}</code></td>
      <td>${esc(s.last_checkin || "Just now")}</td>
      <td>
        <span class="badge-dot ${isAlive ? "dot-verified" : "dot-failed"}"></span>
        ${isAlive ? "Active" : "Dead"}
      </td>
    `;
    tbody.appendChild(tr);
  });
}


/* ================= LIVE JOURNAL (TERMINAL & SSE) ================= */
function toggleSSE() {
  if (state.sse) {
    state.sse.close();
    state.sse = null;
    const btn = $("btnToggleSSE");
    if (btn) btn.classList.remove("active");
    if ($("sseBtnLabel")) $("sseBtnLabel").textContent = "Live Stream: Off";
    showToast("Disconnected from SSE journal", "info");
    return;
  }

  const engage = state.engagement || "demo";
  const url = `${state.apiBase || ""}/campaign/events/${encodeURIComponent(engage)}?follow_seconds=120`;
  const es = new EventSource(url);
  state.sse = es;

  const btn = $("btnToggleSSE");
  if (btn) btn.classList.add("active");
  if ($("sseBtnLabel")) $("sseBtnLabel").textContent = "Live Stream: Active";
  showToast("Streaming live activity journal...", "info");

  es.onmessage = (msg) => {
    let rec;
    try {
      rec = JSON.parse(msg.data);
    } catch {
      return;
    }
    handleJournalRecord(rec);
  };

  es.onerror = () => {
    es.close();
    state.sse = null;
    const b = $("btnToggleSSE");
    if (b) b.classList.remove("active");
    if ($("sseBtnLabel")) $("sseBtnLabel").textContent = "Live Stream: Off";
  };
}

function handleJournalRecord(rec) {
  state.journalEvents.push(rec);
  if (state.journalEvents.length > 1000) state.journalEvents.shift();

  if (rec.node_id) {
    state.lastEvents[rec.node_id] = rec;
    if (rec.event === "step_start") {
      state.live[rec.node_id] = "executing";
      state.nodeStartTs[rec.node_id] = rec.ts;
      playSound("click");
    } else if (rec.event === "step_end") {
      state.live[rec.node_id] = rec.verified ? "verified" : "failed";
      playSound(rec.verified ? "success" : "error");
    } else if (rec.event === "step_skip") {
      state.live[rec.node_id] = rec.verified ? "verified" : "failed";
    }
    restyleGraph();
    if (state.selectedNodeId === rec.node_id) {
      openInspector(rec.node_id);
    }
  }

  appendLogLine(rec);
}

function appendLogLine(rec) {
  const screen = $("eventLogContainer");
  if (!screen) return;

  const filter = ($("journalFilter")?.value || "").toLowerCase().trim();
  const lineStr = JSON.stringify(rec).toLowerCase();
  if (filter && !lineStr.includes(filter)) return;

  const div = document.createElement("div");
  div.className = "log-line";

  const ts = rec.ts ? rec.ts.split("T")[1]?.slice(0, 8) || rec.ts : new Date().toLocaleTimeString();
  let tagClass = "info";
  let tag = rec.event || "INFO";

  if (rec.event === "step_end") {
    tagClass = rec.verified ? "verify" : "error";
    tag = rec.verified ? "VERIFIED" : "FAILED";
  } else if (rec.event === "gate_wait" || rec.event === "hitl_gate") {
    tagClass = "gate";
    tag = "GATE";
    playSound("gate");
  }

  const msg = `${rec.node_id ? `[${rec.node_id}] ` : ""}${rec.title || ""}${rec.verify_reason ? ` — ${rec.verify_reason}` : ""}${rec.note ? ` — ${rec.note}` : ""}`;

  div.innerHTML = `
    <span class="log-ts">${ts}</span>
    <span class="log-tag ${tagClass}">${tag}</span>
    <span class="log-msg">${escapeHtml(msg || JSON.stringify(rec))}</span>
  `;

  screen.appendChild(div);

  if (state.autoscroll) {
    screen.scrollTop = screen.scrollHeight;
  }
}

function escapeHtml(str) {
  return esc(str);
}

function exportJournal() {
  const blob = new Blob([JSON.stringify(state.journalEvents, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `redstrike-journal-${state.engagement}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ================= STATUS & HITL GATE MODAL ================= */
async function refreshStatus() {
  if (!state.engagement) return;
  try {
    const st = await api("/campaign/status", {
      method: "POST",
      body: { engagement_id: state.engagement },
    });

    state.credentials = st.credentials || [];
    renderCreds();

    if (st.c2_sessions) {
      state.c2Sessions = st.c2_sessions;
      renderC2Fleet();
    }

    if (st.teardown_actions) {
      state.teardownActions = st.teardown_actions;
      renderTeardown();
    }

    const gate = st.pending_gate;
    if (gate) {
      showGateModal(gate, st);
    } else {
      $("gateModal")?.classList.add("hidden");
    }

    if (state.graph) {
      const completed = st.completed_nodes || {};
      const attempted = st.attempted_nodes || {};
      state.graph.nodes.forEach((n) => {
        if (completed[n.id]) {
          state.live[n.id] = "verified";
        } else if (n.hitl_gate && gate === n.hitl_gate) {
          state.live[n.id] = "gated";
        } else if (attempted[n.id]) {
          state.live[n.id] = attempted[n.id].verified ? "verified" : "failed";
        }
      });
      restyleGraph();
    }
  } catch (e) {
    showToast("Status refresh error: " + e.message, "error");
  }
}

function showGateModal(gate, st) {
  playSound("gate");
  const gatedNodes = (state.graph?.nodes || []).filter((n) => n.hitl_gate === gate);
  const first = gatedNodes[0] || {};
  if ($("gateName")) $("gateName").textContent = gate;

  const content = $("gateDetailContent");
  if (content) {
    content.innerHTML = `
      Execution for engagement <strong>${esc(st.engagement_id || state.engagement)}</strong> is gated.
      ${first.title ? `<br>Node: <code>${esc(first.id)}</code> &mdash; ${esc(first.title)}` : ""}
      ${first.intent ? `<br>Intent: <code>${esc(first.intent)}</code>` : ""}
      ${first.targets?.length ? `<br>Target Hosts: <code>${first.targets.map(esc).join(", ")}</code>` : ""}
    `;
  }
  $("gateModal")?.classList.remove("hidden");
}

async function approveGate() {
  const gate = $("gateName")?.textContent;
  const note = $("gateApprovalNote")?.value || "Approved from cockpit";
  try {
    playSound("click");
    await api("/campaign/approve", {
      method: "POST",
      body: { engagement_id: state.engagement, gate, note },
    });
    $("gateModal")?.classList.add("hidden");
    showToast(`Gate '${gate}' authorized successfully`, "success");
    await refreshStatus();
  } catch (e) {
    showToast("Gate approval failed: " + e.message, "error");
  }
}

/* ================= RUN CONTROLS ================= */
async function runCampaign(live = false) {
  if (!state.engagement) return;
  const phase = $("phaseSpec")?.value.trim() || "1-3";

  if (live) {
    const ok = confirm(`EXECUTE LIVE: You are about to run phase '${phase}' LIVE against in-scope targets.\nProceed?`);
    if (!ok) return;
  }

  playSound("click");
  const body = {
    engagement_id: state.engagement,
    phase,
    dry_run: !live,
    resume: true,
  };
  if (state.graphPath) body.graph = state.graphPath;

  try {
    showToast(`Launching ${live ? "LIVE" : "dry-run"} campaign execution (Phase ${phase})...`, "info");
    const res = await api("/campaign/run_phase", { method: "POST", body });
    await refreshStatus();
    showToast(
      `Campaign run finished: verified ${res.summary?.verified_count ?? "?"} / ${res.summary?.total ?? "?"} steps`,
      "success"
    );
  } catch (e) {
    showToast("Campaign run failed: " + e.message, "error");
  }
}

/* ================= TOPOLOGY VIEW ================= */
async function refreshTopology() {
  const container = $("topoDetails");
  const policyCont = $("policyDetails");
  try {
    const topo = await api("/topology");
    state.topology = topo;
    if (container) {
      if (topo.targets && Array.isArray(topo.targets)) {
        container.innerHTML = topo.targets
          .map(
            (t) => `
          <div class="topo-item">
            <div>
              <span class="topo-host">${esc(t.hostname || t.ip)}</span>
              <span class="topo-role">${t.ip ? `(${esc(t.ip)})` : ""} &middot; ${esc(t.role || "Target")}</span>
            </div>
            <span class="badge-tag">${esc(t.domain || "CADRE")}</span>
          </div>`
          )
          .join("");
      } else {
        container.innerHTML = `<pre class="code-block">${esc(JSON.stringify(topo, null, 2))}</pre>`;
      }
    }
    if (policyCont) {
      policyCont.innerHTML = `
        <div class="topo-item">
          <div><span class="topo-host">Execution Mode</span></div>
          <span class="badge-tag">Human-In-The-Loop Protected</span>
        </div>
        <div class="topo-item">
          <div><span class="topo-host">Engagement Ledger</span></div>
          <span class="badge-tag">${esc(state.engagement)}</span>
        </div>
      `;
    }
  } catch {
    if (container) container.innerHTML = `<p class="empty-hint">Topology discovery is local to active lab configuration.</p>`;
  }
}

/* ================= TEARDOWN & CLEANUP ================= */
function renderTeardown() {
  const tbody = $("teardownTableBody");
  const empty = $("teardownEmptyHint");
  const badge = $("teardownBadge");
  const actions = state.teardownActions;

  if (badge) {
    badge.textContent = actions.length;
    badge.style.display = actions.length > 0 ? "inline-flex" : "none";
  }

  if (!tbody) return;
  tbody.innerHTML = "";

  if (actions.length === 0) {
    if (empty) empty.style.display = "flex";
    return;
  }
  if (empty) empty.style.display = "none";

  actions.forEach((a) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${esc(a.action || a.name)}</code></td>
      <td><strong>${esc(a.target || "localhost")}</strong></td>
      <td>${esc(a.description || "Reversible post-exploitation state")}</td>
      <td><span class="badge-tag">${esc(a.status || "Registered")}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function executeTeardown() {
  const ok = confirm("Execute all queued reversible cleanup actions for this engagement?");
  if (!ok) return;

  try {
    playSound("click");
    const res = await api("/campaign/teardown", {
      method: "POST",
      body: { engagement_id: state.engagement, execute: true },
    });
    showToast(`Teardown executed: ${res.executed_count || 0} actions performed`, "success");
    await refreshStatus();
  } catch (e) {
    showToast("Teardown error: " + e.message, "error");
  }
}

/* ================= TAB CONTROLLER ================= */
function switchTab(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll(".nav-tab").forEach((tab) => {
    const isActive = tab.dataset.tab === tabName;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-selected", isActive);
  });

  document.querySelectorAll(".view-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `view-${tabName}`);
  });

  if (tabName === "graph" && state.cy) {
    setTimeout(() => {
      state.cy.resize();
      state.cy.fit();
    }, 50);
  } else if (tabName === "c2") {
    refreshC2Fleet();
  }
}

/* ================= PERSISTENCE & EVENT WIREUP ================= */
function persist() {
  sessionStorage.setItem("rs.apiBase", state.apiBase);
  sessionStorage.setItem("rs.apiKey", state.apiKey);
  sessionStorage.setItem("rs.engage", state.engagement);
  sessionStorage.setItem("rs.graph", state.graphPath);
  sessionStorage.setItem("rs.c2Endpoint", state.c2Endpoint);
}

function initEventHandlers() {
  // Navigation tabs
  document.querySelectorAll(".nav-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      playSound("click");
      switchTab(tab.dataset.tab);
    });
  });

  // Sound toggle
  $("btnSoundToggle")?.addEventListener("click", () => {
    state.soundEnabled = !state.soundEnabled;
    localStorage.setItem("rs.sound", state.soundEnabled ? "true" : "false");
    updateSoundIcon();
    playSound("click");
  });
  updateSoundIcon();

  // Preset graph picker
  $("presetGraphSelect")?.addEventListener("change", (e) => {
    const val = e.target.value;
    if (val) {
      if ($("graphPath")) $("graphPath").value = val;
      state.graphPath = val;
      loadGraph();
    }
  });

  // Action strip
  $("btnLoadGraph")?.addEventListener("click", loadGraph);
  $("btnDryRun")?.addEventListener("click", () => runCampaign(false));
  $("btnExecuteLive")?.addEventListener("click", () => runCampaign(true));
  $("btnRefreshStatus")?.addEventListener("click", () => {
    playSound("click");
    refreshStatus();
  });
  $("btnToggleSSE")?.addEventListener("click", toggleSSE);

  // Graph HUD
  $("graphNodeSearch")?.addEventListener("input", applyGraphFilters);
  $("graphPhaseFilter")?.addEventListener("change", applyGraphFilters);
  $("graphStatusFilter")?.addEventListener("change", applyGraphFilters);

  $("btnZoomIn")?.addEventListener("click", () => state.cy?.zoom(state.cy.zoom() * 1.25));
  $("btnZoomOut")?.addEventListener("click", () => state.cy?.zoom(state.cy.zoom() * 0.8));
  $("btnFitGraph")?.addEventListener("click", () => state.cy?.fit());
  $("btnLayoutToggle")?.addEventListener("click", () => {
    const layouts = ["breadthfirst", "concentric", "grid", "circle"];
    const idx = (layouts.indexOf(state.layoutMode) + 1) % layouts.length;
    state.layoutMode = layouts[idx];
    showToast(`Switched layout to ${state.layoutMode}`, "info");
    if (state.cy) {
      state.cy.layout(getLayoutOptions()).run();
    }
  });

  // Slide-over Node Inspector
  $("btnInspectorClose")?.addEventListener("click", closeInspector);
  document.querySelectorAll(".insp-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const tabId = tab.dataset.inspTab;
      document.querySelectorAll(".insp-tab").forEach((t) => t.classList.toggle("active", t === tab));
      document.querySelectorAll(".insp-panel").forEach((p) => p.classList.toggle("active", p.id === `inspTab-${tabId}`));
    });
  });

  $("btnCopyIntentArgs")?.addEventListener("click", () => {
    const text = $("inspIntentCodeBlock")?.textContent || "";
    navigator.clipboard?.writeText(text);
    showToast("Intent payload copied to clipboard", "info");
  });

  $("btnFocusNode")?.addEventListener("click", () => {
    if (state.selectedNodeId && state.cy) {
      const el = state.cy.getElementById(state.selectedNodeId);
      if (el.length) {
        state.cy.center(el);
        state.cy.zoom(1.4);
      }
    }
  });

  $("btnRecommendNode")?.addEventListener("click", () => {
    switchTab("campaign");
  });

  // Campaign Deck
  $("btnRefreshRecommend")?.addEventListener("click", computeRecommendations);
  $("stepperSearch")?.addEventListener("input", renderExecutionStepper);

  // Vault
  $("credSearch")?.addEventListener("input", renderCreds);
  document.querySelectorAll(".vault-filters .filter-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.querySelectorAll(".vault-filters .filter-chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      renderCreds();
    });
  });
  $("btnRefreshCreds")?.addEventListener("click", refreshStatus);
  $("btnExportCreds")?.addEventListener("click", exportCredentialsJSON);

  // C2 Fleet
  if ($("c2EndpointInput")) $("c2EndpointInput").value = state.c2Endpoint;
  $("c2EndpointInput")?.addEventListener("change", (e) => {
    state.c2Endpoint = e.target.value.trim();
    persist();
    refreshC2Fleet();
  });
  $("btnRefreshC2")?.addEventListener("click", refreshC2Fleet);

  // Journal
  $("journalFilter")?.addEventListener("input", () => {
    const screen = $("eventLogContainer");
    if (screen) {
      screen.innerHTML = "";
      state.journalEvents.forEach((rec) => appendLogLine(rec));
    }
  });
  $("btnJournalAutoscroll")?.addEventListener("click", () => {
    state.autoscroll = !state.autoscroll;
    const btn = $("btnJournalAutoscroll");
    if (btn) {
      btn.textContent = `Autoscroll: ${state.autoscroll ? "ON" : "OFF"}`;
      btn.classList.toggle("active", state.autoscroll);
    }
  });
  $("btnClearJournal")?.addEventListener("click", () => {
    state.journalEvents = [];
    const screen = $("eventLogContainer");
    if (screen) screen.innerHTML = "";
  });
  $("btnExportJournal")?.addEventListener("click", exportJournal);

  // Topology & Teardown
  $("btnRefreshTopology")?.addEventListener("click", refreshTopology);
  $("btnExecuteTeardown")?.addEventListener("click", executeTeardown);

  // HITL Gate Modal
  $("btnApproveGate")?.addEventListener("click", approveGate);
  $("btnDismissGate")?.addEventListener("click", () => $("gateModal")?.classList.add("hidden"));

  // Reveal Modal
  $("btnCloseRevealModal")?.addEventListener("click", () => $("revealModal")?.classList.add("hidden"));
  $("btnCloseReveal")?.addEventListener("click", () => $("revealModal")?.classList.add("hidden"));
  $("btnCopyReveal")?.addEventListener("click", () => {
    const txt = $("revealBody")?.textContent || "";
    navigator.clipboard?.writeText(txt);
    showToast("Secret material copied to clipboard", "info");
  });

  // Settings Modal
  $("btnSettings")?.addEventListener("click", () => {
    if ($("apiBase")) $("apiBase").value = state.apiBase;
    if ($("apiKey")) $("apiKey").value = state.apiKey;
    if ($("modalEngageId")) $("modalEngageId").value = state.engagement;
    if ($("modalC2Endpoint")) $("modalC2Endpoint").value = state.c2Endpoint;
    $("settingsModal")?.classList.remove("hidden");
  });
  $("btnCloseSettingsModal")?.addEventListener("click", () => $("settingsModal")?.classList.add("hidden"));
  $("btnSaveSettings")?.addEventListener("click", () => {
    state.apiBase = $("apiBase")?.value.trim() || "";
    state.apiKey = $("apiKey")?.value.trim() || "";
    state.engagement = $("modalEngageId")?.value.trim() || "demo";
    if ($("modalC2Endpoint")) {
      state.c2Endpoint = $("modalC2Endpoint").value.trim() || "http://127.0.0.1:8000";
      if ($("c2EndpointInput")) $("c2EndpointInput").value = state.c2Endpoint;
    }
    if ($("engageId")) $("engageId").value = state.engagement;
    persist();
    $("settingsModal")?.classList.add("hidden");
    connect();
    refreshC2Fleet();
  });
  $("btnTestConn")?.addEventListener("click", async () => {
    try {
      await api("/health");
      showToast("Test connection OK", "success");
    } catch (e) {
      showToast("Test connection failed: " + e.message, "error");
    }
  });

  // Engagement ID change
  $("engageId")?.addEventListener("change", () => {
    state.engagement = $("engageId").value.trim() || "demo";
    if ($("journalEngageLabel")) $("journalEngageLabel").textContent = state.engagement;
    persist();
    refreshStatus();
  });
}

/* ================= BOOTSTRAP ================= */
window.addEventListener("DOMContentLoaded", () => {
  initEventHandlers();
  connect();
});
