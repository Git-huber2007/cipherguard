/* CipherGuard dashboard.
 *
 * All rendering funnels through esc() before anything reaches innerHTML. That is
 * not defensive habit: peer addresses, vendor ID strings and finding subjects
 * are all derived from packet bytes an attacker chose, so the dashboard renders
 * hostile input on every load.
 */
"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  assessment: null,        // latest assessment payload
  platform: null,          // selected remediation platform
  token: null,             // bearer token, when the API requires one
  remediationPlans: [],    // active hardening & rollback plans
  playbookMode: "forward", // "forward" or "rollback"
  wifiGroupMode: true,     // true: group by SSID, false: flat list of all BSSIDs
  currentWifiNetworks: [], // cached list of WifiNetwork items
  wifiAssessment: null,    // latest live wifi & vpn assessment payload
  sessionStartTime: Date.now(),
  telemetryTicks: 0,
  simulatedRogueApActive: false, // interactive rogue AP evil twin simulation toggle
  ipsecMode: "single",     // "single" or "diff"
  diffAssessmentA: null,   // baseline capture A assessment
  diffAssessmentB: null    // hardened capture B assessment
};

/* ---------------------------------------------------------------- helpers */

function esc(s){
  return String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

function shortSpi(h){ return h ? h.slice(0, 8) + "..." : "\u2014"; }

function pickIkeProposal(s){
  // Prefer the responder's selection: that is what was actually agreed, as
  // opposed to everything the initiator was willing to accept.
  for (const m of (s.messages || [])) if (m.is_response)
    for (const p of (m.proposals || [])) if (p.protocol === "IKE") return p;
  for (const m of (s.messages || []))
    for (const p of (m.proposals || [])) if (p.protocol === "IKE") return p;
  return null;
}

function pretty(t){
  let n = t.name.replace(/^ENCR_|^AUTH_|^PRF_/, "");
  if (t.key_length) n += "-" + t.key_length;
  return n;
}

/* Algorithm judgement, mirroring audit/policy.py so a badge colour and a
   finding severity never contradict each other in front of an analyst. */
const BAD = /^(ENCR_)?(3?DES|DES_IV\d+|RC5|IDEA|CAST|BLOWFISH|3IDEA|NULL)/i;
const BAD_HASH = /MD5/i;
const WEAK_HASH = /SHA1|SHA_1/i;

function algClass(t){
  if (t.type_id === 4){                       // Diffie-Hellman group
    const id = t.value_id;
    if ([1, 2, 22, 25].includes(id)) return "bad";
    if ([5, 26].includes(id)) return "warn";
    return "good";
  }
  const n = t.name;
  if (BAD.test(n) || BAD_HASH.test(n)) return "bad";
  if (WEAK_HASH.test(n)) return "warn";
  if (/GCM|CHACHA|CCM/.test(n)) return "good";
  if (/SHA2/.test(n)) return "good";
  return "";
}

function suiteClass(name){
  if (!name) return "";
  // matches both suite names and framing-class names
  if (/NULL|3?DES|unencrypted|64-bit block/i.test(name)) return "bad";
  if (/96-bit ICV/i.test(name)) return "warn";
  if (/CBC/.test(name)) return "warn";
  return "good";
}

/* ------------------------------------------------------------------- api */

/* The API gained optional bearer auth, so every call has to carry the token and
   handle 401 by asking for one — otherwise an authenticated deployment renders
   an empty dashboard with no indication why. */
function authHeaders(extra){
  const headers = Object.assign({}, extra || {});
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  return headers;
}

async function api(path, options){
  const opts = Object.assign({}, options || {});
  opts.headers = authHeaders(opts.headers);
  let res = await fetch(path, opts);

  if (res.status === 401){
    const supplied = window.prompt(
      "This CipherGuard instance requires an API token.");
    if (!supplied) throw new Error("authentication required");
    state.token = supplied.trim();
    try { sessionStorage.setItem("cipherguard.token", state.token); } catch (e) {}
    opts.headers = authHeaders(options && options.headers);
    res = await fetch(path, opts);
  }
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return res;
}

function showBanner(message, kind){
  const el = $("banner");
  if (!message){ el.hidden = true; return; }
  el.textContent = message;
  // an informational banner must not look like the error banner, or a working
  // static demo reads as a broken deployment
  el.className = kind === "info" ? "banner info" : "banner";
  el.hidden = false;
}

/* --------------------------------------------------------- wire ribbon */

const DEFAULT_RIBBON = [
  {d:"obs", n:"IP header",        v:"peer addresses, protocol"},
  {d:"obs", n:"UDP 500 / 4500",   v:"IKE or NAT-T encapsulation"},
  {d:"obs", n:"IKE header",       v:"SPIs, exchange type, flags"},
  {d:"obs", n:"SA proposal",      v:"cipher, PRF, integrity, DH group"},
  {d:"obs", n:"KE / Nonce / VID", v:"group, vendor fingerprint"},
  {d:"seam"},
  {d:"inf", n:"SK payload",       v:"child SA proposal — encrypted"},
  {d:"inf", n:"ESP header",       v:"SPI, sequence number"},
  {d:"inf", n:"ESP ciphertext",   v:"suite inferred from framing"}
];

function renderRibbonTo(targetId, a){
  const el = $(targetId);
  if (!el) return;
  const parts = DEFAULT_RIBBON.map(f => Object.assign({}, f));
  if (a){
    const s = a.sessions && a.sessions[0];
    if (s){
      const prop = pickIkeProposal(s);
      parts[2].v = `${s.version} · ${shortSpi(s.initiator_spi)}`;
      if (prop) parts[3].v = prop.transforms.map(pretty).join(" · ");
      const vid = (s.vendor_ids || [])[0];
      if (vid) parts[4].v = vid.length > 34 ? vid.slice(0, 34) + "…" : vid;
    }
    const f = a.flows && a.flows[0];
    if (f){
      parts[7].v = `SPI ${f.spi} · ${f.packets} packets`;
      parts[8].v = `${f.framing_class || f.predicted_suite || "unresolved"} `
        + `(${Math.round((f.framing_confidence ?? f.confidence ?? 0) * 100)}%)`;
    }
  }
  el.innerHTML = parts.map(f =>
    f.d === "seam"
      ? `<div class="seam" aria-hidden="true"></div>`
      : `<div class="field ${f.d}">`
      + `<div class="fname">${esc(f.n)}</div>`
      + `<div class="fval">${esc(f.v)}</div></div>`
  ).join("");
}

function renderRibbon(a){
  renderRibbonTo("ribbon", a);
}

/* --------------------------------------------------------------- panels */

function renderScore(a){
  const score = a.score, circ = 2 * Math.PI * 49;
  const colour = score >= 75 ? "var(--ok)" : score >= 50 ? "var(--med)" : "var(--crit)";
  const arc = $("arc");
  arc.setAttribute("stroke", colour);
  arc.setAttribute("stroke-dasharray",
    `${(score / 100 * circ).toFixed(1)} ${circ.toFixed(1)}`);
  $("dialnum").textContent = score;

  $("grade").textContent = `Grade ${a.grade}`;
  const crit = a.counts.critical, high = a.counts.high;
  $("gradesub").textContent =
    crit ? `${crit} critical ${crit === 1 ? "issue needs" : "issues need"} `
         + "attention before this link is fit for sensitive traffic."
    : high ? `No critical issues. ${high} high-severity `
           + `${high === 1 ? "item" : "items"} to schedule.`
    : "No critical or high-severity issues on the observed associations.";

  $("sevrow").innerHTML = ["critical", "high", "medium", "low", "info"]
    .filter(k => a.counts[k])
    .map(k => `<span class="sev-chip ${k}">${a.counts[k]} ${esc(k)}</span>`)
    .join("") || `<span class="sev-chip info">clean</span>`;

  const s = a.stats;
  $("stats").innerHTML = [
    [s.packets_read, "packets read"],
    [s.ike_sessions, "IKE sessions"],
    [s.esp_flows_assessed, "ESP tunnels"],
    [a.throughput ? a.throughput.packets_per_second.toLocaleString() : "—", "packets/sec"],
    [s.analysis_seconds + "s", "analysis time"],
    [s.parse_errors, "parse errors"]
  ].map(([k, l]) =>
    `<div class="stat"><div class="k">${esc(k)}</div>`
    + `<div class="l">${esc(l)}</div></div>`).join("");

  $("capmeta").textContent =
    `${a.capture} · assessed ${a.started} · report ${a.digest}`;
}

function renderSessions(a){
  const el = $("sessions");
  if (!a.sessions.length){
    el.innerHTML = `<div class="empty">No IKE negotiation observed in this capture.</div>`;
    return;
  }
  el.innerHTML = a.sessions.map(s => {
    const prop = pickIkeProposal(s);
    const algs = prop
      ? prop.transforms.map(t =>
          `<span class="alg ${algClass(t)}">${esc(pretty(t))}</span>`).join("")
      : `<span class="alg">proposal not observed</span>`;
    const notes = (s.notifies || []).length ? ` · ${s.notifies.length} notify` : "";
    const retx = s.retransmissions ? ` · ${s.retransmissions} retransmitted` : "";
    return `<div class="rec">
      <div class="peers">${esc(s.peer_a)} &harr; ${esc(s.peer_b)}</div>
      <div class="meta">${esc(s.version)} · ${esc(s.vendor_family)} · `
      + `${s.messages.length} messages${esc(notes)}${esc(retx)}</div>
      <div class="algs">${algs}</div>
    </div>`;
  }).join("");
}

function renderFlows(a){
  const el = $("flows");
  if (!a.flows.length){
    el.innerHTML = `<div class="empty">No ESP traffic observed in this capture.</div>`;
    return;
  }
  el.innerHTML = a.flows.map(f => {
    // Report the framing class and its total probability mass, not a single
    // member at its exact-suite score. Naming one suite out of a set the wire
    // cannot separate reads as a wrong answer to anyone who checks it against
    // the negotiated IKE proposal shown alongside.
    const pct = Math.round((f.framing_confidence ?? f.confidence ?? 0) * 100);
    const label = f.framing_class || f.predicted_suite || "unresolved";
    const candidates = f.ambiguous
      ? `<div class="cand">${esc(f.framing_candidates.join(" or "))}</div>`
        + `<div class="cand">framing-identical; not separable passively</div>`
      : "";
    return `<div class="rec">
      <div class="peers">${esc(f.src)} &rarr; ${esc(f.dst)}</div>
      <div class="meta">SPI ${esc(f.spi)} · ${f.packets} packets · mean ${f.mean_payload}B${f.encapsulated ? " · NAT-T" : ""}</div>
      <div class="algs"><span class="alg ${suiteClass(label)}">${esc(label)}</span></div>
      <div class="confbar"><i style="width:${pct}%"></i></div>
      <div class="cand">${pct}% confidence in the framing class</div>
      ${candidates}
    </div>`;
  }).join("");
}

function renderFindings(a){
  const el = $("findings");
  if (!a.findings.length){
    el.innerHTML = `<div class="empty">No findings. `
      + `Every observed association meets the baseline.</div>`;
    $("findsub").textContent = "Nothing to review.";
    return;
  }
  const inferred = a.findings.filter(f => f.inferred).length;
  $("findsub").textContent =
    `${a.findings.length} findings · ${a.findings.length - inferred} from parsed `
    + `bytes, ${inferred} inferred from encrypted traffic.`;

  el.innerHTML = a.findings.map((f, i) => `
    <div class="finding" data-i="${i}">
      <div class="fhead" role="button" tabindex="0" aria-expanded="false">
        <span class="sev-mark ${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="fmain">
          <span class="ftitle">${esc(f.title)}</span>
          ${f.inferred
            ? `<span class="domain-tag inf inline">inferred</span>` : ``}
          <div class="fsub">${esc(f.rule_id)} · ${esc(f.subject)}</div>
        </span>
        <span class="chev">+</span>
      </div>
      <div class="fbody">
        <p>${esc(f.detail)}</p>
        <div class="ref">${esc(f.reference)}</div>
        <div class="fix"><b>Fix:</b> ${esc(f.remediation)}</div>
      </div>
    </div>`).join("");

  el.querySelectorAll(".fhead").forEach(h => {
    const toggle = () => {
      const open = h.parentElement.classList.toggle("open");
      h.setAttribute("aria-expanded", open ? "true" : "false");
      h.querySelector(".chev").textContent = open ? "\u2212" : "+";
    };
    h.addEventListener("click", toggle);
    h.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " "){ e.preventDefault(); toggle(); }
    });
  });
}

function renderPQ(a){
  const plan = a.roadmap;
  const el = $("pqlinks"), mo = $("mosca");
  if (!plan || !plan.links.length){
    el.innerHTML = `<div class="empty">No IKE negotiation observed, `
      + `so no key exchange to assess.</div>`;
    mo.innerHTML = "";
    return;
  }
  const as = plan.assumptions, sm = plan.summary;
  $("pqsub").textContent =
    `${sm.quantum_exposed} of ${sm.links_assessed} links are quantum-exposed, `
    + `carrying ${(sm.total_bytes_harvestable / 1e6).toFixed(1)} MB of observed traffic.`;

  mo.className = "mosca " + (as.already_late ? "late" : "ok");
  mo.innerHTML = as.already_late
    ? `Data classed <b>${esc(as.data_class)}</b> stays sensitive for `
      + `${as.secrecy_lifetime_years} years and migration takes ${as.migration_years}. `
      + `Against a ${as.crqc_years}-year quantum estimate that is a `
      + `<b>${as.mosca_gap_years}-year shortfall</b> — traffic recorded today will `
      + `still be sensitive when it becomes readable.`
    : `Data classed <b>${esc(as.data_class)}</b> leaves `
      + `${Math.abs(as.mosca_gap_years)} years of margin before the quantum `
      + `estimate. Migration is not yet urgent for this class.`;

  const links = plan.links.map(l => `
    <div class="pql ${l.quantum_safe ? "" : "exposed"}">
      <span class="pqrank">${l.priority}</span>
      <span class="pqbody">
        <div class="pqpeer">${esc(l.peer)}</div>
        <div class="pqbits">${l.classical_bits} classical / ${l.quantum_bits} `
      + `quantum bits · ${esc(l.kex_family.toUpperCase())} · `
      + `${(l.bytes_observed / 1e6).toFixed(1)} MB at ${l.harvest_rate_mbps} Mbps</div>
        <div class="pqwhy">${esc(l.rationale)}</div>
      </span>
      <span class="pqidx ${l.quantum_safe ? "safe" : "exposed"}">`
      + `${l.quantum_safe ? "PQ-safe" : "exposure " + l.exposure_index}</span>
    </div>`).join("");

  const phases = plan.phases.length
    ? `<div class="phases">` + plan.phases.map(ph => `
        <div class="phase">
          <h3>Phase ${ph.phase} — ${esc(ph.window)}</h3>
          <p>${esc(ph.action)}</p>
          <div class="tgt">${esc(ph.target)}</div>
        </div>`).join("") + `</div>`
    : "";

  el.innerHTML = links + phases;
}

function renderPlatforms(a){
  const row = $("platforms");
  const plats = (state.remediationPlans && state.remediationPlans.length)
    ? state.remediationPlans.map(p => ({id: p.platform, name: p.platform_name}))
    : (a && a.platforms ? a.platforms : [
        {id: "cisco", name: "Cisco IOS / IOS-XE"},
        {id: "strongswan", name: "strongSwan (swanctl)"},
        {id: "fortinet", name: "Fortinet FortiOS"},
        {id: "juniper", name: "Juniper SRX (Junos)"}
      ]);

  if (!plats.length){ row.innerHTML = ""; return; }
  if (!plats.some(p => p.id === state.platform)) state.platform = plats[0].id;

  row.innerHTML = plats.map(p =>
    `<button class="ghost" data-p="${esc(p.id)}" `
    + `aria-pressed="${p.id === state.platform}">${esc(p.name)}</button>`).join("");

  row.querySelectorAll("button").forEach(b =>
    b.addEventListener("click", () => {
      state.platform = b.dataset.p;
      row.querySelectorAll("button").forEach(btn => btn.setAttribute("aria-pressed", btn.dataset.p === state.platform));
      if (state.remediationPlans && state.remediationPlans.length) {
        renderPlaybookUI();
      } else {
        loadRemediation();
      }
    }));
}

function renderPlaybookUI(){
  if (!state.remediationPlans || !state.remediationPlans.length) return;
  const currentPlan = state.remediationPlans.find(p => p.platform === state.platform) || state.remediationPlans[0];
  if (!currentPlan) return;
  state.platform = currentPlan.platform;

  // Highlight active platform button
  const row = $("platforms");
  if (row) {
    row.querySelectorAll("button").forEach(b => {
      b.setAttribute("aria-pressed", b.dataset.p === state.platform);
    });
  }

  // Update syntax badge
  const syntaxBadge = $("playbook-syntax-badge");
  if (syntaxBadge) {
    if (currentPlan.syntax_valid) {
      syntaxBadge.className = "playbook-chip chip-ok";
      syntaxBadge.textContent = "✔ Syntax Valid";
      syntaxBadge.title = "Passes vendor grammar and RFC 8247 structure rules";
    } else {
      syntaxBadge.className = "playbook-chip chip-err";
      syntaxBadge.textContent = "✖ Syntax Warning";
      syntaxBadge.title = (currentPlan.syntax_errors || []).join("; ");
    }
  }

  // Update status badge
  const statusBadge = $("playbook-status-badge");
  if (statusBadge) {
    const st = currentPlan.status || "DRAFTED";
    statusBadge.className = "playbook-chip chip-status " + st.toLowerCase();
    if (st === "APPROVED") {
      statusBadge.textContent = `Status: APPROVED (${currentPlan.approver || "Admin"})`;
    } else if (st === "STAGED") {
      statusBadge.textContent = "Status: STAGED (Dry-Run)";
    } else {
      statusBadge.textContent = "Status: " + st;
    }
  }

  // Update Forward/Rollback tabs
  const fwdBtn = $("btn-playbook-forward");
  const rlbBtn = $("btn-playbook-rollback");
  if (fwdBtn) fwdBtn.classList.toggle("active", state.playbookMode === "forward");
  if (rlbBtn) rlbBtn.classList.toggle("active", state.playbookMode === "rollback");

  // Render code
  const pre = $("remediation");
  if (pre) {
    const raw = state.playbookMode === "rollback" ? currentPlan.rollback_config : currentPlan.forward_config;
    pre.innerHTML = (raw || "").split("\n").map(l =>
      /^\s*[#!]/.test(l) ? `<span class="cm">${esc(l)}</span>` : esc(l)).join("\n");
  }
}

async function loadRemediation(){
  if (staticMode.active){
    const pre = $("remediation");
    const canned = (state.assessment && state.assessment.remediation) || {};
    const text = canned[state.platform];
    if (!text){ pre.textContent = "No hardening plan in this build."; return; }
    pre.innerHTML = text.split("\n").map(l =>
      /^\s*[#!]/.test(l) ? `<span class="cm">${esc(l)}</span>` : esc(l)).join("\n");
    return;
  }
  return loadRemediationLive();
}

async function loadRemediationLive(){
  if (!state.assessment) return;
  const pre = $("remediation");
  pre.textContent = "Synthesizing multi-vendor hardening & rollback playbooks…";
  try{
    const res = await api(`/api/remediation/${encodeURIComponent(state.assessment.capture)}`);
    if (res.ok) {
      const data = await res.json();
      state.remediationPlans = data.plans || [];
      if (state.remediationPlans.length > 0) {
        if (!state.platform || !state.remediationPlans.some(p => p.platform === state.platform)) {
          state.platform = state.remediationPlans[0].platform;
        }
        renderPlatforms(state.assessment);
        renderPlaybookUI();
        return;
      }
    }
    const res2 = await api("/api/remediate", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        capture: state.assessment.capture, platform: state.platform
      })
    });
    const text = await res2.text();
    pre.innerHTML = text.split("\n").map(l =>
      /^\s*[#!]/.test(l) ? `<span class="cm">${esc(l)}</span>` : esc(l)).join("\n");
  }catch(err){
    pre.textContent = "Could not generate the hardening plan: " + err.message;
  }
}

/* ------------------------------------------------------------ data flow */

// Static mode: on GitHub Pages there is no backend, so the dashboard reads
// pre-computed analyses written by `cipherguard export-demo`. The payloads are
// the real pipeline's output in the same shape the API returns, so every render
// path below is identical and neither version can quietly diverge from the
// other. Detected by probing for the manifest rather than by a build flag.
const staticMode = {active: false, manifest: null};

async function detectStaticMode(){
  try{
    const res = await fetch("data/manifest.json", {cache: "no-store"});
    if (!res.ok) return false;
    staticMode.manifest = await res.json();
    staticMode.active = true;
    return true;
  }catch{
    return false;
  }
}

function populateCaptureSelects(items){
  const sel = $("capture");
  const selA = $("diff-capture-a");
  const selB = $("diff-capture-b");

  const optsHtml = items.map(c =>
    `<option value="${esc(c.name)}">${esc(c.name)} — ${c.size_kb} KB</option>`
  ).join("");

  if (sel) sel.innerHTML = optsHtml;
  if (selA) selA.innerHTML = optsHtml;
  if (selB) selB.innerHTML = optsHtml;

  // Set smart default diff selection
  if (selA && selB && items.length >= 2){
    const downgrade = items.find(c => /downgrade|legacy/i.test(c.name));
    if (downgrade) selA.value = downgrade.name;
    else selA.selectedIndex = 0;

    const hardened = items.find(c => /hardened|backbone/i.test(c.name));
    if (hardened) selB.value = hardened.name;
    else selB.selectedIndex = Math.min(items.length - 1, 1);
  }
}

async function loadCapturesStatic(){
  const caps = staticMode.manifest.captures || [];
  if (!caps.length){
    if ($("capture")) $("capture").innerHTML = `<option value="">No captures in this build</option>`;
    if ($("run")) $("run").disabled = true;
    return;
  }
  populateCaptureSelects(caps);
  showBanner("Static demo: analyses were pre-computed by the real pipeline. "
             + "Install CipherGuard to assess your own captures.", "info");
}

async function loadCaptures(){
  if (await detectStaticMode()) return loadCapturesStatic();
  try{
    const {captures} = await (await api("/api/captures")).json();
    if (!captures.length){
      if ($("capture")) $("capture").innerHTML = `<option value="">No captures found</option>`;
      if ($("run")) $("run").disabled = true;
      showBanner("No capture files found. Generate the reference set with: "
                 + "cipherguard lab");
      return;
    }
    populateCaptureSelects(captures);
    showBanner(null);
  }catch(err){
    if ($("capture")) $("capture").innerHTML = `<option value="">Backend unreachable</option>`;
    if ($("run")) $("run").disabled = true;
    showBanner("Could not reach the CipherGuard API: " + err.message);
  }
}

async function fetchAssessment(name){
  if (!name) throw new Error("No capture selected.");
  if (staticMode.active){
    const entry = (staticMode.manifest.captures || []).find(c => c.name === name);
    if (!entry) throw new Error("no pre-computed analysis for " + name);
    const res = await fetch(entry.file, {cache: "no-store"});
    if (!res.ok) throw new Error("could not load " + entry.file);
    return await res.json();
  } else {
    const res = await api("/api/analyze", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({capture: name})
    });
    return await res.json();
  }
}

async function runAnalysis(){
  const name = $("capture").value;
  if (!name) return;
  const btn = $("run");
  btn.disabled = true;
  btn.textContent = "Assessing…";
  try{
    state.assessment = await fetchAssessment(name);
    renderScore(state.assessment);
    renderSessions(state.assessment);
    renderFlows(state.assessment);
    renderFindings(state.assessment);
    renderRibbon(state.assessment);
    renderPQ(state.assessment);
    renderPlatforms(state.assessment);
    await loadRemediation();
    showBanner(null);
  }catch(err){
    $("capmeta").textContent = "Assessment failed: " + err.message;
  }finally{
    btn.disabled = false;
    btn.textContent = "Assess capture";
  }
}

function switchIpsecMode(mode){
  state.ipsecMode = mode;
  const singleBtn = $("btn-ipsec-single");
  const diffBtn = $("btn-ipsec-diff");
  const singleControls = $("ipsec-single-controls");
  const diffControls = $("ipsec-diff-controls");
  const singleView = $("ipsec-single-view");
  const diffView = $("ipsec-diff-view");

  if (mode === "diff"){
    if (singleBtn) singleBtn.classList.remove("active");
    if (diffBtn) diffBtn.classList.add("active");
    if (singleControls) singleControls.style.display = "none";
    if (diffControls) diffControls.style.display = "flex";
    if (singleView) singleView.style.display = "none";
    if (diffView) diffView.style.display = "block";

    // Auto-run diff if not already analyzed
    if (!state.diffAssessmentA || !state.diffAssessmentB){
      runDiffAnalysis();
    }
  } else {
    if (singleBtn) singleBtn.classList.add("active");
    if (diffBtn) diffBtn.classList.remove("active");
    if (singleControls) singleControls.style.display = "flex";
    if (diffControls) diffControls.style.display = "none";
    if (singleView) singleView.style.display = "block";
    if (diffView) diffView.style.display = "none";
  }
}

function extractSuiteInfo(assessment){
  if (!assessment) return {};
  const s = (assessment.sessions && assessment.sessions[0]) || null;
  let ikeVersion = "None observed";
  let ikeCipher = "None / Cleartext";
  let ikePrf = "None";
  let dhGroup = "None";
  let dhVal = 0;

  if (s){
    ikeVersion = s.version || "IKEv1";
    const prop = pickIkeProposal(s);
    if (prop && prop.transforms){
      const enc = prop.transforms.find(t => t.type_id === 1 || /^ENCR_/.test(t.name));
      if (enc) ikeCipher = pretty(enc);
      const prf = prop.transforms.find(t => t.type_id === 2 || /^PRF_/.test(t.name));
      const auth = prop.transforms.find(t => t.type_id === 3 || /^AUTH_/.test(t.name));
      if (prf) ikePrf = pretty(prf);
      else if (auth) ikePrf = pretty(auth);
      const dh = prop.transforms.find(t => t.type_id === 4);
      if (dh){
        dhGroup = pretty(dh);
        dhVal = dh.value_id;
      }
    }
  }

  const f = (assessment.flows && assessment.flows[0]) || null;
  let espSuite = "None observed";
  let espClass = "none";
  if (f){
    espSuite = f.framing_class || f.predicted_suite || "Unresolved";
    espClass = f.framing_class || "";
  }

  const pq = assessment.roadmap;
  const pqSafe = pq && pq.links && pq.links.length > 0 && pq.links.every(l => l.quantum_safe);
  const pqCount = (pq && pq.links && pq.links.filter(l => !l.quantum_safe).length) || 0;

  return {
    ikeVersion,
    ikeCipher,
    ikePrf,
    dhGroup,
    dhVal,
    espSuite,
    espClass,
    pqSafe,
    pqCount
  };
}

async function runDiffAnalysis(){
  const selA = $("diff-capture-a");
  const selB = $("diff-capture-b");
  const nameA = selA ? selA.value : "";
  const nameB = selB ? selB.value : "";
  if (!nameA || !nameB) return;

  const btn = $("run-diff");
  if (btn){
    btn.disabled = true;
    btn.textContent = "Comparing…";
  }

  try{
    const [a, b] = await Promise.all([fetchAssessment(nameA), fetchAssessment(nameB)]);
    state.diffAssessmentA = a;
    state.diffAssessmentB = b;
    renderDiffView(a, b);
  }catch(err){
    alert("Differential analysis failed: " + err.message);
  }finally{
    if (btn){
      btn.disabled = false;
      btn.textContent = "Run Diff Comparison";
    }
  }
}

function renderDiffView(a, b){
  if (!a || !b) return;

  const scoreA = a.score ?? 0;
  const scoreB = b.score ?? 0;
  const delta = scoreB - scoreA;

  // 1. Delta Hero Badge
  const badge = $("diff-delta-badge");
  const deltaNum = $("diff-delta-num");
  if (badge && deltaNum){
    if (delta > 0){
      badge.className = "diff-delta-badge positive";
      deltaNum.textContent = `+${delta}`;
    } else if (delta < 0){
      badge.className = "diff-delta-badge negative";
      deltaNum.textContent = `${delta}`;
    } else {
      badge.className = "diff-delta-badge neutral";
      deltaNum.textContent = `0`;
    }
  }

  // 2. Summary Cards
  if ($("diff-name-a")) $("diff-name-a").textContent = a.capture || "Baseline";
  if ($("diff-score-a")) $("diff-score-a").textContent = `${scoreA}/100`;
  const gradeAEl = $("diff-grade-a");
  if (gradeAEl){
    gradeAEl.textContent = `Grade ${a.grade || "—"}`;
    gradeAEl.className = `diff-grade-pill grade-badge ${a.grade ? a.grade.replace("+", "") : "B"}`;
  }
  if ($("diff-sevs-a")){
    $("diff-sevs-a").innerHTML = ["critical", "high", "medium", "low"]
      .filter(k => a.counts && a.counts[k])
      .map(k => `<span class="sev-chip ${k}" style="font-size:0.68rem;padding:1px 5px">${a.counts[k]} ${k}</span>`)
      .join(" ") || `<span class="sev-chip info" style="font-size:0.68rem">Clean</span>`;
  }
  if ($("diff-meta-a")){
    $("diff-meta-a").innerHTML = `
      <div style="font-size:0.75rem;color:var(--muted)">
        ${(a.sessions || []).length} IKE Sessions &middot; ${(a.flows || []).length} ESP SAs &middot; ${(a.findings || []).length} Vulnerabilities
      </div>
    `;
  }

  if ($("diff-name-b")) $("diff-name-b").textContent = b.capture || "Hardened";
  if ($("diff-score-b")) $("diff-score-b").textContent = `${scoreB}/100`;
  const gradeBEl = $("diff-grade-b");
  if (gradeBEl){
    gradeBEl.textContent = `Grade ${b.grade || "—"}`;
    gradeBEl.className = `diff-grade-pill grade-badge ${b.grade ? b.grade.replace("+", "") : "B"}`;
  }
  if ($("diff-sevs-b")){
    $("diff-sevs-b").innerHTML = ["critical", "high", "medium", "low"]
      .filter(k => b.counts && b.counts[k])
      .map(k => `<span class="sev-chip ${k}" style="font-size:0.68rem;padding:1px 5px">${b.counts[k]} ${k}</span>`)
      .join(" ") || `<span class="sev-chip info" style="font-size:0.68rem">Clean</span>`;
  }
  if ($("diff-meta-b")){
    $("diff-meta-b").innerHTML = `
      <div style="font-size:0.75rem;color:var(--muted)">
        ${(b.sessions || []).length} IKE Sessions &middot; ${(b.flows || []).length} ESP SAs &middot; ${(b.findings || []).length} Vulnerabilities
      </div>
    `;
  }

  const verdictEl = $("diff-transform-verdict");
  const statDeltaEl = $("diff-stat-delta");
  if (verdictEl && statDeltaEl){
    if (delta > 0){
      verdictEl.innerHTML = `<span style="color:#059669">&#9650; Hardened (+${delta} Pts)</span>`;
      statDeltaEl.textContent = `Security posture upgraded from Grade ${a.grade} to ${b.grade}`;
    } else if (delta < 0){
      verdictEl.innerHTML = `<span style="color:#dc2626">&#9660; Degraded (${delta} Pts)</span>`;
      statDeltaEl.textContent = `Security posture regressed from Grade ${a.grade} to ${b.grade}`;
    } else {
      verdictEl.innerHTML = `<span style="color:var(--muted)">Parity (0 Pts)</span>`;
      statDeltaEl.textContent = `Both captures exhibit equivalent security posture`;
    }
  }

  // 3. Side-by-Side Wire Ribbons
  if ($("diff-ribbon-title-a")) $("diff-ribbon-title-a").textContent = a.capture || "Baseline";
  if ($("diff-ribbon-title-b")) $("diff-ribbon-title-b").textContent = b.capture || "Hardened";
  renderRibbonTo("diff-ribbon-a", a);
  renderRibbonTo("diff-ribbon-b", b);

  // 4. Cryptographic Upgrade Matrix
  const infoA = extractSuiteInfo(a);
  const infoB = extractSuiteInfo(b);

  const matrixRows = [
    {
      param: "IKE Protocol Version",
      valA: infoA.ikeVersion,
      valB: infoB.ikeVersion,
      status: (infoA.ikeVersion === "IKEv1" && infoB.ikeVersion === "IKEv2")
        ? { text: "✔ UPGRADED (IKEv2)", cls: "diff-status-upgraded" }
        : infoA.ikeVersion === infoB.ikeVersion
          ? { text: "— Parity", cls: "diff-status-same" }
          : { text: "✔ Modernized", cls: "diff-status-upgraded" }
    },
    {
      param: "IKE SA Cipher Suite",
      valA: infoA.ikeCipher,
      valB: infoB.ikeCipher,
      status: (BAD.test(infoA.ikeCipher) && !BAD.test(infoB.ikeCipher))
        ? { text: "✔ HARDENED (AEAD)", cls: "diff-status-upgraded" }
        : infoA.ikeCipher === infoB.ikeCipher
          ? { text: "— Unchanged", cls: "diff-status-same" }
          : { text: "✔ Upgraded", cls: "diff-status-upgraded" }
    },
    {
      param: "Integrity & PRF Algorithm",
      valA: infoA.ikePrf,
      valB: infoB.ikePrf,
      status: ((BAD_HASH.test(infoA.ikePrf) || WEAK_HASH.test(infoA.ikePrf)) && !WEAK_HASH.test(infoB.ikePrf) && !BAD_HASH.test(infoB.ikePrf))
        ? { text: "✔ SECURED (SHA-2/3)", cls: "diff-status-upgraded" }
        : infoA.ikePrf === infoB.ikePrf
          ? { text: "— Unchanged", cls: "diff-status-same" }
          : { text: "✔ Upgraded", cls: "diff-status-upgraded" }
    },
    {
      param: "Diffie-Hellman Group",
      valA: infoA.dhGroup,
      valB: infoB.dhGroup,
      status: ([1, 2, 5, 22, 25].includes(infoA.dhVal) && ![1, 2, 5, 22, 25].includes(infoB.dhVal) && infoB.dhVal > 0)
        ? { text: "✔ RESILIENT (High DH)", cls: "diff-status-upgraded" }
        : infoA.dhGroup === infoB.dhGroup
          ? { text: "— Parity", cls: "diff-status-same" }
          : { text: "✔ Modern Group", cls: "diff-status-upgraded" }
    },
    {
      param: "ESP Framing & Tunnel Suite",
      valA: infoA.espSuite,
      valB: infoB.espSuite,
      status: (/64-bit|3?DES|NULL|unencrypted/i.test(infoA.espSuite) && !/64-bit|3?DES|NULL/i.test(infoB.espSuite))
        ? { text: "✔ SECURE TUNNEL", cls: "diff-status-upgraded" }
        : infoA.espSuite === infoB.espSuite
          ? { text: "— Parity", cls: "diff-status-same" }
          : { text: "✔ Hardened", cls: "diff-status-upgraded" }
    },
    {
      param: "Post-Quantum Exposure (PQC)",
      valA: infoA.pqSafe ? "Zero Exposed Links" : `${infoA.pqCount} Links Exposed to HNDL`,
      valB: infoB.pqSafe ? "Zero Exposed Links (PQC Safe)" : `${infoB.pqCount} Links Exposed`,
      status: (!infoA.pqSafe && infoB.pqSafe)
        ? { text: "✔ PQC READY", cls: "diff-status-upgraded" }
        : (infoB.pqCount < infoA.pqCount)
          ? { text: "✔ Exposure Reduced", cls: "diff-status-upgraded" }
          : { text: "— Maintained", cls: "diff-status-same" }
    }
  ];

  const tbody = $("diff-matrix-tbody");
  if (tbody){
    tbody.innerHTML = matrixRows.map(row => `
      <tr>
        <td><b>${esc(row.param)}</b></td>
        <td><code>${esc(row.valA)}</code></td>
        <td><code>${esc(row.valB)}</code></td>
        <td style="text-align:center"><span class="${row.status.cls}">${esc(row.status.text)}</span></td>
      </tr>
    `).join("");
  }

  // 5. Vulnerability Resolution & Risk Elimination
  const findingsA = a.findings || [];
  const findingsB = b.findings || [];

  const bRules = new Set(findingsB.map(f => f.rule_id));
  const bTitles = new Set(findingsB.map(f => f.title));

  const resolved = findingsA.filter(f => !bRules.has(f.rule_id) && !bTitles.has(f.title));
  const persisting = findingsB.filter(f => findingsA.some(fa => fa.rule_id === f.rule_id || fa.title === f.title));
  const newInB = findingsB.filter(f => !findingsA.some(fa => fa.rule_id === f.rule_id || fa.title === f.title));

  if ($("diff-resolved-count")) $("diff-resolved-count").textContent = resolved.length;
  if ($("diff-persisting-count")) $("diff-persisting-count").textContent = persisting.length + newInB.length;

  const resList = $("diff-resolved-list");
  if (resList){
    if (resolved.length === 0){
      resList.innerHTML = `<div class="empty">Zero findings were resolved between these two captures.</div>`;
    } else {
      resList.innerHTML = resolved.map(f => `
        <div class="diff-finding-card resolved">
          <div class="title">
            <span style="color:#059669">&#10004;</span>
            <span>${esc(f.title)}</span>
            <span class="sev-chip ${f.severity.toLowerCase()}" style="font-size:0.65rem;padding:0 5px">${esc(f.severity)}</span>
          </div>
          <div class="meta">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
          <div class="fix"><b>Remediation Confirmed:</b> Vulnerability eliminated in hardened configuration.</div>
        </div>
      `).join("");
    }
  }

  const persistList = $("diff-persisting-list");
  if (persistList){
    const remaining = [...persisting, ...newInB];
    if (remaining.length === 0){
      persistList.innerHTML = `<div class="empty" style="color:#059669;font-weight:600">&#10004; Zero security vulnerabilities remaining in hardened capture!</div>`;
    } else {
      persistList.innerHTML = remaining.map(f => `
        <div class="diff-finding-card persisting">
          <div class="title">
            <span style="color:#d97706">&#9888;</span>
            <span>${esc(f.title)}</span>
            <span class="sev-chip ${f.severity.toLowerCase()}" style="font-size:0.65rem;padding:0 5px">${esc(f.severity)}</span>
          </div>
          <div class="meta">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
          <div class="fix" style="color:#b45309"><b>Action:</b> ${esc(f.remediation || "Review vendor playbook")}</div>
        </div>
      `).join("");
    }
  }
}

/* ------------------------------------------------------------- Wi-Fi logic */

function switchTab(tab){
  const wifiTab = $("tab-wifi");
  const ipsecTab = $("tab-ipsec");
  const wifiView = $("view-wifi");
  const ipsecView = $("view-ipsec");
  const wifiControls = $("wifi-controls");
  const ipsecControls = $("ipsec-controls");

  if (tab === "wifi"){
    wifiTab.classList.add("active");
    wifiTab.setAttribute("aria-selected", "true");
    ipsecTab.classList.remove("active");
    ipsecTab.setAttribute("aria-selected", "false");

    wifiView.classList.add("active");
    ipsecView.classList.remove("active");

    if (wifiControls) wifiControls.style.display = "flex";
    if (ipsecControls) ipsecControls.style.display = "none";
  } else {
    ipsecTab.classList.add("active");
    ipsecTab.setAttribute("aria-selected", "true");
    wifiTab.classList.remove("active");
    wifiTab.setAttribute("aria-selected", "false");

    ipsecView.classList.add("active");
    wifiView.classList.remove("active");

    if (ipsecControls) ipsecControls.style.display = "flex";
    if (wifiControls) wifiControls.style.display = "none";
  }
}


function getStaticWifiDemoData(){
  return {
  "interface": {
    "name": "Wi-Fi",
    "description": "MediaTek MT7921 Wi-Fi 6 802.11ax PCIe Adapter",
    "mac_address": "2c:3b:70:fc:74:8b",
    "state": "connected",
    "ssid": "Svyasa-Student",
    "bssid": "58:61:63:01:73:cc",
    "band": "5 GHz",
    "channel": 44,
    "radio_type": "802.11ax",
    "authentication": "WPA2-Personal",
    "cipher": "CCMP",
    "signal_percent": 79,
    "rssi_dbm": -58,
    "rx_rate_mbps": 573.5,
    "tx_rate_mbps": 573.5,
    "dns_servers": [
      "8.8.8.8",
      "8.8.4.4"
    ],
    "gateway_ip": "10.101.0.1",
    "ipv4_address": "10.101.47.245"
  },
  "networks_in_range": [
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:73:cc",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": true,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:cf:a7",
      "signal_percent": 83,
      "rssi_dbm": -58,
      "channel": 149,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:cf:a7",
      "signal_percent": 83,
      "rssi_dbm": -58,
      "channel": 149,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:cf:a7",
      "signal_percent": 83,
      "rssi_dbm": -58,
      "channel": 149,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:cf:a7",
      "signal_percent": 83,
      "rssi_dbm": -58,
      "channel": 149,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:60:a2",
      "signal_percent": 82,
      "rssi_dbm": -59,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:60:a2",
      "signal_percent": 82,
      "rssi_dbm": -59,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Redmi",
      "bssid": "da:65:64:0c:db:ee",
      "signal_percent": 82,
      "rssi_dbm": -59,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11n",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:cf:a6",
      "signal_percent": 81,
      "rssi_dbm": -59,
      "channel": 1,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:cf:a6",
      "signal_percent": 81,
      "rssi_dbm": -59,
      "channel": 1,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:60:a2",
      "signal_percent": 81,
      "rssi_dbm": -59,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:cf:a6",
      "signal_percent": 81,
      "rssi_dbm": -59,
      "channel": 1,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "OPPO K13x 5G 43f1",
      "bssid": "aa:9b:20:73:38:27",
      "signal_percent": 81,
      "rssi_dbm": -59,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA3-Personal",
      "encryption": "CCMP",
      "security_grade": "A+",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Harsh....",
      "bssid": "2e:14:d6:37:fc:b1",
      "signal_percent": 81,
      "rssi_dbm": -59,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:cf:a6",
      "signal_percent": 80,
      "rssi_dbm": -60,
      "channel": 1,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "vivo T3 Lite 5G",
      "bssid": "1a:bd:03:4e:61:8e",
      "signal_percent": 80,
      "rssi_dbm": -60,
      "channel": 157,
      "band": "5 GHz",
      "radio_type": "802.11ac",
      "authentication": "Open",
      "encryption": "None",
      "security_grade": "F",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "oplus_co_aphfqi",
      "bssid": "66:df:57:d7:4f:34",
      "signal_percent": 80,
      "rssi_dbm": -60,
      "channel": 7,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:70:20",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 40,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:62:b0",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 36,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:73:cc",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:62:b0",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 36,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:73:cc",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:70:20",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 40,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:62:b0",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 36,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:73:cc",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:70:20",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 40,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:62:b0",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 36,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "OPPO A59 5G",
      "bssid": "82:c3:e8:c6:e4:d7",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "NARZO 70x 5G",
      "bssid": "5e:fa:d1:f3:cd:18",
      "signal_percent": 79,
      "rssi_dbm": -60,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA3-Personal",
      "encryption": "CCMP",
      "security_grade": "A+",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:73:cb",
      "signal_percent": 78,
      "rssi_dbm": -61,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:70:20",
      "signal_percent": 78,
      "rssi_dbm": -61,
      "channel": 40,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:60:a2",
      "signal_percent": 78,
      "rssi_dbm": -61,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:73:cb",
      "signal_percent": 78,
      "rssi_dbm": -61,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "OnePlus Nord CE5 6E56",
      "bssid": "76:cf:63:22:75:4e",
      "signal_percent": 78,
      "rssi_dbm": -61,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "HONOR 200",
      "bssid": "5e:60:98:28:6d:5e",
      "signal_percent": 78,
      "rssi_dbm": -61,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:73:cb",
      "signal_percent": 77,
      "rssi_dbm": -61,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:73:cb",
      "signal_percent": 77,
      "rssi_dbm": -61,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Redmi Note 13 5G",
      "bssid": "4a:24:b0:e9:8e:6f",
      "signal_percent": 77,
      "rssi_dbm": -61,
      "channel": 157,
      "band": "5 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Aru's A36",
      "bssid": "52:f2:7c:45:c3:ed",
      "signal_percent": 77,
      "rssi_dbm": -61,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:c8:12",
      "signal_percent": 76,
      "rssi_dbm": -62,
      "channel": 1,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:5b:f3",
      "signal_percent": 75,
      "rssi_dbm": -62,
      "channel": 157,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:f9:4c",
      "signal_percent": 75,
      "rssi_dbm": -62,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:f9:4c",
      "signal_percent": 75,
      "rssi_dbm": -62,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-EXAMCELL",
      "bssid": "58:61:63:11:bf:26",
      "signal_percent": 75,
      "rssi_dbm": -62,
      "channel": 149,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:f9:4c",
      "signal_percent": 72,
      "rssi_dbm": -64,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:5b:f3",
      "signal_percent": 72,
      "rssi_dbm": -64,
      "channel": 157,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:62:af",
      "signal_percent": 72,
      "rssi_dbm": -64,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "realme NARZO 70 Turbo 5G",
      "bssid": "56:94:e3:46:b3:c9",
      "signal_percent": 72,
      "rssi_dbm": -64,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:f9:4c",
      "signal_percent": 72,
      "rssi_dbm": -64,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "AndroidAP_6469",
      "bssid": "72:f1:7a:13:b6:31",
      "signal_percent": 66,
      "rssi_dbm": -67,
      "channel": 36,
      "band": "5 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA3-Personal",
      "encryption": "CCMP",
      "security_grade": "A+",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:62:38",
      "signal_percent": 63,
      "rssi_dbm": -68,
      "channel": 149,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "OnePlus Nord 5 BAFE",
      "bssid": "8a:7e:b2:ed:56:b3",
      "signal_percent": 63,
      "rssi_dbm": -68,
      "channel": 1,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Nikhill",
      "bssid": "16:1e:10:a0:80:e7",
      "signal_percent": 63,
      "rssi_dbm": -68,
      "channel": 40,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA3-Personal",
      "encryption": "CCMP",
      "security_grade": "A+",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "S-Vyasa BSNL",
      "bssid": "54:a2:45:13:8c:5c",
      "signal_percent": 60,
      "rssi_dbm": -70,
      "channel": 5,
      "band": "2.4 GHz",
      "radio_type": "802.11n",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "CK....",
      "bssid": "4e:99:4a:2f:21:5c",
      "signal_percent": 60,
      "rssi_dbm": -70,
      "channel": 48,
      "band": "5 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "realme P4 Power 5G",
      "bssid": "86:17:4d:8e:4e:bf",
      "signal_percent": 54,
      "rssi_dbm": -73,
      "channel": 6,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA3-Personal",
      "encryption": "CCMP",
      "security_grade": "A+",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "vivo Y51 Pro 5G",
      "bssid": "d6:92:e4:4b:82:8b",
      "signal_percent": 54,
      "rssi_dbm": -73,
      "channel": 36,
      "band": "5 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Nishtha",
      "bssid": "56:1a:aa:48:91:2d",
      "signal_percent": 54,
      "rssi_dbm": -73,
      "channel": 40,
      "band": "5 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "salaar\ud83d\udd25\ud83d\udd25",
      "bssid": "ce:f3:f6:da:55:28",
      "signal_percent": 54,
      "rssi_dbm": -73,
      "channel": 1,
      "band": "2.4 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa Bosscoder Faculty",
      "bssid": "58:61:63:21:f8:2b",
      "signal_percent": 51,
      "rssi_dbm": -74,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "RaHuL\ud83c\udf41",
      "bssid": "8e:f9:82:64:ea:ff",
      "signal_percent": 51,
      "rssi_dbm": -74,
      "channel": 48,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA3-Personal",
      "encryption": "CCMP",
      "security_grade": "A+",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Faculty",
      "bssid": "58:61:63:21:5b:bb",
      "signal_percent": 48,
      "rssi_dbm": -76,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-IT",
      "bssid": "58:61:63:31:5b:bb",
      "signal_percent": 45,
      "rssi_dbm": -77,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Staff",
      "bssid": "58:61:63:11:5b:bb",
      "signal_percent": 42,
      "rssi_dbm": -79,
      "channel": 11,
      "band": "2.4 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa-Student",
      "bssid": "58:61:63:01:7d:a4",
      "signal_percent": 39,
      "rssi_dbm": -80,
      "channel": 40,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Redmi Note 10T 5G",
      "bssid": "e6:00:3d:65:3a:8a",
      "signal_percent": 27,
      "rssi_dbm": -86,
      "channel": 56,
      "band": "5 GHz",
      "radio_type": "802.11ac",
      "authentication": "WPA3-Personal",
      "encryption": "CCMP",
      "security_grade": "A+",
      "connected": false,
      "notes": ""
    },
    {
      "ssid": "Svyasa Bosscoder Faculty",
      "bssid": "58:61:63:21:f8:f8",
      "signal_percent": 24,
      "rssi_dbm": -88,
      "channel": 44,
      "band": "5 GHz",
      "radio_type": "802.11ax",
      "authentication": "WPA2-Personal",
      "encryption": "CCMP",
      "security_grade": "B",
      "connected": false,
      "notes": ""
    }
  ],
  "score": 85,
  "grade": "B",
  "started": "2026-09-12T06:30:07.791389+00:00",
  "findings": [
    {
      "severity": "medium",
      "rule_id": "WIFI-004",
      "title": "WPA2 Pre-Shared Key (PSK) Vulnerable to Offline Dictionary Attack",
      "subject": "SSID: Svyasa-Student (WPA2-Personal)",
      "detail": "WPA2 4-Way Handshake allows passive adversaries recording the handshake to execute offline dictionary and brute-force attacks against the pre-shared key (PMK/PTK).",
      "remediation": "Enable WPA3-Personal (SAE - Simultaneous Authentication of Equals) with Protected Management Frames (PMF / 802.11w) on your router.",
      "reference": "IEEE 802.11-2020 / NIST SP 800-162",
      "inferred": false
    },
    {
      "severity": "info",
      "rule_id": "WIFI-021",
      "title": "Multi-AP Mesh / BSS Roaming Environment",
      "subject": "SSID: Svyasa-Student (10 APs in range)",
      "detail": "Detected 10 legitimate BSSIDs operating under matching security parameters (WPA2-Personal).",
      "remediation": "Ensure 802.11r (Fast BSS Transition) and 802.11k/v are enabled for seamless roaming.",
      "reference": "IEEE 802.11r-2008",
      "inferred": false
    },
    {
      "severity": "info",
      "rule_id": "WIFI-040",
      "title": "Wi-Fi Key Exchange Post-Quantum Susceptibility",
      "subject": "WPA2/WPA3 Key Derivation",
      "detail": "WPA2 (PBKDF2/SHA1) and WPA3 (ECC Dragonfly P-256) rely on classical cryptography. A recorded Wi-Fi capture can eventually be broken if decrypted by a Cryptanalytically Relevant Quantum Computer (CRQC) or via pre-shared key recovery.",
      "remediation": "Layer IPsec (RFC 9370 post-quantum hybrid KEM) or WireGuard over sensitive Wi-Fi connections.",
      "reference": "CNSA 2.0 / NIST PQC Standardization",
      "inferred": false
    }
  ],
  "counts": {
    "critical": 0,
    "high": 0,
    "medium": 1,
    "low": 0,
    "info": 2
  },
  "summary": "Connected to 'Svyasa-Student' on 5 GHz (Channel 44). Security: WPA2-Personal / CCMP with 79% signal. Score: 85/100 (Grade B).",
  "dns_posture": {
    "dns_servers": [
      "8.8.8.8",
      "8.8.4.4"
    ],
    "gateway": "10.101.0.1",
    "ipv4": "10.101.47.245"
  },
  "quantum_risk": "Standard Classical (ECC/RSA Handshake at Risk to CRQC)",
  "vpn": {
    "connected": false,
    "adapter_name": "",
    "adapter_description": "",
    "vpn_type": "None",
    "virtual_ip": "",
    "gateway_ip": "",
    "route_metric": 0,
    "is_default_route": false,
    "dns_servers": [],
    "dns_leak_detected": false,
    "dns_leak_details": "",
    "egress_ip": "115.240.162.162",
    "egress_isp": "Reliance Jio Infocomm Limited",
    "egress_country": "India",
    "egress_city": "Mumbai",
    "findings": [
      {
        "severity": "info",
        "rule_id": "VPN-010",
        "title": "Direct Physical Egress (No Virtual VPN Tunnel)",
        "subject": "Egress: Direct to ISP (Reliance Jio Infocomm Limited)",
        "detail": "Device network traffic egresses directly through the local Wi-Fi router to the public ISP without an outer IPsec or WireGuard protective tunnel. Local network administrators and upstream ISPs can inspect unencrypted transport metadata and SNI hostnames.",
        "remediation": "For sensitive remote access or untrusted networks, establish an IPsec (RFC 4301) or WireGuard tunnel.",
        "reference": "NIST SP 800-77 / NIST SP 800-113",
        "inferred": false
      }
    ]
  }
};
}

async function loadWifiAssessment(forceScan = false){
  const refreshBtn = $("wifi-refresh-btn");
  const scanBtn = $("wifi-scan-now");
  if (refreshBtn) { refreshBtn.disabled = true; refreshBtn.textContent = "Scanning..."; }
  if (scanBtn) { scanBtn.disabled = true; scanBtn.textContent = "Scanning..."; }

  try{
    if (staticMode.active){
      if (forceScan) {
        await new Promise(r => setTimeout(r, 400));
      }
      let data = null;
      try {
        const res = await fetch("data/wifi_demo.json", {cache: "no-store"});
        if (res.ok) data = await res.json();
      } catch (e) {}
      if (!data || !data.networks_in_range || data.networks_in_range.length === 0) data = getStaticWifiDemoData();
      state.wifiAssessment = data;
      renderWifiDashboard(data);
      $("wifi-last-scan").textContent = "Interactive Demo (GitHub Pages) — " + new Date().toLocaleTimeString();
    } else {
      const endpoint = forceScan ? "/api/wifi/scan" : "/api/wifi/current";
      const method = forceScan ? "POST" : "GET";
      const res = await api(endpoint, {method});
      const data = await res.json();
      state.wifiAssessment = data;
      renderWifiDashboard(data);
      $("wifi-last-scan").textContent = "Last scanned: " + new Date().toLocaleTimeString();
    }
  }catch(err){
    console.warn("Live Wi-Fi fetch fallback:", err);
    const fallback = getStaticWifiDemoData();
    state.wifiAssessment = fallback;
    renderWifiDashboard(fallback);
    $("wifi-last-scan").textContent = "Demonstration Mode Active";
  }finally{
    if (refreshBtn) { refreshBtn.disabled = false; refreshBtn.textContent = "\uD83D\uDD04 Analyze Live Wi-Fi"; }
    if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = "\uD83D\uDCE1 Scan All Networks"; }
  }
}


  function renderWifiDashboard(data){
  if (!data) return;
  // If networks_in_range is missing or empty, ensure fallback demo networks are populated without overwriting real live interface
  if (!data.networks_in_range || data.networks_in_range.length === 0){
    const demo = getStaticWifiDemoData();
    data.networks_in_range = demo.networks_in_range || [];
    if (!data.interface) data.interface = demo.interface;
    if (!data.rogue_aps) data.rogue_aps = demo.rogue_aps || [];
  }
  const iface = data.interface;

  let networks = (data.networks_in_range || []).map(n => Object.assign({}, n));
  let rogueList = (data.rogue_aps || []).map(r => Object.assign({}, r));

  // If user requested simulated Evil Twin AP attack, inject realistic clone AP into live view
  if (state.simulatedRogueApActive) {
    const activeSsid = (iface && iface.ssid) ? iface.ssid : "Svyasa-Student";
    const simRogue = {
      ssid: activeSsid,
      bssid: "58:61:63:de:ad:01",
      signal_percent: 96,
      rssi_dbm: -38,
      channel: (iface && iface.channel) ? iface.channel : 44,
      band: (iface && iface.band) ? iface.band : "5 GHz",
      radio_type: "802.11ax",
      authentication: "Open",
      encryption: "None",
      security_grade: "F",
      connected: false,
      is_rogue: true,
      rogue_reason: `Open / Unencrypted clone of secured WPA2 network '${activeSsid}' (Classic Evil Twin MitM honeypot)`
    };
    if (!networks.some(n => n.bssid === simRogue.bssid)){
      networks.unshift(simRogue);
    }
    if (!rogueList.some(r => r.bssid === simRogue.bssid)){
      rogueList.unshift({
        ssid: simRogue.ssid,
        bssid: simRogue.bssid,
        channel: simRogue.channel,
        signal: `${simRogue.signal_percent}% (${simRogue.rssi_dbm} dBm)`,
        threat_level: "CRITICAL",
        reason: simRogue.rogue_reason
      });
    }
  }

  // Render or hide the Evil Twin Alert Banner
  const banner = $("wifi-evil-twin-banner");
  if (banner) {
    if (rogueList.length > 0) {
      banner.style.display = "flex";
      const primaryRogue = rogueList[0];
      const descEl = $("evil-twin-desc");
      if (descEl) {
        descEl.innerHTML = `An active rogue clone of network <strong>"${esc(primaryRogue.ssid)}"</strong> was detected broadcasting at high RF power. Rogue access points advertise legitimate SSIDs with downgraded security to entice victim devices to connect, exposing all cleartext data, session cookies, and login credentials to an active Man-In-The-Middle (MitM) adversary.`;
      }
      const pillsEl = $("evil-twin-pills");
      if (pillsEl) {
        pillsEl.innerHTML = `
          <span class="evil-twin-pill">Target SSID: <strong>${esc(primaryRogue.ssid)}</strong></span>
          <span class="evil-twin-pill">Rogue BSSID: <code>${esc(primaryRogue.bssid)}</code></span>
          <span class="evil-twin-pill">Security: <b>Open (No Encryption)</b></span>
          <span class="evil-twin-pill">Signal: <b>${esc(primaryRogue.signal || '96% (-38 dBm)')}</b></span>
          <span class="evil-twin-pill">Threat Type: <b>Evil Twin Clone</b></span>
        `;
      }
    } else {
      banner.style.display = "none";
    }
  }

  // Update simulation toggle button state
  const simBtn = $("wifi-simulate-evil-twin");
  if (simBtn) {
    if (state.simulatedRogueApActive) {
      simBtn.textContent = "🚨 Remove Evil Twin Sim";
      simBtn.style.background = "rgba(239,68,68,0.3)";
      simBtn.style.borderColor = "#ef4444";
    } else {
      simBtn.textContent = "🚨 Simulate Evil Twin AP";
      simBtn.style.background = "rgba(239,68,68,0.14)";
      simBtn.style.borderColor = "rgba(239,68,68,0.35)";
    }
  }

  // 1. Hero Card
  if (iface && iface.state && iface.state.toLowerCase() === "connected"){
    $("wifi-ssid-title").textContent = iface.ssid || "Connected (Hidden SSID)";
    $("wifi-bssid").textContent = iface.bssid || "—";
    $("wifi-band").textContent = iface.band || "—";
    $("wifi-channel").textContent = iface.channel ? `${iface.channel}` : "—";
    $("wifi-radio").textContent = iface.radio_type || "—";

    const badge = $("wifi-state-badge");
    badge.className = "wifi-status-badge";
    const ifaceDesc = iface.description ? ` (${iface.description})` : "";
    $("wifi-state-text").textContent = `CONNECTED · ${iface.name || "Wi-Fi"}${ifaceDesc}`;
  } else {
    $("wifi-ssid-title").textContent = "No Wi-Fi Connected";
    $("wifi-bssid").textContent = "—";
    $("wifi-band").textContent = "—";
    $("wifi-channel").textContent = "—";
    $("wifi-radio").textContent = "—";

    const badge = $("wifi-state-badge");
    badge.className = "wifi-status-badge disconnected";
    $("wifi-state-text").textContent = "DISCONNECTED";
  }

  // 2. Score & Dial
  const score = data.score ?? 0;
  const circ = 2 * Math.PI * 49;
  const colour = score >= 80 ? "var(--ok)" : score >= 60 ? "var(--med)" : "var(--crit)";
  const arc = $("wifi-arc");
  if (arc){
    arc.setAttribute("stroke", colour);
    arc.setAttribute("stroke-dasharray", `${(score / 100 * circ).toFixed(1)} ${circ.toFixed(1)}`);
  }
  $("wifi-dialnum").textContent = score;
  $("wifi-grade").textContent = `Grade ${data.grade || "—"}`;
  $("wifi-gradesub").textContent = data.summary || "Wireless posture assessed.";

  const counts = data.counts || {};
  $("wifi-sevrow").innerHTML = ["critical", "high", "medium", "low", "info"]
    .filter(k => counts[k])
    .map(k => `<span class="sev-chip ${k}">${counts[k]} ${esc(k)}</span>`)
    .join("") || `<span class="sev-chip info">clean</span>`;

  // 3. Stats row
  const sig = iface ? `${iface.signal_percent}%` : "—";
  const rssi = iface ? `${iface.rssi_dbm} dBm` : "—";
  const auth = iface ? `${iface.authentication}` : "—";
  const cipher = iface ? `${iface.cipher}` : "—";
  state.currentWifiNetworks = networks;
  const uniqueSsids = new Set(networks.map(n => n.ssid || "(Hidden SSID)")).size;
  const totalAps = networks.length;

  $("wifi-stats").innerHTML = [
    [sig, "signal level"],
    [rssi, "RSSI strength"],
    [auth, "auth protocol"],
    [cipher, "cipher stream"],
    [uniqueSsids, `networks (${totalAps} APs)`],
    [data.quantum_risk ? "At Risk" : "Safe", "PQC posture"]
  ].map(([k, l]) =>
    `<div class="stat"><div class="k">${esc(k)}</div>`
    + `<div class="l">${esc(l)}</div></div>`).join("");

  const sub = $("wifi-networks-subtitle");
  if (sub) {
    sub.textContent = `${uniqueSsids} unique networks (${totalAps} total access points discovered across 2.4 GHz, 5 GHz, and 6 GHz spectrum).`;
  }

  state.wifiAssessment = data;
  state.telemetryTicks++;

  // 4. Health List
  $("wifi-auth-cipher-val").textContent = iface ? `${iface.authentication} (${iface.cipher})` : "—";
  $("wifi-signal-pct").textContent = iface ? `${iface.signal_percent}% (${iface.rssi_dbm} dBm)` : "—";
  if ($("wifi-signal-bar") && iface){
    $("wifi-signal-bar").style.width = `${Math.max(5, iface.signal_percent)}%`;
    $("wifi-signal-bar").style.background = iface.signal_percent >= 60 ? "var(--ok)" : iface.signal_percent >= 30 ? "var(--med)" : "var(--crit)";
  }
  $("wifi-rates-val").textContent = (iface && iface.rx_rate_mbps)
    ? `RX ${iface.rx_rate_mbps} Mbps / TX ${iface.tx_rate_mbps} Mbps` : "Auto-negotiated";

  const dns = (iface && iface.dns_servers && iface.dns_servers.length)
    ? iface.dns_servers.join(", ") : "Default Gateway DNS";
  $("wifi-dns-val").textContent = dns;
  $("wifi-gateway-val").textContent = (iface && iface.gateway_ip) ? iface.gateway_ip : "—";

  const elapsedMins = Math.floor((Date.now() - state.sessionStartTime) / 60000);
  const elapsedSecs = Math.floor(((Date.now() - state.sessionStartTime) % 60000) / 1000);
  const uptimeEl = $("wifi-uptime-val");
  if (uptimeEl) {
    const timeStr = elapsedMins > 0 ? `${elapsedMins}m ${elapsedSecs}s` : `${elapsedSecs}s`;
    const vpnOk = data.vpn && data.vpn.connected;
    uptimeEl.innerHTML = `<span style="color:var(--ok)">● Active ${timeStr}</span> &middot; <span style="color:var(--dim)">${state.telemetryTicks} telemetry cycles</span> &middot; <span style="color:${vpnOk ? 'var(--ok)' : 'var(--med)'}">${vpnOk ? 'Encrypted Overlay Active' : 'Direct ISP Link'}</span>`;
  }

  // 5. VPN Overlay Card
  renderVpnOverlay(data.vpn);

  // 6. Findings List (Combine Wi-Fi and VPN findings)
  const allFindings = [...(data.findings || []), ...((data.vpn && data.vpn.findings) || [])];
  renderWifiFindings(allFindings);

  // 7. In-range Networks Table
  renderWifiNetworksTable(networks);
}

function renderVpnOverlay(vpn){
  const badge = $("vpn-badge");
  const indicator = $("vpn-status-indicator");
  const statusText = $("vpn-status-text");
  const protoVal = $("vpn-proto-val");
  const adapterVal = $("vpn-adapter-val");
  const egressVal = $("vpn-egress-val");
  const locationVal = $("vpn-location-val");
  const routeVal = $("vpn-route-val");
  const routeSub = $("vpn-route-sub");
  const leakVal = $("vpn-leak-val");
  const leakSub = $("vpn-leak-sub");

  if (!badge) return;

  if (vpn && vpn.connected){
    badge.textContent = vpn.vpn_type;
    badge.className = "domain-tag inf";

    indicator.className = "vpn-status-badge vpn-status-active";
    statusText.textContent = `TUNNEL ACTIVE · ${vpn.vpn_type}`;

    protoVal.textContent = vpn.vpn_type;
    adapterVal.textContent = vpn.adapter_name || "Virtual Tunnel Adapter";

    routeVal.textContent = vpn.is_default_route ? "VPN Tunnel" : "Split-Tunnel";
    routeSub.textContent = vpn.is_default_route ? "Default route (0.0.0.0/0) routed via tunnel" : "Default route remains on local Wi-Fi";

    if (vpn.dns_leak_detected){
      leakVal.innerHTML = `<span style="color:var(--crit);font-weight:700">🚨 DNS LEAK</span>`;
      leakSub.textContent = `Leaking to ${vpn.dns_leak_details}`;
    } else if (vpn.dns_servers && vpn.dns_servers.length){
      leakVal.innerHTML = `<span style="color:var(--ok);font-weight:700">✅ Protected</span>`;
      leakSub.textContent = `Tunnel DNS: ${vpn.dns_servers.join(", ")}`;
    } else {
      leakVal.innerHTML = `<span style="color:var(--ok);font-weight:700">✅ Tunnel Isolated</span>`;
      leakSub.textContent = "No leak detected";
    }
  } else {
    badge.textContent = "Direct ISP";
    badge.className = "domain-tag obs";

    indicator.className = "vpn-status-badge vpn-status-inactive";
    statusText.textContent = "NO VPN TUNNEL (DIRECT ISP)";

    protoVal.textContent = "Direct (None)";
    adapterVal.textContent = "Physical Wi-Fi link";

    routeVal.textContent = "Wi-Fi Gateway";
    routeSub.textContent = "0.0.0.0/0 on physical NIC";

    leakVal.textContent = "N/A (No Tunnel)";
    leakSub.textContent = "Direct to ISP DNS";
  }

  if (vpn && vpn.egress_ip){
    egressVal.textContent = `${vpn.egress_ip}`;
    const loc = [vpn.egress_city, vpn.egress_country].filter(Boolean).join(", ");
    locationVal.textContent = `${vpn.egress_isp || "Public ISP"}${loc ? ` (${loc})` : ""}`;
  } else {
    egressVal.textContent = "Direct Egress";
    locationVal.textContent = "Local Network Interface";
  }
}

function renderWifiFindings(findings){
  const el = $("wifi-findings");
  if (!findings.length){
    el.innerHTML = `<div class="empty">No security findings. Current wireless posture meets standard baselines.</div>`;
    return;
  }
  $("wifi-findsub").textContent = `${findings.length} findings identified on the local wireless segment.`;

  el.innerHTML = findings.map((f, i) => `
    <div class="finding" data-i="${i}">
      <div class="fhead" role="button" tabindex="0" aria-expanded="false">
        <span class="sev-mark ${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="fmain">
          <span class="ftitle">${esc(f.title)}</span>
          <div class="fsub">${esc(f.rule_id)} &middot; ${esc(f.subject)}</div>
        </span>
        <span class="chev">+</span>
      </div>
      <div class="fbody">
        <p>${esc(f.detail)}</p>
        ${f.reference ? `<div class="ref">${esc(f.reference)}</div>` : ``}
        <div class="fix"><b>Fix:</b> ${esc(f.remediation)}</div>
      </div>
    </div>`).join("");

  el.querySelectorAll(".fhead").forEach(h => {
    const toggle = () => {
      const open = h.parentElement.classList.toggle("open");
      h.setAttribute("aria-expanded", open ? "true" : "false");
      h.querySelector(".chev").textContent = open ? "\u2212" : "+";
    };
    h.addEventListener("click", toggle);
    h.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " "){ e.preventDefault(); toggle(); }
    });
  });
}

function renderWifiNetworksTable(networks){
  networks = networks || state.currentWifiNetworks || [];
  const tbody = $("wifi-networks-tbody");
  if (!tbody) return;

  const iface = state.wifiAssessment ? state.wifiAssessment.interface : null;
  const isIfaceConnected = Boolean(iface && iface.state && iface.state.toLowerCase() === "connected");
  const connBssid = (isIfaceConnected && iface.bssid) ? iface.bssid.toLowerCase().trim() : "";
  const connSsid = (isIfaceConnected && iface.ssid) ? iface.ssid.toLowerCase().trim() : "";

  // Normalize networks list and ensure the live connected AP is strictly identified
  let hasConnInList = false;
  let normalizedNetworks = (networks || []).map(n => {
    const netBssid = (n.bssid || "").toLowerCase().trim();
    const netSsid = (n.ssid || "").toLowerCase().trim();
    const isConn = Boolean(
      (connBssid && netBssid && netBssid === connBssid) ||
      (!connBssid && connSsid && netSsid === connSsid) ||
      n.connected
    );
    if (isConn) hasConnInList = true;
    return Object.assign({}, n, { connected: isConn });
  });

  // If the active connected AP is not present in the scan results, inject it so it is ALWAYS visible and at the top!
  if (isIfaceConnected && !hasConnInList && (connBssid || connSsid)) {
    normalizedNetworks.unshift({
      ssid: iface.ssid || "(Connected Network)",
      bssid: iface.bssid || "—",
      band: iface.band || "5 GHz",
      channel: iface.channel || 0,
      radio_type: iface.radio_type || "802.11",
      authentication: iface.authentication || "WPA2-Personal",
      encryption: iface.cipher || "CCMP",
      signal_percent: iface.signal_percent || 80,
      rssi_dbm: iface.rssi_dbm || -60,
      security_grade: (state.wifiAssessment && state.wifiAssessment.grade) || "B",
      connected: true,
      notes: "Active Interface"
    });
  }

  networks = normalizedNetworks;
  state.currentWifiNetworks = networks;

  if (!networks.length){
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No other networks detected in range.</td></tr>`;
    return;
  }

  const theadRow = $("wifi-networks-thead-row");

  if (state.wifiGroupMode) {
    if (theadRow) {
      theadRow.innerHTML = `
        <th>SSID / Network</th>
        <th>Access Points (BSSID)</th>
        <th>Security / Auth</th>
        <th>Band &amp; Channels</th>
        <th>Signal</th>
        <th>Security Grade</th>
      `;
    }

    // Group by SSID
    const groups = new Map();
    for (const n of networks) {
      const key = n.ssid || "(Hidden SSID)";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(n);
    }

    // Sort groups: connected network first, then by best signal descending
    const sortedGroups = Array.from(groups.entries()).sort((a, b) => {
      const aConn = a[1].some(n => n.connected);
      const bConn = b[1].some(n => n.connected);
      if (aConn !== bConn) return aConn ? -1 : 1;
      const aSig = Math.max(...a[1].map(n => n.signal_percent));
      const bSig = Math.max(...b[1].map(n => n.signal_percent));
      return bSig - aSig;
    });

    let html = "";
    sortedGroups.forEach(([ssid, items], gIdx) => {
      const isConnected = items.some(n => n.connected);
      const hasRogue = items.some(n => n.is_rogue);
      const connectedNet = items.find(n => n.connected) || null;
      const bestSignal = Math.max(...items.map(n => n.signal_percent));
      const bestNet = items.find(n => n.signal_percent === bestSignal) || items[0];
      const apCount = items.length;

      const bands = Array.from(new Set(items.map(n => n.band).filter(Boolean)));
      const channels = Array.from(new Set(items.map(n => n.channel).filter(c => c > 0))).sort((a,b) => a-b);
      const chanSummary = channels.length > 0 ? `Ch ${channels.join(", ")}` : "—";
      const bandSummary = bands.join(" & ") || "2.4 GHz";

      let cls = isConnected ? "active-net" : "";
      if (hasRogue) cls += (cls ? " " : "") + "rogue-ap-row";
      const activeLabel = isConnected ? ` <span class="sev-chip info" style="font-size:0.7rem;padding:1px 5px">CONNECTED</span>` : "";
      const rogueLabel = hasRogue ? ` <span class="rogue-badge">🚨 ROGUE CLONE AP</span>` : "";
      const meshLabel = apCount > 1 
        ? `<span class="mesh-count-badge">${apCount} APs (Mesh)</span>`
        : "";
      const badgeCls = hasRogue ? "F" : (bestNet.security_grade ? bestNet.security_grade.replace("+", "") : "B");

      let apCell = "";
      if (isConnected && connectedNet) {
        apCell = `<div class="mesh-cell-summary"><code>${esc(connectedNet.bssid)}</code> <span class="active-ap-pill">● Active AP</span></div>`;
        if (apCount > 1) {
          apCell += `<button type="button" class="btn-ap-subtoggle" data-group="${gIdx}" aria-expanded="false"><span class="subtoggle-icon">▼</span> View all ${apCount} mesh APs</button>`;
        }
      } else if (apCount > 1) {
        apCell = `<div class="mesh-cell-summary"><code>${esc(bestNet.bssid)}</code> <span class="best-signal-pill">(Best signal)</span></div>
                  <button type="button" class="btn-ap-subtoggle" data-group="${gIdx}" aria-expanded="false"><span class="subtoggle-icon">▼</span> View all ${apCount} mesh APs</button>`;
      } else {
        apCell = `<code>${esc(items[0].bssid)}</code>`;
      }

      html += `<tr class="${cls}">
        <td><b>${esc(ssid)}</b>${activeLabel}${rogueLabel}${meshLabel}</td>
        <td>${apCell}</td>
        <td>${esc(bestNet.authentication)} / ${esc(bestNet.encryption)}</td>
        <td>${esc(bandSummary)} &middot; ${esc(chanSummary)}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <span>${bestSignal}%</span>
            <div class="signal-bar-track" style="width:50px;height:5px">
              <div class="signal-bar-fill" style="width:${bestSignal}%;background:${bestSignal>60?'var(--ok)':'var(--med)'}"></div>
            </div>
          </div>
        </td>
        <td><span class="grade-badge ${badgeCls}">Grade ${esc(hasRogue ? 'F' : bestNet.security_grade)}</span></td>
      </tr>`;

      // If multi-AP, render collapsible detail subrow
      if (apCount > 1) {
        const sortedItems = [...items].sort((a,b) => (b.connected ? 1 : 0) - (a.connected ? 1 : 0) || (b.is_rogue ? 1 : 0) - (a.is_rogue ? 1 : 0) || b.signal_percent - a.signal_percent);
        html += `<tr id="wifi-subgroup-${gIdx}" class="mesh-subgroup-row" style="display:none">
          <td colspan="6" class="mesh-subgroup-cell">
            <div class="mesh-subgroup-header">
              <div class="mesh-subgroup-title">
                <span class="mesh-icon">📡</span>
                <span>Physical Access Points for ESSID <strong>"${esc(ssid)}"</strong></span>
                <span class="mesh-count-tag">${apCount} APs in Roaming Cluster</span>
              </div>
              <div class="mesh-subgroup-meta">802.11k/v Fast BSS Transition</div>
            </div>
            <div class="mesh-ap-grid">
              ${sortedItems.map(ap => {
                const isApConn = ap.connected;
                const isRogue = ap.is_rogue;
                let cardCls = isApConn ? "mesh-ap-card is-connected" : "mesh-ap-card";
                if (isRogue) cardCls += " rogue-ap-row";
                const sigColor = ap.signal_percent >= 70 ? "var(--ok)" : ap.signal_percent >= 45 ? "var(--med)" : "var(--crit)";
                const badgeText = isApConn 
                  ? '<span class="mesh-ap-badge connected">● CONNECTED AP</span>' 
                  : isRogue 
                    ? '<span class="mesh-ap-badge" style="background:#dc2626;color:#fff;font-weight:700">🚨 ROGUE CLONE AP</span>'
                    : '<span class="mesh-ap-badge neighbor">Neighbor AP</span>';
                const warningNote = isRogue
                  ? `<div style="color:#b91c1c;font-size:0.72rem;font-weight:600;margin-top:4px;grid-column:1/-1">⚠ Downgraded Security: ${esc(ap.authentication)} / ${esc(ap.encryption)} &middot; Potential MitM Honeypot</div>`
                  : "";
                return `<div class="${cardCls}">
                  <div class="mesh-ap-top">
                    <code class="mesh-bssid">${esc(ap.bssid)}</code>
                    ${badgeText}
                  </div>
                  <div class="mesh-ap-bottom">
                    <div class="mesh-ap-spec">
                      <span>${esc(ap.band)} &middot; Ch ${esc(ap.channel)}</span>
                    </div>
                    <div class="mesh-ap-signal" style="color:${sigColor}">
                      ${ap.signal_percent}% (${ap.rssi_dbm} dBm)
                    </div>
                    ${warningNote}
                  </div>
                </div>`;
              }).join("")}
            </div>
          </td>
        </tr>`;
      }
    });

    tbody.innerHTML = html;

    // Attach expand/collapse toggles
    tbody.querySelectorAll(".btn-ap-subtoggle").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const gIdx = btn.getAttribute("data-group");
        const subRow = $(`wifi-subgroup-${gIdx}`);
        if (!subRow) return;
        const isHidden = subRow.style.display === "none";
        subRow.style.display = isHidden ? "table-row" : "none";
        btn.setAttribute("aria-expanded", isHidden ? "true" : "false");
        const count = subRow.querySelectorAll(".mesh-ap-card").length;
        if (isHidden) {
          btn.innerHTML = `<span class="subtoggle-icon">▲</span> Collapse AP list`;
          btn.classList.add("expanded");
        } else {
          btn.innerHTML = `<span class="subtoggle-icon">▼</span> View all ${count} mesh APs`;
          btn.classList.remove("expanded");
        }
      });
    });

  } else {
    // Flat list of all BSSIDs
    if (theadRow) {
      theadRow.innerHTML = `
        <th>SSID</th>
        <th>BSSID (MAC)</th>
        <th>Security / Auth</th>
        <th>Band / Channel</th>
        <th>Signal</th>
        <th>Security Grade</th>
      `;
    }

    tbody.innerHTML = networks.map(n => {
      let cls = n.connected ? "active-net" : "";
      if (n.is_rogue) cls += (cls ? " " : "") + "rogue-ap-row";
      const activeLabel = n.connected ? ` <span class="sev-chip info" style="font-size:0.7rem;padding:1px 5px">CONNECTED</span>` : "";
      const rogueLabel = n.is_rogue ? ` <span class="rogue-badge">🚨 ROGUE CLONE AP</span>` : "";
      const badgeCls = n.is_rogue ? "F" : (n.security_grade ? n.security_grade.replace("+", "") : "B");
      return `<tr class="${cls}">
        <td><b>${esc(n.ssid)}</b>${activeLabel}${rogueLabel}</td>
        <td><code>${esc(n.bssid)}</code></td>
        <td>${esc(n.authentication)} / ${esc(n.encryption)}</td>
        <td>${esc(n.band)} &middot; Ch ${esc(n.channel)}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <span>${n.signal_percent}%</span>
            <div class="signal-bar-track" style="width:50px;height:5px">
              <div class="signal-bar-fill" style="width:${n.signal_percent}%;background:${n.signal_percent>60?'var(--ok)':'var(--med)'}"></div>
            </div>
          </div>
        </td>
        <td><span class="grade-badge ${badgeCls}">Grade ${esc(n.is_rogue ? 'F' : (n.security_grade || 'B'))}</span></td>
      </tr>`;
    }).join("");
  }
}

/* --------------------------------------------------- export audit dossier */

function exportSecurityAuditReport(){
  const wifiData = state.wifiAssessment || {};
  const iface = wifiData.interface || {};
  const vpn = wifiData.vpn || {};
  const ipsecData = state.assessment || {};
  const timestamp = new Date().toISOString();
  const dateFormatted = new Date().toLocaleString();

  const report = {
    report_title: "CipherGuard Executive Security Audit Dossier",
    standard: "SIH26160 / NTRO & NIST SP 800-77 Rev 1 / RFC 8247",
    timestamp: timestamp,
    date_formatted: dateFormatted,
    wifi_posture: {
      ssid: iface.ssid || "Unassociated",
      bssid: iface.bssid || "N/A",
      score: wifiData.score ?? 0,
      grade: wifiData.grade ?? "—",
      authentication: iface.authentication || "Unknown",
      cipher: iface.cipher || "None",
      channel: iface.channel || 0,
      band: iface.band || "N/A",
      signal: `${iface.signal_percent || 0}% (${iface.rssi_dbm || -100} dBm)`,
      dns_servers: iface.dns_servers || [],
      gateway: iface.gateway_ip || "N/A"
    },
    vpn_overlay: {
      connected: vpn.connected || false,
      protocol: vpn.vpn_type || "Direct ISP (No Tunnel)",
      adapter: vpn.adapter_name || "N/A",
      virtual_ip: vpn.virtual_ip || "N/A",
      egress_ip: vpn.egress_ip || "N/A",
      egress_isp: vpn.egress_isp || "N/A",
      egress_location: `${vpn.egress_city || ''}, ${vpn.egress_country || ''}`.trim() || "N/A",
      dns_leak_detected: vpn.dns_leak_detected || false
    },
    findings_count: (wifiData.findings || []).length + ((vpn.findings || []).length),
    findings: [...(wifiData.findings || []), ...(vpn.findings || [])],
    ipsec_assessment: ipsecData.score ? {
      capture: $("capture") ? $("capture").value : "N/A",
      score: ipsecData.score,
      grade: ipsecData.grade,
      sessions: (ipsecData.sessions || []).length,
      flows: (ipsecData.flows || []).length
    } : null,
    remediation_plans: (state.remediationPlans || []).map(p => ({
      platform: p.platform_name,
      status: p.status,
      syntax_valid: p.syntax_valid,
      forward_config: p.forward_config,
      rollback_config: p.rollback_config
    }))
  };

  const printWindow = window.open("", "_blank", "width=920,height=850");
  if (!printWindow) {
    alert("Popup blocked. Please allow popups to view the Executive Security Audit Dossier.");
    return;
  }

  const findingsHtml = report.findings.map(f => `
    <div style="margin-bottom:12px;padding:12px;border-left:4px solid ${f.severity==='critical'?'#ef4444':f.severity==='high'?'#f97316':f.severity==='medium'?'#eab308':'#38bdf8'};background:#f8fafc;border-radius:0 6px 6px 0;border:1px solid #e2e8f0;border-left-width:4px;">
      <div style="display:flex;justify-content:space-between;font-weight:bold;margin-bottom:4px">
        <span style="color:#0f172a">[${esc(f.rule_id)}] ${esc(f.title)}</span>
        <span style="text-transform:uppercase;font-size:0.75rem;padding:2px 8px;border-radius:3px;background:#e2e8f0;font-weight:700;">${esc(f.severity)}</span>
      </div>
      <div style="font-size:0.85rem;color:#475569;margin-bottom:4px"><strong>Subject:</strong> ${esc(f.subject)}</div>
      <div style="font-size:0.85rem;margin-bottom:6px;color:#334155;">${esc(f.detail)}</div>
      <div style="font-size:0.85rem;color:#1e293b;background:#f1f5f9;padding:6px 10px;border-radius:4px;border:1px solid #cbd5e1"><strong>Remediation:</strong> ${esc(f.remediation)}</div>
    </div>
  `).join("") || "<p>No vulnerabilities detected.</p>";

  const jsonBlob = encodeURIComponent(JSON.stringify(report, null, 2));

  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>CipherGuard Security Audit Dossier - ${esc(report.wifi_posture.ssid)}</title>
      <style>
        body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; line-height: 1.5; color: #0f172a; padding: 28px; max-width: 860px; margin: 0 auto; background: #fff; }
        .no-print { display: flex; gap: 10px; margin-bottom: 24px; padding: 12px; background: #f0f9ff; border-radius: 6px; border: 1px solid #bae6fd; }
        .btn { padding: 8px 16px; background: #0284c7; color: #fff; border: none; border-radius: 4px; font-weight: 600; cursor: pointer; text-decoration: none; font-size: 0.85rem; }
        .btn-secondary { background: #475569; }
        .hdr { border-bottom: 2px solid #0f172a; padding-bottom: 14px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
        .card { border: 1px solid #cbd5e1; border-radius: 6px; padding: 14px; background: #f8fafc; font-size: 0.88rem; }
        .card div { margin-bottom: 5px; }
        h2 { font-size: 1.05rem; margin-top: 0; margin-bottom: 12px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; color: #0f172a; }
        .badge { font-weight: bold; padding: 2px 8px; border-radius: 4px; font-size: 0.82rem; }
        .grade-a { background: #dcfce7; color: #15803d; }
        .grade-b { background: #fef9c3; color: #854d0e; }
        .grade-c { background: #fee2e2; color: #b91c1c; }
        code { font-family: Consolas, monospace; background: #e2e8f0; padding: 2px 5px; border-radius: 3px; font-size: 0.82rem; }
        @media print { .no-print { display: none; } body { padding: 0; } }
      </style>
    </head>
    <body>
      <div class="no-print">
        <button class="btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
        <a class="btn btn-secondary" href="data:application/json;charset=utf-8,${jsonBlob}" download="cipherguard-audit-${Date.now()}.json">💾 Download JSON Telemetry</a>
      </div>
      <div class="hdr">
        <div style="display:flex;justify-content:space-between;align-items:flex-start">
          <div>
            <h1 style="margin:0;font-size:1.5rem;color:#0f172a">CIPHERGUARD EXECUTIVE SECURITY AUDIT DOSSIER</h1>
            <div style="font-size:0.85rem;color:#64748b;margin-top:2px">Compliance Framework: SIH26160 / NTRO &middot; NIST SP 800-77 Rev 1 &middot; RFC 8247</div>
          </div>
          <div style="text-align:right;font-size:0.8rem;color:#64748b">
            <div>Date: <strong>${esc(report.date_formatted)}</strong></div>
            <div>Classification: <strong>OFFICIAL / RESTRICTED AUDIT</strong></div>
          </div>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <h2>1. Physical Wi-Fi Posture (802.11 RF)</h2>
          <div><strong>Associated SSID:</strong> ${esc(report.wifi_posture.ssid)}</div>
          <div><strong>Hardware BSSID:</strong> <code>${esc(report.wifi_posture.bssid)}</code></div>
          <div><strong>Security Posture Grade:</strong> <span class="badge ${report.wifi_posture.grade.includes('A')?'grade-a':report.wifi_posture.grade.includes('B')?'grade-b':'grade-c'}">Grade ${esc(report.wifi_posture.grade)} (${report.wifi_posture.score}/100)</span></div>
          <div><strong>Auth &amp; Cipher:</strong> ${esc(report.wifi_posture.authentication)} / ${esc(report.wifi_posture.cipher)}</div>
          <div><strong>RF Band &amp; Channel:</strong> ${esc(report.wifi_posture.band)} &middot; Channel ${esc(report.wifi_posture.channel)}</div>
          <div><strong>Signal Level:</strong> ${esc(report.wifi_posture.signal)}</div>
          <div><strong>Configured DNS:</strong> ${esc((report.wifi_posture.dns_servers || []).join(', ') || 'Default Gateway')}</div>
        </div>

        <div class="card">
          <h2>2. Transport Layer Overlay &amp; VPN</h2>
          <div><strong>Tunnel State:</strong> <span class="badge ${report.vpn_overlay.connected?'grade-a':'grade-c'}">${report.vpn_overlay.connected?'● ENCRYPTED OVERLAY ACTIVE':'○ DIRECT ISP LINK'}</span></div>
          <div><strong>VPN Protocol:</strong> ${esc(report.vpn_overlay.protocol)}</div>
          <div><strong>Adapter:</strong> ${esc(report.vpn_overlay.adapter)}</div>
          <div><strong>Virtual Tunnel IP:</strong> <code>${esc(report.vpn_overlay.virtual_ip)}</code></div>
          <div><strong>Public Egress Node:</strong> ${esc(report.vpn_overlay.egress_ip)}</div>
          <div><strong>Egress Geolocation:</strong> ${esc(report.vpn_overlay.egress_location)} (${esc(report.vpn_overlay.egress_isp)})</div>
          <div><strong>DNS Leak Status:</strong> <span style="color:${report.vpn_overlay.dns_leak_detected?'#b91c1c':'#15803d'};font-weight:bold">${report.vpn_overlay.dns_leak_detected?'LEAK DETECTED':'NO LEAK (SECURE)'}</span></div>
        </div>
      </div>

      <h2>3. Security Findings &amp; Cryptographic Audit (${report.findings.length} Items)</h2>
      ${findingsHtml}

      <div style="margin-top:30px;padding-top:12px;border-top:1px solid #cbd5e1;font-size:0.75rem;color:#64748b;display:flex;justify-content:space-between">
        <span>CipherGuard Automated Passive Security Engine v2.0</span>
        <span>Deterministic Zero Live Mutation &middot; NIST SP 800-77 Validated</span>
      </div>
    </body>
    </html>
  `);
  printWindow.document.close();
}

/* ----------------------------------------------------------------- init */

async function init(){
  try { state.token = sessionStorage.getItem("cipherguard.token"); } catch (e) {}

  // Tab listeners
  $("tab-wifi").addEventListener("click", () => switchTab("wifi"));
  $("tab-ipsec").addEventListener("click", () => switchTab("ipsec"));

  // Wi-Fi action buttons
  const refreshBtn = $("wifi-refresh-btn");
  if (refreshBtn) refreshBtn.addEventListener("click", () => loadWifiAssessment(true));
  const scanBtn = $("wifi-scan-now");
  if (scanBtn) scanBtn.addEventListener("click", () => loadWifiAssessment(true));

  // Export Dossier action buttons
  const exportBtn1 = $("wifi-export-report");
  if (exportBtn1) exportBtn1.addEventListener("click", exportSecurityAuditReport);
  const exportBtn2 = $("wifi-header-export-btn");
  if (exportBtn2) exportBtn2.addEventListener("click", exportSecurityAuditReport);
  const exportBtn3 = $("ipsec-export-report");
  if (exportBtn3) exportBtn3.addEventListener("click", exportSecurityAuditReport);

  // Wi-Fi view mode toggles (Group by SSID vs Show All APs)
  const btnGroup = $("btn-wifi-group");
  const btnAll = $("btn-wifi-all");
  if (btnGroup && btnAll) {
    btnGroup.addEventListener("click", () => {
      state.wifiGroupMode = true;
      btnGroup.classList.add("active");
      btnAll.classList.remove("active");
      renderWifiNetworksTable();
    });
    btnAll.addEventListener("click", () => {
      state.wifiGroupMode = false;
      btnAll.classList.add("active");
      btnGroup.classList.remove("active");
      renderWifiNetworksTable();
    });
  }

  // IPsec action buttons & mode toggles
  $("run").addEventListener("click", runAnalysis);
  const btnSingle = $("btn-ipsec-single");
  if (btnSingle) btnSingle.addEventListener("click", () => switchIpsecMode("single"));
  const btnDiff = $("btn-ipsec-diff");
  if (btnDiff) btnDiff.addEventListener("click", () => switchIpsecMode("diff"));
  const btnRunDiff = $("run-diff");
  if (btnRunDiff) btnRunDiff.addEventListener("click", runDiffAnalysis);
  const selDiffA = $("diff-capture-a");
  if (selDiffA) selDiffA.addEventListener("change", runDiffAnalysis);
  const selDiffB = $("diff-capture-b");
  if (selDiffB) selDiffB.addEventListener("change", runDiffAnalysis);

  // Wi-Fi Evil Twin & Rogue AP controls
  const btnInspectRogue = $("btn-inspect-rogue-ap");
  if (btnInspectRogue) {
    btnInspectRogue.addEventListener("click", () => {
      const table = $("wifi-networks-table");
      if (table) {
        table.scrollIntoView({ behavior: "smooth", block: "center" });
        setTimeout(() => {
          const rogueRow = table.querySelector(".rogue-ap-row");
          if (rogueRow) {
            const subtoggle = rogueRow.querySelector(".btn-ap-subtoggle");
            if (subtoggle && !subtoggle.classList.contains("expanded")) {
              subtoggle.click();
            }
            rogueRow.classList.remove("rogue-highlight-flash");
            void rogueRow.offsetWidth;
            rogueRow.classList.add("rogue-highlight-flash");
          }
        }, 350);
      }
    });
  }
  const btnDismissRogue = $("btn-dismiss-rogue-banner");
  if (btnDismissRogue) {
    btnDismissRogue.addEventListener("click", () => {
      const b = $("wifi-evil-twin-banner");
      if (b) b.style.display = "none";
    });
  }
  const simEvilTwinBtn = $("wifi-simulate-evil-twin");
  if (simEvilTwinBtn) {
    simEvilTwinBtn.addEventListener("click", () => {
      state.simulatedRogueApActive = !state.simulatedRogueApActive;
      if (state.wifiAssessment) {
        renderWifiDashboard(state.wifiAssessment);
      }
    });
  }

  renderRibbon(null);

  // Remediation Playbook toolbar controls
  const fwdBtn = $("btn-playbook-forward");
  if (fwdBtn) fwdBtn.addEventListener("click", () => {
    state.playbookMode = "forward";
    renderPlaybookUI();
  });
  const rlbBtn = $("btn-playbook-rollback");
  if (rlbBtn) rlbBtn.addEventListener("click", () => {
    state.playbookMode = "rollback";
    renderPlaybookUI();
  });

  const copyBtn = $("btn-playbook-copy");
  if (copyBtn) copyBtn.addEventListener("click", () => {
    const currentPlan = (state.remediationPlans || []).find(p => p.platform === state.platform);
    if (!currentPlan) return;
    const content = state.playbookMode === "rollback" ? currentPlan.rollback_config : currentPlan.forward_config;
    navigator.clipboard.writeText(content).then(() => {
      const old = copyBtn.textContent;
      copyBtn.textContent = "✔ Copied!";
      setTimeout(() => copyBtn.textContent = old, 1500);
    }).catch(() => {
      alert("Copied to clipboard.");
    });
  });

  const approveBtn = $("btn-playbook-approve");
  if (approveBtn) approveBtn.addEventListener("click", async () => {
    const currentPlan = (state.remediationPlans || []).find(p => p.platform === state.platform);
    if (!currentPlan) {
      alert("No active plan to approve.");
      return;
    }
    const admin = prompt("Enter Administrator Name or Sign-off Badge ID:", "SecOps-Lead");
    if (!admin) return;
    try {
      const res = await api(`/api/remediation/${currentPlan.plan_id}/approve`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          actor: admin,
          comment: "Approved via CipherGuard Management Console"
        })
      });
      if (res.ok) {
        currentPlan.status = "APPROVED";
        currentPlan.approver = admin;
        renderPlaybookUI();
      }
    } catch(err) {
      alert("Approval failed: " + err.message);
    }
  });

  const dryRunBtn = $("btn-playbook-dryrun");
  if (dryRunBtn) dryRunBtn.addEventListener("click", async () => {
    const currentPlan = (state.remediationPlans || []).find(p => p.platform === state.platform);
    if (!currentPlan) {
      alert("No active plan to validate.");
      return;
    }
    const simBox = $("playbook-sim-box");
    const simDetail = $("sim-detail");
    if (simBox) simBox.style.display = "block";
    if (simDetail) simDetail.textContent = "Executing pre-staging dry-run simulation...";
    try {
      const res = await api(`/api/remediation/${currentPlan.plan_id}/apply`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ dry_run: true })
      });
      const data = await res.json();
      if (simDetail) {
        simDetail.innerHTML = `
          <div><strong>Result:</strong> ${data.success ? "<span style='color:#4ade80'>PASSED (Zero Syntax Violations)</span>" : "<span style='color:#f87171'>FAILED</span>"}</div>
          <div><strong>Mode:</strong> ${esc(data.mode)} | <strong>Commands Staged:</strong> ${data.lines_staged} lines</div>
          <div><strong>Rollback Verified:</strong> Safe reverse playbook compiled (${(currentPlan.rollback_config || '').split('\n').length} lines)</div>
          <div style="margin-top:6px; color:#94a3b8;"><strong>Execution Log:</strong></div>
          <div style="background:#020617; padding:8px; border-radius:4px; margin-top:4px;">
            ${(data.simulation_log || []).map(l => esc(l)).join("<br>")}
          </div>
        `;
      }
      if (data.success && currentPlan.status === "APPROVED") {
        currentPlan.status = "STAGED";
        renderPlaybookUI();
      }
    } catch(err) {
      if (simDetail) simDetail.textContent = "Dry-run failed: " + err.message;
    }
  });

  const simClose = $("sim-close");
  if (simClose) simClose.addEventListener("click", () => {
    const simBox = $("playbook-sim-box");
    if (simBox) simBox.style.display = "none";
  });

  // Detect host mode: GitHub Pages (static demo) vs live local API server
  const isStatic = await detectStaticMode();

  if (isStatic) {
    // In static mode (GitHub Pages), default to interactive IPsec capture analyzer
    switchTab("ipsec");
    await loadCaptures();
    if (!$("run").disabled) await runAnalysis();
    // Pre-load demo Wi-Fi assessment in background
    loadWifiAssessment(false);
  } else {
    // In live server mode, default to real-time Wi-Fi scanning
    switchTab("wifi");
    loadWifiAssessment(false);

    // Auto-poll live Wi-Fi and VPN telemetry every 15s ONLY in live backend mode
    setInterval(() => {
      const wifiView = $("view-wifi");
      if (wifiView && wifiView.classList.contains("active")) {
        loadWifiAssessment(false);
      }
    }, 15000);

    // Preload IPsec captures in background
    loadCaptures().then(() => { if (!$("run").disabled) runAnalysis(); });
  }
}

if (document.readyState === "loading"){
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
