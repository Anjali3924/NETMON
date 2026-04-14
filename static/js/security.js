// ===============================
// NETMON • Security Page Logic
// - Threshold column shows MAX packet length observed (per scan)
// - Top IP clickable on SAFE rows too (backend provides top talker)
// - Hits shown ONLY inside modal after click
// ===============================

function esc(v) {
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value ?? "");
}

/**  safer status setter: doesn't wipe other classes */
function setStatus(text, cls, note) {
  const statusEl = document.getElementById("secStatus");
  const noteEl = document.getElementById("secNote");

  if (statusEl) {
    statusEl.textContent = text;
    statusEl.classList.remove("ok", "warning", "danger", "bad", "warn");
    if (cls) statusEl.classList.add(cls);
  }
  if (noteEl) noteEl.textContent = note || "";
}

function statusClass(status, severity) {
  status = (status || "").toString().toUpperCase();
  severity = (severity || "").toString().toUpperCase();

  if (status === "SAFE") return "ok";
  if (severity === "HIGH") return "danger";
  return "warning";
}

function severityClass(severity) {
  severity = (severity || "").toString().toUpperCase();
  if (severity === "HIGH") return "danger";
  if (severity === "MEDIUM") return "warning";
  return "ok";
}

// ===============================
// IP MODAL LOGIC
// ===============================
const ipModal = () => document.getElementById("ipModal");
const ipBody  = () => document.getElementById("ipBody");
const ipTitle = () => document.getElementById("ipTitle");

const btnCopyIp = () => document.getElementById("btnCopyIp");

let CURRENT_IP = "";

function openIpModal() {
  const m = ipModal();
  if (!m) return;
  m.classList.remove("hidden");
  m.setAttribute("aria-hidden", "false");
}

function closeIpModal() {
  const m = ipModal();
  if (!m) return;
  m.classList.add("hidden");
  m.setAttribute("aria-hidden", "true");
}

function makeMapLink(lat, lon) {
  if (lat == null || lon == null) return "";
  const href = `https://www.google.com/maps?q=${encodeURIComponent(lat)},${encodeURIComponent(lon)}`;
  return `<a class="maps" href="${href}" target="_blank" rel="noopener">Open in Maps ↗</a>`;
}

function kvRow(k, v) {
  return `<div class="kv"><span>${esc(k)}</span><span>${esc(v ?? "-")}</span></div>`;
}

function sectionTitle(text) {
  return `<div class="sec-line">${esc(text)}</div>`;
}

function kvIf(label, val) {
  if (val === undefined || val === null) return "";
  const s = String(val).trim();
  if (!s || s === "-" || s.toLowerCase() === "none") return "";
  return kvRow(label, s);
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      return true;
    } catch {
      return false;
    }
  }
}

function computePrivateFlags(ip) {
  try {
    const isIPv6 = ip.includes(":");
    let range = "";
    let loopback = false;
    let linkLocal = false;

    if (!isIPv6) {
      if (ip.startsWith("10.")) range = "10.0.0.0/8";
      else if (ip.startsWith("192.168.")) range = "192.168.0.0/16";
      else if (ip.startsWith("172.")) {
        const sec = Number(ip.split(".")[1] || -1);
        if (sec >= 16 && sec <= 31) range = "172.16.0.0/12";
      }
      loopback = ip.startsWith("127.");
      linkLocal = ip.startsWith("169.254.");
    } else {
      loopback = (ip === "::1");
      linkLocal = ip.toLowerCase().startsWith("fe80:");
    }

    return {
      ip_version: isIPv6 ? "IPv6" : "IPv4",
      rfc1918_range: range || (isIPv6 ? "N/A" : "-"),
      is_loopback: loopback ? "Yes" : "No",
      is_link_local: linkLocal ? "Yes" : "No",
    };
  } catch {
    return {};
  }
}

async function fetchIpDetails(ip) {
  const endpoint =
    (window.NETMON_ENDPOINTS && window.NETMON_ENDPOINTS.ipDetails) ||
    "/api/ip-details";

  const res = await fetch(`${endpoint}?ip=${encodeURIComponent(ip)}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

//  hits shown ONLY inside modal (after click)
async function showIpDetails(ip, hits = null) {
  ip = (ip || "").trim();
  if (!ip) return;

  CURRENT_IP = ip;

  const t = ipTitle();
  const b = ipBody();

  if (t) t.textContent = `IP Details • ${ip}`;
  if (b) b.innerHTML = "Loading…";

  if (btnCopyIp()) btnCopyIp().textContent = "Copy IP";

  openIpModal();

  try {
    const d = await fetchIpDetails(ip);
    const type = (d.type || "-").toString().toLowerCase();
    let html = "";

    html += kvRow("Type", type.toUpperCase());

    if (hits !== null && hits !== undefined) {
      html += kvRow("IP Hits (in this scan)", hits);
    }

    if (type === "private") {
      html += `<div class="note">${esc(d.note || "Private/internal IP. Geo-location is not applicable.")}</div>`;

      const extra = computePrivateFlags(ip);
      html += sectionTitle("More details (local network)");
      html += kvIf("IP Version", extra.ip_version);
      html += kvIf("RFC1918 Range", extra.rfc1918_range);
      html += kvIf("Loopback", extra.is_loopback);
      html += kvIf("Link-local", extra.is_link_local);

      if (b) b.innerHTML = html;
      return;
    }

    html += kvRow("Country", d.country || "-");
    html += kvRow("Region", d.region || d.regionName || "-");
    html += kvRow("City", d.city || "-");
    html += kvRow("Timezone", d.timezone || "-");
    html += kvRow("ISP", d.isp || "-");
    html += kvIf("Org", d.org);

    html += sectionTitle("More details");
    html += kvIf("Latitude", d.latitude ?? d.lat);
    html += kvIf("Longitude", d.longitude ?? d.lon);
    html += makeMapLink(d.latitude ?? d.lat, d.longitude ?? d.lon);

    if (b) b.innerHTML = html;

  } catch (e) {
    if (b) b.innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}

//  no badge near IP (only link), but keep hits inside data attribute
function ipLinkHTML(ip, hits) {
  const v = (ip || "").toString().trim();
  if (!v || v === "-" || v.toLowerCase() === "unknown") return "-";
  const h = (hits === null || hits === undefined) ? "" : ` data-hits="${esc(hits)}"`;
  return `<a href="#" class="ip-link" data-ip="${esc(v)}"${h}>${esc(v)}</a>`;
}

function wireModalButtons() {
  const cIp = btnCopyIp();

  if (cIp) {
    cIp.addEventListener("click", async () => {
      if (!CURRENT_IP) return;
      const ok = await copyToClipboard(CURRENT_IP);
      cIp.textContent = ok ? "Copied ✓" : "Copy failed";
      setTimeout(() => (cIp.textContent = "Copy IP"), 900);
    });
  }
}

// Global click handlers
document.addEventListener("click", (e) => {
  const a = e.target && e.target.closest ? e.target.closest(".ip-link") : null;
  if (a) {
    e.preventDefault();
    const ip = a.getAttribute("data-ip") || a.textContent || "";
    const hitsAttr = a.getAttribute("data-hits");
    const hits = (hitsAttr === null) ? null : Number(hitsAttr);
    showIpDetails(ip, Number.isFinite(hits) ? hits : null);
    return;
  }

  if (e.target && e.target.id === "ipCloseBtn") {
    e.preventDefault();
    closeIpModal();
    return;
  }

  const m = ipModal();
  if (m && e.target === m) closeIpModal();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeIpModal();
});

// ===============================
// RUN SECURITY
// ===============================
async function runSecurity() {
  setStatus("RUNNING...", "", "Analyzing traffic...");

  try {
    const endpoint =
      (window.NETMON_ENDPOINTS && window.NETMON_ENDPOINTS.security) ||
      "/api/security/scan";

    const res = await fetch(endpoint);
    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);

    const total = Number(data.total ?? 0);
    const normal = Number(data.normal ?? 0);
    const suspicious = Number(data.suspicious ?? 0);
    const severity = (data.severity || "-").toString().toUpperCase();

    setText("secTotal", total);
    setText("secNormal", normal);
    setText("secSuspicious", suspicious);
    setText("secSeverity", severity);

    setText("secThresholdBase", data.threshold_base ?? 1200);

    //  Determine status from suspicious count
    const status = suspicious > 0 ? "SUSPICIOUS" : "SAFE";

    const note =
      suspicious > 0
        ? `Suspicious packets detected: ${suspicious}`
        : "No suspicious activity detected.";

    setStatus(status, statusClass(status, severity), note);

    await loadSecurityHistory();
  } catch (err) {
    setStatus("FAILED", "danger", `Security check failed: ${err.message}`);
  }
}

// ===============================
// LOAD HISTORY + ALERTS
// ===============================
async function loadSecurityHistory() {
  const days = document.getElementById("secDays")?.value || 2;

  const tbody = document.getElementById("secHistoryTable");
  const alertsBody = document.getElementById("secAlertsTable");
  const meta = document.getElementById("secHistoryMeta");

  if (!tbody || !alertsBody) return;

  tbody.innerHTML = `<tr><td colspan="8">Loading...</td></tr>`;
  alertsBody.innerHTML = `<tr><td colspan="5">Loading...</td></tr>`;
  if (meta) meta.textContent = "";

  try {
    const endpoint =
      (window.NETMON_ENDPOINTS && window.NETMON_ENDPOINTS.securityHistory) ||
      "/api/security/history";

    const res = await fetch(`${endpoint}?days=${encodeURIComponent(days)}`);
    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.error) {
      const msg = data.error || `HTTP ${res.status}`;
      tbody.innerHTML = `<tr><td colspan="8">${esc(msg)}</td></tr>`;
      alertsBody.innerHTML = `<tr><td colspan="5">${esc(msg)}</td></tr>`;
      return;
    }

    const scans = Array.isArray(data.scans) ? data.scans : [];

    if (meta) {
      meta.textContent = `Showing ${data.days ?? days} day(s) | Total Scans: ${data.total_scans ?? scans.length}`;
    }

    if (!scans.length) {
      tbody.innerHTML = `<tr><td colspan="8">No records found.</td></tr>`;
      alertsBody.innerHTML = `<tr><td colspan="5">No alerts yet</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    for (const s of scans) {
      const sev = (s.severity || "-").toString().toUpperCase();
      const susp = Number(s.suspicious ?? 0);
      const st = susp > 0 ? "SUSPICIOUS" : "SAFE";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${esc(s.ts ?? "-")}</td>
        <td>${esc(s.total ?? 0)}</td>
        <td>${esc(s.normal ?? 0)}</td>
        <td>${esc(susp)}</td>
        <td>${ipLinkHTML(s.top_ip, s.top_ip_count)}</td>
        <td><span class="chip ${statusClass(st, sev)}">${esc(st)}</span></td>
        <td><span class="chip ${severityClass(sev)}">${esc(sev)}</span></td>
        <td>${esc(s.threshold_value ?? "-")}</td>
      `;
      tbody.appendChild(tr);
    }

    const alerts = scans.filter(x => Number(x.suspicious ?? 0) > 0).slice(0, 10);

    if (!alerts.length) {
      alertsBody.innerHTML = `<tr><td colspan="5">No alerts yet</td></tr>`;
      return;
    }

    alertsBody.innerHTML = "";
    for (const a of alerts) {
      const sev = (a.severity || "-").toString().toUpperCase();

      const note =
        sev === "HIGH" ? "Packet length exceeded base threshold" :
        sev === "MEDIUM" ? "Traffic close to base threshold" :
        "Low level anomaly";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${esc(a.ts ?? "-")}</td>
        <td>${esc(a.suspicious ?? 0)}</td>
        <td>${ipLinkHTML(a.top_ip, a.top_ip_count)}</td>
        <td><span class="chip ${severityClass(sev)}">${esc(sev)}</span></td>
        <td>${esc(note)}</td>
      `;
      alertsBody.appendChild(tr);
    }

  } catch {
    tbody.innerHTML = `<tr><td colspan="8">Error loading history</td></tr>`;
    alertsBody.innerHTML = `<tr><td colspan="5">Error loading alerts</td></tr>`;
  }
}

window.addEventListener("load", () => {
  wireModalButtons();
  loadSecurityHistory();
});

window.runSecurity = runSecurity;
window.loadSecurityHistory = loadSecurityHistory; // so your HTML button onclick works too
