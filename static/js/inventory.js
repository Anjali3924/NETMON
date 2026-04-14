// ===============================
// inventory.js (FINAL VERSION)
// ===============================

// Current view mode
let currentView = "table";

// ===============================
// UTIL FUNCTIONS
// ===============================
function esc(v) {
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value ?? "");
}

// ===============================
// TOGGLE VIEW (TABLE ↔ CARD)
// ===============================
function toggleView() {
  currentView = currentView === "table" ? "card" : "table";
  loadInventory();
}

// ===============================
// LOAD INVENTORY (SCAN)
// ===============================
async function loadInventory() {
  const table = document.getElementById("inventoryTable");
  const cards = document.getElementById("inventoryCards");

  const invStatus = document.getElementById("invStatus");
  const invNote = document.getElementById("invNote");

  if (!table) return;

  // Loading UI
  table.innerHTML = `<tr><td colspan="6">Scanning network...</td></tr>`;
  if (cards) cards.innerHTML = "Scanning...";

  if (invStatus) invStatus.textContent = "SCANNING...";
  if (invNote) invNote.textContent = "Capturing packets...";

  try {
    const res = await fetch("/api/inventory/scan");
    const data = await res.json().catch(() => ({}));

    if (!res.ok || data?.error) {
      throw new Error(data?.error || "Server Error");
    }

    const devices = Array.isArray(data.devices) ? data.devices : [];

    // Clear UI
    table.innerHTML = "";
    if (cards) cards.innerHTML = "";

    if (!devices.length) {
      table.innerHTML = `<tr><td colspan="6">No devices found</td></tr>`;
      if (cards) cards.innerHTML = "No devices found";
      return;
    }

    let internal = 0;
    let external = 0;

    devices.forEach((d, idx) => {
      const ip = d.ip ?? "-";
      const type = d.type ?? "Unknown";
      const packets = d.packets ?? "-";
      const first = d.first_seen ?? "-";
      const last = d.last_seen ?? "-";

      if (type === "Internal") internal++;
      else if (type === "External") external++;

      // ================= TABLE VIEW =================
      if (currentView === "table") {
        const tr = document.createElement("tr");

        tr.innerHTML = `
          <td>${idx + 1}</td>
          <td>${esc(ip)}</td>
          <td class="${type === "Internal" ? "device-internal" : "device-external"}">
            ${esc(type)}
          </td>
          <td>${esc(packets)}</td>
          <td>${esc(first)}</td>
          <td>${esc(last)}</td>
        `;

        table.appendChild(tr);
      }

      // ================= CARD VIEW =================
      if (currentView === "card" && cards) {
        const card = document.createElement("div");
        card.className = "inv-card";

        card.innerHTML = `
          <h3>${esc(ip)}</h3>
          <p><b>Type:</b> 
            <span class="${type === "Internal" ? "device-internal" : "device-external"}">
              ${esc(type)}
            </span>
          </p>
          <p><b>Packets:</b> ${esc(packets)}</p>
          <p><b>First Seen:</b> ${esc(first)}</p>
          <p><b>Last Seen:</b> ${esc(last)}</p>
        `;

        cards.appendChild(card);
      }
    });

    // ================= VIEW SWITCH =================
    const tableElement = document.querySelector("table");

    if (currentView === "table") {
      if (tableElement) tableElement.style.display = "table";
      if (cards) cards.style.display = "none";
    } else {
      if (tableElement) tableElement.style.display = "none";
      if (cards) cards.style.display = "grid";
    }

    // ================= STATS =================
    setText("invTotal", devices.length);
    setText("invInternal", internal);
    setText("invExternal", external);

    if (invStatus) invStatus.textContent = "UPDATED";
    if (invNote) invNote.textContent = "Scan completed successfully";

    // Load history automatically
    if (typeof loadInventoryHistory === "function") {
      loadInventoryHistory();
    }

  } catch (err) {
    console.error("Inventory Error:", err);

    table.innerHTML = `<tr><td colspan="6">Error: ${esc(err.message)}</td></tr>`;
    if (invStatus) invStatus.textContent = "FAILED";
    if (invNote) invNote.textContent = "Unable to fetch data";
  }
}

// ===============================
// LOAD INVENTORY HISTORY
// ===============================
async function loadInventoryHistory() {
  const days = document.getElementById("historyDays")?.value || "2";
  const tbody = document.getElementById("historyTable");
  const meta = document.getElementById("historyMeta");

  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="6">Loading history...</td></tr>`;
  if (meta) meta.textContent = "";

  try {
    const res = await fetch(`/api/inventory/history?days=${encodeURIComponent(days)}`);
    const data = await res.json().catch(() => ({}));

    if (!res.ok || data?.error) {
      throw new Error(data?.error || "Error loading history");
    }

    const devices = Array.isArray(data.devices) ? data.devices : [];

    if (meta) {
      meta.textContent =
        `Showing ${data.days} day(s) | Total: ${data.total} | Internal: ${data.internal} | External: ${data.external}`;
    }

    if (!devices.length) {
      tbody.innerHTML = `<tr><td colspan="6">No history found</td></tr>`;
      return;
    }

    tbody.innerHTML = "";

    devices.forEach((d, idx) => {
      const tr = document.createElement("tr");

      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td>${esc(d.ip)}</td>
        <td>${esc(d.type)}</td>
        <td>${esc(d.total_packets)}</td>
        <td>${esc(d.first_seen)}</td>
        <td>${esc(d.last_seen)}</td>
      `;

      tbody.appendChild(tr);
    });

  } catch (err) {
    console.error("History Error:", err);
    tbody.innerHTML = `<tr><td colspan="6">Error loading history</td></tr>`;
  }
}

// ===============================
// AUTO LOAD ON PAGE OPEN
// ===============================
window.addEventListener("load", () => {
  loadInventory();
});