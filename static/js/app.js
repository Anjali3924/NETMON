// Traffic page logic

function esc(v){
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function startCapture(){
  const totalEl = document.getElementById("totalPackets");
  const tbody = document.getElementById("packetTable");

  if (tbody) tbody.innerHTML = `<tr><td colspan="4">Capturing packets… (3 sec)</td></tr>`;
  if (totalEl) totalEl.textContent = "…";

  try{
    const res = await fetch("/api/traffic/start", { cache:"no-store" });
    const data = await res.json().catch(()=> ({}));

    if (!res.ok || data.error){
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    const packets = Array.isArray(data.packets) ? data.packets : [];
    if (totalEl) totalEl.textContent = String(data.count ?? packets.length);

    if (!tbody){
      return;
    }

    if (!packets.length){
      tbody.innerHTML = `<tr><td colspan="4">No packets captured yet</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    packets.forEach((p, idx)=>{
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${esc(p.no ?? (idx+1))}</td>
        <td>${esc(p.src ?? "-")}</td>
        <td>${esc(p.dst ?? "-")}</td>
        <td>${esc(p.len ?? "-")}</td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    if (tbody) tbody.innerHTML = `<tr><td colspan="4">Error: ${esc(e.message)}</td></tr>`;
    if (totalEl) totalEl.textContent = "0";
  }
}

// expose for inline onclick
window.startCapture = startCapture;
