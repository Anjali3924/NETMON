(() => {
  // prevent double-run
  if (window.__NETMON_QA_STARTED__) return;
  window.__NETMON_QA_STARTED__ = true;

  const $ = (id) => document.getElementById(id);

  // ===== Running states =====
  let globalRunning = true;
  let anomRunning = true;
  let protoRunning = true;
  let animRunning = true;

  // logo pulse control (live anomaly)
  const qaLogo = document.getElementById("qaLogo");
  let threatPulseTimer = null;

  // Polling control
  let liveInterval = null;
  let isFetching = false;

  // Buffers for anomaly line chart
  const labels = [];
  const ppsSeries = [];
  const anomSeries = [];

  // Charts
  let anomChart = null;
  let protoChart = null;

  // ======================
  // Helpers
  // ======================
  function safeText(id, txt) {
    const el = $(id);
    if (el) el.textContent = txt;
  }

  function updateInsights(reasons) {
    const ul = $("aiInsights");
    if (!ul) return;
    ul.innerHTML = "";
    const list = (reasons && reasons.length) ? reasons : ["No strong risk signals detected."];
    list.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      ul.appendChild(li);
    });
  }

  function updateProto(protocolsObj) {
    if (!protoChart) return;
    const entries = Object.entries(protocolsObj || {});
    entries.sort((a, b) => b[1] - a[1]);
    const top = entries.slice(0, 6);

    const lbls = top.length ? top.map(x => x[0]) : ["—"];
    const vals = top.length ? top.map(x => x[1]) : [0];

    protoChart.data.labels = lbls;
    protoChart.data.datasets[0].data = vals;
    protoChart.update();
  }

  // ======================
  // Charts
  // ======================
  function makeAnomChart() {
    const ctx = $("anomChart").getContext("2d");
    anomChart = new Chart(ctx, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          { label: "Packets/sec", data: [], tension: 0.35, pointRadius: 2, borderWidth: 2 },
          { label: "Anomaly", data: [], showLine: false, pointRadius: 6, borderWidth: 0 }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "rgba(234,242,255,0.75)" } } },
        scales: {
          x: { ticks: { color: "rgba(234,242,255,0.55)" }, grid: { color: "rgba(255,255,255,0.06)" } },
          y: { ticks: { color: "rgba(234,242,255,0.55)" }, grid: { color: "rgba(255,255,255,0.06)" } }
        }
      }
    });
  }

  function makeProtoChart() {
    const ctx = $("protoChart").getContext("2d");
    protoChart = new Chart(ctx, {
      type: "bar",
      data: { labels: ["—"], datasets: [{ label: "Packets", data: [0] }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "rgba(234,242,255,0.75)" } } },
        scales: {
          x: { ticks: { color: "rgba(234,242,255,0.55)" }, grid: { color: "rgba(255,255,255,0.06)" } },
          y: { ticks: { color: "rgba(234,242,255,0.55)" }, grid: { color: "rgba(255,255,255,0.06)" } }
        }
      }
    });
  }

  // ======================
  // Canvas Animation (stop truly stops)
  // ======================
  const canvas = $("trafficCanvas");
  const ctxA = canvas.getContext("2d");
  let W = 0, H = 0;
  const particles = [];

  function resizeCanvas() {
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.floor(rect.width * devicePixelRatio);
    canvas.height = Math.floor(rect.height * devicePixelRatio);
    ctxA.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
    W = rect.width;
    H = rect.height;
  }
  window.addEventListener("resize", resizeCanvas);

  function drawLanes() {
    ctxA.globalAlpha = 0.25;
    for (let i = 1; i <= 5; i++) {
      const y = (H / 6) * i;
      ctxA.beginPath();
      ctxA.moveTo(0, y);
      ctxA.lineTo(W, y);
      ctxA.strokeStyle = "rgba(255,255,255,0.06)";
      ctxA.stroke();
    }
    ctxA.globalAlpha = 1;
  }

  function drawPausedOverlay() {
    ctxA.fillStyle = "rgba(0,0,0,0.35)";
    ctxA.fillRect(0, 0, W, H);
    ctxA.font = "600 14px system-ui";
    ctxA.fillStyle = "rgba(234,242,255,0.75)";
    ctxA.fillText("Animation Paused", 14, 24);
  }

  function spawnParticle(isAnom = false) {
    particles.push({
      x: 0,
      y: Math.random() * H,
      vx: 2.0 + Math.random() * 2.8,
      r: isAnom ? 3.8 : 2.4,
      anom: isAnom
    });
    if (particles.length > 240) particles.shift();
  }

  function stopAnimationInstant() {
    animRunning = false;
    particles.length = 0;
    ctxA.clearRect(0, 0, W, H);
    drawLanes();
    drawPausedOverlay();
  }

  function resumeAnimation() {
    animRunning = true;
  }

  function animateLoop() {
    ctxA.clearRect(0, 0, W, H);
    drawLanes();

    if (!animRunning) {
      drawPausedOverlay();
      requestAnimationFrame(animateLoop);
      return;
    }

    for (const p of particles) {
      p.x += p.vx;

      if (p.anom) {
        ctxA.beginPath();
        ctxA.arc(p.x, p.y, p.r + 6, 0, Math.PI * 2);
        ctxA.fillStyle = "rgba(255,70,70,0.14)";
        ctxA.fill();
      }

      ctxA.beginPath();
      ctxA.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctxA.fillStyle = p.anom ? "rgba(255,70,70,0.95)" : "rgba(234,242,255,0.75)";
      ctxA.fill();
    }

    for (let i = particles.length - 1; i >= 0; i--) {
      if (particles[i].x > W + 20) particles.splice(i, 1);
    }

    requestAnimationFrame(animateLoop);
  }

  // ======================
  // Live polling (single interval)
  // ======================
  async function tick() {
    if (!globalRunning) return;
    if (isFetching) return;
    isFetching = true;

    try {
      const res = await fetch("/api/live_stats", { cache: "no-store" });
      const d = await res.json();

      safeText("pps", d.pps ?? "—");
      safeText("tps", d.tps ?? "—");
      safeText("flows", d.active_flows ?? "—");
      safeText("threatLevel", d.threat_level ?? "—");
      safeText("threatScore", `Score: ${d.threat_score ?? "—"}`);

      safeText("avgLen", `${d.avg_len ?? 0} bytes`);
      safeText("baselinePps", d.baseline_pps === null ? "—" : `${d.baseline_pps}`);
      safeText("zScore", d.z ?? "—");

      const intro = $("liveIntro");
      if (intro) {
        intro.textContent = `Currently monitoring: ${d.pps ?? 0} packets/sec • ${d.active_flows ?? 0} active flows`;
      }

      updateInsights(d.ai_reasons);

      // ---- Anomaly chart
      if (anomRunning && anomChart) {
        const label = new Date((d.ts ?? Math.floor(Date.now() / 1000)) * 1000)
          .toLocaleTimeString().slice(0, 8);

        labels.push(label);
        ppsSeries.push(d.pps ?? 0);
        anomSeries.push(d.anom ? (d.pps ?? 0) : null);

        if (labels.length > 30) {
          labels.shift(); ppsSeries.shift(); anomSeries.shift();
        }

        anomChart.data.labels = labels;
        anomChart.data.datasets[0].data = ppsSeries;
        anomChart.data.datasets[1].data = anomSeries;
        anomChart.update();
      }

      // ---- Protocol chart
      if (protoRunning) updateProto(d.protocols);

      // ---- Live traffic animation particles
      if (animRunning) {
        const isAnomaly = Boolean(d.anom);
        const burst = Math.max(1, Math.min(10, Math.floor(Number(d.pps ?? 0) / 10)));
        for (let i = 0; i < burst; i++) spawnParticle(isAnomaly);

        // RED logo pulse ONLY when anomaly seen in live traffic
        if (isAnomaly && qaLogo) {
          qaLogo.classList.add("threat-live");
          clearTimeout(threatPulseTimer);
          threatPulseTimer = setTimeout(() => {
            qaLogo.classList.remove("threat-live");
          }, 3000);
        }
      }

      // Pill status
      const pill = $("anomPill");
      if (pill) {
        if (!globalRunning) pill.textContent = "Stopped";
        else if (!anomRunning) pill.textContent = "Chart Stopped";
        else pill.textContent = d.anom ? "Anomaly Detected" : "Monitoring";
      }

      safeText("ppsHint", globalRunning ? "rolling baseline…" : "Monitoring stopped");

    } catch (e) {
      safeText("ppsHint", "Network error (retrying)…");
    } finally {
      isFetching = false;
    }
  }

  function startLive() {
    if (liveInterval) return;
    globalRunning = true;
    tick();
    liveInterval = setInterval(tick, 1000);
  }

  function stopLive() {
    globalRunning = false;
    if (liveInterval) {
      clearInterval(liveInterval);
      liveInterval = null;
    }
  }

  // ======================
  // Buttons
  // ======================
  function wireButtons() {
    $("btnStopAll").onclick = () => {
      stopLive();
      stopAnimationInstant();
      if (qaLogo) qaLogo.classList.remove("threat-live");
      safeText("ppsHint", "Monitoring stopped (global)");
    };

    $("btnResumeAll").onclick = () => {
      startLive();
      resumeAnimation();
      safeText("ppsHint", "Monitoring resumed (global)");
    };

    // per graph stop/resume
    $("stopAnom").onclick = () => { anomRunning = false; };
    $("resumeAnom").onclick = () => { anomRunning = true; };

    $("stopProto").onclick = () => { protoRunning = false; };
    $("resumeProto").onclick = () => { protoRunning = true; };

    $("stopAnim").onclick = () => stopAnimationInstant();
    $("resumeAnim").onclick = () => resumeAnimation();

    // optional API triggers
    $("btnCapture").onclick = () => fetch("/api/traffic/start").catch(()=>{});
    $("btnInventory").onclick = () => fetch("/api/inventory/scan").catch(()=>{});
    $("btnThreat").onclick = () => fetch("/api/security/scan").catch(()=>{});
  }

  // stop polling if leaving page
  window.addEventListener("beforeunload", () => stopLive());

  // pause/resume when tab hidden
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopLive();
    else startLive();
  });

  // ======================
  // Init
  // ======================
  function init() {
    resizeCanvas();
    makeAnomChart();
    makeProtoChart();
    animateLoop();
    wireButtons();
    startLive();
  }

  init();
})();
