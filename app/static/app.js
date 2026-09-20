(() => {
  "use strict";

  const state = {
    lastScan: null,
    simpleMode: true,
    health: null,
  };

  const $ = (id) => document.getElementById(id);
  const els = {
    nav: [...document.querySelectorAll(".nav-item")],
    views: [...document.querySelectorAll(".view")],
    dropZone: $("dropZone"),
    uploadPanel: $("uploadPanel"),
    fileInput: $("fileInput"),
    chooseFileButton: $("chooseFileButton"),
    loadDemoButton: $("loadDemoButton"),
    scanProgress: $("scanProgress"),
    resultPanel: $("resultPanel"),
    resultFilename: $("resultFilename"),
    resultMeta: $("resultMeta"),
    riskOrb: $("riskOrb"),
    riskScore: $("riskScore"),
    riskLabel: $("riskLabel"),
    plainLanguageText: $("plainLanguageText"),
    payloadTitle: $("payloadTitle"),
    payloadSummary: $("payloadSummary"),
    payloadFields: $("payloadFields"),
    payloadText: $("payloadText"),
    qrCountTag: $("qrCountTag"),
    simpleNextSteps: $("simpleNextSteps"),
    evidenceList: $("evidenceList"),
    technicalExplanation: $("technicalExplanation"),
    contextSnippet: $("contextSnippet"),
    contextText: $("contextText"),
    limitationsBox: $("limitationsBox"),
    historyBody: $("historyBody"),
    evidenceModal: $("evidenceModal"),
    modalEvidenceList: $("modalEvidenceList"),
    healthModal: $("healthModal"),
    healthDetails: $("healthDetails"),
    healthDot: $("healthDot"),
    healthText: $("healthText"),
    familyModeButton: $("familyModeButton"),
    urlForm: $("urlForm"),
    urlInput: $("urlInput"),
    contextInput: $("contextInput"),
    urlResult: $("urlResult"),
    benchmarkMetrics: $("benchmarkMetrics"),
    benchmarkDetail: $("benchmarkDetail"),
    toastStack: $("toastStack"),
    startDialog: $("startDialog"),
  };

  const verdictColors = {
    low: "var(--safe)",
    suspicious: "var(--warning)",
    high: "var(--danger)",
    critical: "var(--critical)",
  };

  function navigate(view) {
    if (state.simpleMode && ["benchmark", "method"].includes(view)) view = "scan";
    els.nav.forEach((item) => item.classList.toggle("active", item.dataset.view === view));
    els.views.forEach((section) => section.classList.toggle("active", section.id === `view-${view}`));
    history.replaceState(null, "", `#${view}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (view === "benchmark") loadBenchmark();
  }

  function toast(title, message = "", type = "info") {
    const box = document.createElement("div");
    box.className = `toast ${type === "error" ? "error" : ""}`;
    const strong = document.createElement("strong");
    strong.textContent = title;
    const span = document.createElement("span");
    span.textContent = message;
    box.append(strong, span);
    els.toastStack.appendChild(box);
    window.setTimeout(() => box.remove(), 4800);
  }

  function setSimpleMode(enabled) {
    state.simpleMode = enabled;
    document.body.classList.toggle("simple-mode", enabled);
    els.familyModeButton.setAttribute("aria-pressed", String(enabled));
    els.familyModeButton.textContent = enabled ? "Detailed view" : "Simple view";
    if (enabled && ["benchmark", "method"].includes(location.hash.replace("#", ""))) navigate("scan");
  }

  async function api(url, options = {}) {
    const response = await fetch(url, options);
    let body = null;
    try { body = await response.json(); } catch (_) { body = null; }
    if (!response.ok) throw new Error(body?.detail || `Request failed (${response.status})`);
    return body;
  }

  function setBusy(isBusy, text = "Decoding the QR and checking what its payload means.") {
    els.scanProgress.classList.toggle("hidden", !isBusy);
    $("scanProgressText").textContent = text;
    els.chooseFileButton.disabled = isBusy;
    els.loadDemoButton.disabled = isBusy;
  }

  async function scanFile(file) {
    if (!file) return;
    if (file.size > 12 * 1024 * 1024) {
      toast("File too large", "QuishLens currently accepts files up to 12 MB.", "error");
      return;
    }
    const form = new FormData();
    form.append("file", file);
    setBusy(true);
    els.resultPanel.classList.add("hidden");
    try {
      const result = await api("/api/scan", { method: "POST", body: form });
      state.lastScan = result;
      renderScan(result);
      await loadHistory();
      toast("QR check finished", result.qr_found ? `${result.qr_count} QR code${result.qr_count === 1 ? "" : "s"} decoded.` : "No readable QR code was found.");
    } catch (error) {
      toast("Could not scan the file", error.message, "error");
    } finally {
      setBusy(false);
      els.fileInput.value = "";
    }
  }

  function renderScan(result) {
    const payload = result.payload_analysis || null;
    els.resultFilename.textContent = result.filename;
    els.resultMeta.textContent = `${result.file_type} · ${result.elapsed_ms} ms · static analysis`;
    els.riskScore.textContent = result.risk_score;
    els.riskLabel.textContent = result.verdict.toUpperCase();
    setRiskMeter(els.riskOrb, result.risk_score, result.verdict);
    els.plainLanguageText.textContent = result.plain_language;
    els.qrCountTag.textContent = `${result.qr_count} QR${result.qr_count === 1 ? "" : "s"}`;
    els.technicalExplanation.textContent = result.explanation;

    if (payload) {
      els.payloadTitle.textContent = payload.title || "Decoded QR content";
      els.payloadSummary.textContent = payload.summary || "The QR was decoded successfully.";
      els.payloadText.textContent = result.selected_payload || "—";
      renderPayloadFields(payload.fields || []);
    } else {
      els.payloadTitle.textContent = "No readable QR code";
      els.payloadSummary.textContent = "The file was processed, but QuishLens could not recover a QR payload.";
      els.payloadText.textContent = "—";
      renderPayloadFields([]);
    }

    renderNextSteps(result, payload);
    renderEvidence(result.signals || [], els.evidenceList, 6);
    renderEvidence(result.signals || [], els.modalEvidenceList);

    if (result.extracted_text_preview) {
      els.contextText.textContent = result.extracted_text_preview;
      els.contextSnippet.classList.remove("hidden");
    } else {
      els.contextSnippet.classList.add("hidden");
    }

    if (result.limitations?.length) {
      els.limitationsBox.textContent = `Limitations: ${result.limitations.join(" ")}`;
      els.limitationsBox.classList.remove("hidden");
    } else {
      els.limitationsBox.classList.add("hidden");
    }

    els.resultPanel.classList.remove("hidden");
    els.resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderPayloadFields(fields) {
    els.payloadFields.replaceChildren();
    if (!fields.length) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "No structured fields were recovered.";
      els.payloadFields.appendChild(p);
      return;
    }
    fields.slice(0, 12).forEach((field) => {
      const div = document.createElement("div");
      div.className = "payload-field";
      const label = document.createElement("span");
      label.textContent = field.label || "Field";
      const value = document.createElement("strong");
      value.textContent = field.value == null || field.value === "" ? "—" : String(field.value);
      div.append(label, value);
      els.payloadFields.appendChild(div);
    });
  }

  function renderNextSteps(result, payload) {
    const steps = [];
    if (!result.qr_found) {
      steps.push("Try a sharper screenshot with the whole QR visible.", "Do not assume the file is safe just because the QR could not be decoded.");
    } else if (payload?.kind === "payment") {
      steps.push("Look at the receiver or merchant name shown by your payment app.", "If the receiver is not exactly who you expected, cancel the payment.", "Never approve a payment just because the QR itself looks official.");
    } else if (payload?.kind === "url") {
      steps.push("Do not open the link from the QR if the result shows warning signs.", "Open the organisation's official app or type its known address yourself.", "Never enter a password, OTP, or payment detail after an unexpected QR prompt.");
    } else if (payload?.kind === "credential") {
      steps.push("Do not share this QR or a screenshot of it.", "Treat it like a password or authenticator secret.");
    } else {
      steps.push("Read the decoded content above before letting another app act on it.", "If you did not expect this action, stop and confirm who sent the QR.");
    }
    if (["high", "critical"].includes(result.verdict)) steps.unshift("Stop here for now — QuishLens found a strong warning sign.");

    els.simpleNextSteps.replaceChildren();
    steps.slice(0, 4).forEach((text, index) => {
      const row = document.createElement("div");
      row.className = "next-step";
      const n = document.createElement("b");
      n.textContent = String(index + 1);
      const span = document.createElement("span");
      span.textContent = text;
      row.append(n, span);
      els.simpleNextSteps.appendChild(row);
    });
  }

  function setRiskMeter(container, score, verdict) {
    const color = verdictColors[verdict] || "var(--safe)";
    container.style.setProperty("--risk", String(Math.max(0, Math.min(100, score))));
    container.style.setProperty("--risk-color", color);
  }

  function renderEvidence(signals, target, limit = Infinity) {
    target.replaceChildren();
    if (!signals.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No additional technical evidence is available for this result.";
      target.appendChild(empty);
      return;
    }
    signals.slice(0, limit).forEach((signal) => {
      const row = document.createElement("div");
      row.className = "evidence-item";
      const dot = document.createElement("span");
      dot.className = `evidence-dot ${signal.level || "info"}`;
      const copy = document.createElement("div");
      copy.className = "evidence-copy";
      const title = document.createElement("strong");
      title.textContent = signal.label || signal.key;
      const detail = document.createElement("small");
      detail.textContent = signal.detail || "";
      copy.append(title, detail);
      const value = document.createElement("span");
      value.className = "evidence-value";
      value.textContent = formatValue(signal.value);
      row.append(dot, copy, value);
      target.appendChild(row);
    });
  }

  function formatValue(value) {
    if (value === true) return "Yes";
    if (value === false) return "No";
    if (value === null || value === undefined || value === "") return "—";
    return String(value);
  }

  async function loadDemoFile() {
    try {
      setBusy(true, "Loading a safe demonstration QR.");
      const response = await fetch("/api/demo/suspicious_qr");
      if (!response.ok) throw new Error("Demo file is unavailable.");
      const blob = await response.blob();
      const file = new File([blob], "demo-suspicious-qr.png", { type: blob.type || "image/png" });
      setBusy(false);
      await scanFile(file);
    } catch (error) {
      setBusy(false);
      toast("Could not load demo", error.message, "error");
    }
  }

  async function loadHistory() {
    try {
      const data = await api("/api/history");
      els.historyBody.replaceChildren();
      if (!data.items?.length) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 5;
        td.className = "empty-cell";
        td.textContent = "No scans in this server session yet.";
        tr.appendChild(td);
        els.historyBody.appendChild(tr);
        return;
      }
      data.items.forEach((item) => {
        const tr = document.createElement("tr");
        tr.append(cell(item.filename), cell(item.qr_count));
        const verdictCell = document.createElement("td");
        const chip = document.createElement("span");
        chip.className = `verdict-chip verdict-${item.verdict}`;
        chip.textContent = item.verdict;
        verdictCell.appendChild(chip);
        tr.append(verdictCell, cell(`${item.risk_score}/100`), cell(`${item.elapsed_ms} ms`));
        els.historyBody.appendChild(tr);
      });
    } catch (_) {
      // Scan results matter more than session history; do not interrupt the main flow.
    }
  }

  function cell(value) {
    const td = document.createElement("td");
    td.textContent = value == null ? "—" : String(value);
    return td;
  }

  async function checkHealth(openModal = false) {
    try {
      const health = await api("/api/health");
      state.health = health;
      els.healthDot.className = "status-dot ok";
      els.healthText.textContent = health.model_loaded ? "Ready" : "Ready · fallback";
      if (openModal) renderHealth(health);
    } catch (error) {
      els.healthDot.className = "status-dot error";
      els.healthText.textContent = "Unavailable";
      if (openModal) {
        els.healthDetails.textContent = error.message;
        els.healthModal.showModal();
      }
    }
  }

  function renderHealth(health) {
    els.healthDetails.replaceChildren();
    const rows = [
      ["API", health.status === "ok" ? "Healthy" : health.status],
      ["URL model", health.model_loaded ? (health.model_name || "Loaded") : "Heuristic fallback"],
      ["Model status", health.bootstrap_model ? "Demo bootstrap model — do not report as benchmark evidence" : (health.model_loaded ? "Loaded model" : "Fallback only")],
      ["Payment QR model", health.payment_model_loaded ? (health.payment_model_name || "Loaded") : "Not loaded"],
      ["Known malicious URLs", health.threat_intel_urls],
      ["Known malicious domains", health.threat_intel_domains],
    ];
    rows.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "health-row";
      const span = document.createElement("span"); span.textContent = label;
      const strong = document.createElement("strong"); strong.textContent = value;
      row.append(span, strong);
      els.healthDetails.appendChild(row);
    });
    els.healthModal.showModal();
  }

  function renderUrlResult(result) {
    const box = document.createElement("section");
    box.className = "result-panel";
    box.innerHTML = `
      <div class="result-topline">
        <div><p class="eyebrow">LINK RESULT</p><h2>${html(result.features.registered_domain || result.normalized_url)}</h2><p class="muted advanced-only">Static inspection · destination not opened</p></div>
        <div class="risk-box" id="urlRiskMeter"><span>RISK</span><strong>${result.risk.score}</strong><small>/ 100 · <b>${html(result.risk.verdict.toUpperCase())}</b></small><i class="risk-fill"></i></div>
      </div>
      <div class="human-answer"><div class="human-answer-icon">i</div><div><strong>What this means</strong><p>${html(result.plain_language)}</p></div></div>
      <article class="glass-panel payload-card"><div class="panel-heading"><div><p class="eyebrow">DESTINATION</p><h3>${html(result.features.registered_domain || "Link")}</h3></div></div><div class="payload-fields"><div class="payload-field"><span>Full address</span><strong>${html(result.normalized_url)}</strong></div><div class="payload-field"><span>Threat intelligence</span><strong>${result.threat_intel?.matched ? "Known match" : "No local match"}</strong></div></div></article>
      <article class="glass-panel explanation-panel advanced-only"><p class="eyebrow">WHY</p><p>${html(result.explanation)}</p><div class="evidence-list" id="urlEvidenceDynamic"></div></article>`;
    els.urlResult.replaceChildren(box);
    els.urlResult.classList.remove("hidden");
    setRiskMeter($("urlRiskMeter"), result.risk.score, result.risk.verdict);
    renderEvidence(result.signals || [], $("urlEvidenceDynamic"));
    box.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function html(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));
  }

  async function loadBenchmark() {
    try {
      const data = await api("/api/benchmark/summary");
      if (!data.available) {
        els.benchmarkDetail.innerHTML = `No benchmark summary yet. Run an evaluation script; QuishLens reads <code>results/benchmark_summary.json</code> automatically.`;
        return;
      }
      const m = data.metrics || {};
      const boxes = els.benchmarkMetrics.querySelectorAll("div strong");
      boxes[0].textContent = data.dataset || "Benchmark";
      boxes[1].textContent = data.samples ?? "—";
      boxes[2].textContent = m.recall != null ? `${(m.recall * 100).toFixed(1)}%` : "—";
      boxes[3].textContent = m.f1 != null ? `${(m.f1 * 100).toFixed(1)}%` : "—";
      const entries = [
        ["Accuracy", pct(m.accuracy)], ["Precision", pct(m.precision)], ["Recall", pct(m.recall)], ["F1", pct(m.f1)],
        ["ROC-AUC", pct(m.roc_auc)], ["False-positive rate", pct(m.false_positive_rate)], ["False-negative rate", pct(m.false_negative_rate)],
        ["Average latency", m.avg_latency_ms != null ? `${Number(m.avg_latency_ms).toFixed(1)} ms` : "—"],
      ];
      const table = document.createElement("table"); table.className = "benchmark-table";
      entries.forEach(([label, value]) => { const tr = document.createElement("tr"); tr.append(cell(label), cell(value)); table.appendChild(tr); });
      els.benchmarkDetail.replaceChildren(table);
    } catch (error) {
      els.benchmarkDetail.textContent = `Could not load benchmark results: ${error.message}`;
    }
  }

  function pct(value) { return value == null ? "—" : `${(value * 100).toFixed(2)}%`; }

  function closeStartAndScan() {
    if (els.startDialog.open) els.startDialog.close();
    navigate("scan");
    window.setTimeout(() => els.uploadPanel.scrollIntoView({ behavior: "smooth", block: "center" }), 100);
  }

  els.nav.forEach((item) => item.addEventListener("click", () => navigate(item.dataset.view)));
  els.chooseFileButton.addEventListener("click", () => els.fileInput.click());
  els.fileInput.addEventListener("change", () => scanFile(els.fileInput.files?.[0]));
  els.loadDemoButton.addEventListener("click", loadDemoFile);
  $("heroScanButton").addEventListener("click", closeStartAndScan);
  $("heroUrlButton").addEventListener("click", () => navigate("url"));
  $("startScanButton").addEventListener("click", closeStartAndScan);
  $("startUrlButton").addEventListener("click", () => { if (els.startDialog.open) els.startDialog.close(); navigate("url"); });
  $("startCloseButton").addEventListener("click", () => els.startDialog.close());

  els.dropZone.addEventListener("dragover", (event) => { event.preventDefault(); els.dropZone.classList.add("dragging"); });
  els.dropZone.addEventListener("dragleave", () => els.dropZone.classList.remove("dragging"));
  els.dropZone.addEventListener("drop", (event) => { event.preventDefault(); els.dropZone.classList.remove("dragging"); scanFile(event.dataTransfer?.files?.[0]); });

  $("showAllEvidenceButton").addEventListener("click", () => els.evidenceModal.showModal());
  $("refreshHistoryButton").addEventListener("click", loadHistory);
  $("refreshBenchmarkButton").addEventListener("click", loadBenchmark);
  $("healthButton").addEventListener("click", () => checkHealth(true));
  document.querySelectorAll("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => $(button.dataset.closeDialog)?.close()));

  els.familyModeButton.addEventListener("click", () => {
    setSimpleMode(!state.simpleMode);
    toast(state.simpleMode ? "Simple view on" : "Detailed view on", state.simpleMode ? "Technical model details are hidden; the decoded content and safety advice stay visible." : "Model, evidence, benchmark, and method details are visible again.");
  });

  els.urlForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = els.urlInput.value.trim();
    if (!url) return;
    const submit = els.urlForm.querySelector("button[type=submit]");
    submit.disabled = true;
    submit.textContent = "Checking…";
    try {
      const result = await api("/api/analyze-url", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ url, context: els.contextInput.value }),
      });
      renderUrlResult(result);
    } catch (error) {
      toast("Link check failed", error.message, "error");
    } finally {
      submit.disabled = false;
      submit.textContent = "Check link";
    }
  });

  setSimpleMode(true);
  const requestedView = location.hash.replace("#", "");
  if (["scan", "url", "benchmark", "method"].includes(requestedView)) navigate(requestedView);
  checkHealth();
  loadHistory();
  window.setTimeout(() => {
    if (els.startDialog && typeof els.startDialog.showModal === "function" && !els.startDialog.open) els.startDialog.showModal();
  }, 350);
})();
