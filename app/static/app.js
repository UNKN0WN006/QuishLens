(() => {
  "use strict";

  const state = {
    lastScan: null,
    familyMode: false,
    health: null,
  };

  const $ = (id) => document.getElementById(id);
  const els = {
    nav: [...document.querySelectorAll(".nav-item")],
    views: [...document.querySelectorAll(".view")],
    dropZone: $("dropZone"),
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
    payloadText: $("payloadText"),
    qrCountTag: $("qrCountTag"),
    destinationFacts: $("destinationFacts"),
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
  };

  const verdictColors = {
    low: "var(--safe)",
    suspicious: "var(--warning)",
    high: "var(--danger)",
    critical: "var(--critical)",
  };

  function navigate(view) {
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

  function escapeText(value) {
    return value == null ? "—" : String(value);
  }

  function setBusy(isBusy, text = "Finding QR codes and extracting document context.") {
    els.scanProgress.classList.toggle("hidden", !isBusy);
    $("scanProgressText").textContent = text;
    els.chooseFileButton.disabled = isBusy;
    els.loadDemoButton.disabled = isBusy;
  }

  async function api(url, options = {}) {
    const response = await fetch(url, options);
    let body = null;
    try { body = await response.json(); } catch (_) { body = null; }
    if (!response.ok) {
      const detail = body?.detail || `Request failed (${response.status})`;
      throw new Error(detail);
    }
    return body;
  }

  async function scanFile(file) {
    if (!file) return;
    if (file.size > 12 * 1024 * 1024) {
      toast("File too large", "The current prototype accepts files up to 12 MB.", "error");
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
      toast("Analysis complete", `${result.qr_count} QR artifact${result.qr_count === 1 ? "" : "s"} found · risk ${result.risk_score}/100`);
    } catch (error) {
      toast("Could not scan file", error.message, "error");
    } finally {
      setBusy(false);
      els.fileInput.value = "";
    }
  }

  function renderScan(result) {
    els.resultFilename.textContent = result.filename;
    els.resultMeta.textContent = `${result.file_type} · ${result.elapsed_ms} ms · static analysis`;
    els.riskScore.textContent = result.risk_score;
    els.riskLabel.textContent = result.verdict.toUpperCase();
    setRiskMeter(els.riskOrb, els.riskLabel, result.risk_score, result.verdict);
    els.plainLanguageText.textContent = result.plain_language;
    els.payloadText.textContent = result.selected_payload || (result.qr_found ? "QR payload is not a web URL" : "No web URL decoded");
    els.qrCountTag.textContent = `${result.qr_count} QR${result.qr_count === 1 ? "" : "s"}`;
    els.technicalExplanation.textContent = result.explanation;

    renderFacts(result);
    renderEvidence(result.signals || [], els.evidenceList, 5);
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

  function setRiskMeter(container, label, score, verdict) {
    const color = verdictColors[verdict] || "var(--green)";
    container.style.setProperty("--risk", String(Math.max(0, Math.min(100, score))));
    container.style.setProperty("--risk-color", color);
    label.style.color = color;
  }

  function renderFacts(result) {
    const analysis = result.url_analysis;
    const feature = analysis?.features || {};
    const model = analysis?.model || {};
    const brand = analysis?.brand?.best_match;
    const facts = [
      ["Registered domain", feature.registered_domain || "—"],
      ["Classifier", model.phishing_probability != null ? `${Math.round(model.phishing_probability * 100)}% phishing score` : "—"],
      ["Brand candidate", brand?.brand || "None"],
      ["Threat intel", analysis?.threat_intel?.matched ? "Match" : "No local match"],
    ];
    els.destinationFacts.replaceChildren();
    for (const [label, value] of facts) {
      const div = document.createElement("div");
      div.className = "mini-fact";
      const span = document.createElement("span");
      span.textContent = label;
      const strong = document.createElement("strong");
      strong.textContent = value;
      div.append(span, strong);
      els.destinationFacts.appendChild(div);
    }
  }

  function renderEvidence(signals, target, limit = Infinity) {
    target.replaceChildren();
    if (!signals.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No URL-specific evidence is available for this result.";
      target.appendChild(empty);
      return;
    }
    signals.slice(0, limit).forEach((signal) => {
      const row = document.createElement("div");
      row.className = "evidence-item";
      const dot = document.createElement("span");
      dot.className = `evidence-dot ${signal.level}`;
      const copy = document.createElement("div");
      copy.className = "evidence-copy";
      const title = document.createElement("strong");
      title.textContent = signal.label;
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
      // History is convenience UI; a failure here should not obscure scan results.
    }
  }

  function cell(value) {
    const td = document.createElement("td");
    td.textContent = escapeText(value);
    return td;
  }

  async function checkHealth(openModal = false) {
    try {
      const health = await api("/api/health");
      state.health = health;
      els.healthDot.className = "status-dot ok";
      els.healthText.textContent = health.model_loaded ? "Engine ready" : "Engine ready · fallback model";
      if (openModal) renderHealth(health);
    } catch (error) {
      els.healthDot.className = "status-dot error";
      els.healthText.textContent = "Engine unavailable";
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
      ["URL model", health.model_loaded ? (health.model_name || "Loaded") : "Not loaded — heuristic fallback active"],
      ["Model status", health.bootstrap_model ? "Bootstrap demo model — replace before reporting metrics" : (health.model_loaded ? "Competition/externally trained model" : "Fallback only")],
      ["Known malicious URLs", health.threat_intel_urls],
      ["Known malicious domains", health.threat_intel_domains],
    ];
    rows.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "health-row";
      const span = document.createElement("span"); span.textContent = label;
      const strong = document.createElement("strong"); strong.textContent = value;
      row.append(span, strong); els.healthDetails.appendChild(row);
    });
    els.healthModal.showModal();
  }

  function renderUrlResult(result) {
    const box = document.createElement("section");
    box.className = "result-panel";
    box.innerHTML = `
      <div class="result-head">
        <div><p class="eyebrow">URL ANALYSIS</p><h2>${html(result.features.registered_domain || result.normalized_url)}</h2><p class="muted">Static inspection · destination not opened</p></div>
        <div class="risk-scorecard" id="urlRiskMeter"><div class="risk-number"><strong>${result.risk.score}</strong><span>/100</span></div><div class="risk-track" aria-hidden="true"><i></i></div><small id="urlRiskLabel">${html(result.risk.verdict.toUpperCase())}</small></div>
      </div>
      <div class="plain-callout"><span class="callout-icon">?</span><div><strong>What this means</strong><p>${html(result.plain_language)}</p></div></div>
      <div class="result-grid"><article class="panel destination-panel"><h3>Destination</h3><code>${html(result.normalized_url)}</code></article><article class="panel"><h3>Security explanation</h3><p class="muted">${html(result.explanation)}</p></article></div>
      <article class="panel explanation-panel"><div class="panel-title"><h3>Evidence</h3><span class="tag neutral">Static</span></div><div class="evidence-list" id="urlEvidenceDynamic"></div></article>`;
    els.urlResult.replaceChildren(box);
    els.urlResult.classList.remove("hidden");
    setRiskMeter($("urlRiskMeter"), $("urlRiskLabel"), result.risk.score, result.risk.verdict);
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
        els.benchmarkDetail.innerHTML = `No benchmark summary yet. Run an evaluation script; QuishLens will read <code>results/benchmark_summary.json</code> automatically.`;
        return;
      }
      const m = data.metrics || {};
      const metricBoxes = els.benchmarkMetrics.querySelectorAll("div strong");
      metricBoxes[0].textContent = data.dataset || "Benchmark";
      metricBoxes[1].textContent = data.samples ?? "—";
      metricBoxes[2].textContent = m.recall != null ? `${(m.recall*100).toFixed(1)}%` : "—";
      metricBoxes[3].textContent = m.f1 != null ? `${(m.f1*100).toFixed(1)}%` : "—";
      const entries = [
        ["Accuracy", pct(m.accuracy)], ["Precision", pct(m.precision)], ["Recall", pct(m.recall)],
        ["F1", pct(m.f1)], ["ROC-AUC", pct(m.roc_auc)], ["False-positive rate", pct(m.false_positive_rate)],
        ["False-negative rate", pct(m.false_negative_rate)], ["Average latency", m.avg_latency_ms != null ? `${m.avg_latency_ms.toFixed(1)} ms` : "—"],
      ];
      const table = document.createElement("table"); table.className = "benchmark-table";
      entries.forEach(([label, value]) => { const tr=document.createElement("tr"); tr.append(cell(label),cell(value)); table.appendChild(tr); });
      els.benchmarkDetail.replaceChildren(table);
    } catch (error) {
      els.benchmarkDetail.textContent = `Could not load benchmark results: ${error.message}`;
    }
  }

  function pct(value) { return value == null ? "—" : `${(value * 100).toFixed(2)}%`; }

  function makeDemoFile() {
    // A small SVG is accepted by browsers but not by the scanner's upload allowlist,
    // so the demo instead sends users to the URL lab with a reserved .invalid domain.
    navigate("url");
    els.urlInput.value = "https://micros0ft-account-verify.example.invalid/login?continue=secure";
    els.contextInput.value = "Microsoft 365 security notice: your account expires today. Scan the QR code and verify your password immediately to avoid suspension.";
    toast("Demo loaded", "A safe reserved-domain example is ready in the URL laboratory.");
  }

  els.nav.forEach((item) => item.addEventListener("click", () => navigate(item.dataset.view)));
  els.chooseFileButton.addEventListener("click", () => els.fileInput.click());
  els.fileInput.addEventListener("change", () => scanFile(els.fileInput.files?.[0]));
  els.loadDemoButton.addEventListener("click", makeDemoFile);
  els.dropZone.addEventListener("dragover", (event) => { event.preventDefault(); els.dropZone.classList.add("dragging"); });
  els.dropZone.addEventListener("dragleave", () => els.dropZone.classList.remove("dragging"));
  els.dropZone.addEventListener("drop", (event) => { event.preventDefault(); els.dropZone.classList.remove("dragging"); scanFile(event.dataTransfer?.files?.[0]); });
  $("showAllEvidenceButton").addEventListener("click", () => els.evidenceModal.showModal());
  $("refreshHistoryButton").addEventListener("click", loadHistory);
  $("refreshBenchmarkButton").addEventListener("click", loadBenchmark);
  $("healthButton").addEventListener("click", () => checkHealth(true));
  els.familyModeButton.addEventListener("click", () => {
    state.familyMode = !state.familyMode;
    document.body.classList.toggle("family-mode", state.familyMode);
    els.familyModeButton.setAttribute("aria-pressed", String(state.familyMode));
    toast(state.familyMode ? "Simple view on" : "Technical view restored", state.familyMode ? "The main guidance is simplified; full evidence is still available." : "Technical details are visible again.");
  });
  els.urlForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = els.urlInput.value.trim();
    if (!url) return;
    const submit = els.urlForm.querySelector("button[type=submit]");
    submit.disabled = true; submit.textContent = "Analyzing…";
    try {
      const result = await api("/api/analyze-url", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ url, context: els.contextInput.value }) });
      renderUrlResult(result);
    } catch (error) {
      toast("URL analysis failed", error.message, "error");
    } finally {
      submit.disabled = false; submit.textContent = "Analyze URL";
    }
  });

  const requestedView = location.hash.replace("#", "");
  if (["scan", "url", "benchmark", "method"].includes(requestedView)) navigate(requestedView);
  checkHealth();
  loadHistory();
})();
