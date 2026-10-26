// ModScan front end. Everything in a report can come from a malicious file, so it is only ever
// inserted with textContent (via h()), never as HTML, and addresses are never made clickable.
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const KEY_STORAGE = "modscan:anthropic-key";
  const ADVICE = {
    likely_malicious: "Don't run this file. It contains patterns strongly associated with malware.",
    suspicious: "Be careful. This file does things mods rarely need. Only run it if you trust where it came from.",
    no_known_threats: "That's a good sign, but no scanner can prove a file is safe. Only run mods from sources you " +
      "trust.",
  };
  let currentReport = null;

  function h(tag, props = {}, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") el.className = value;
      else el.setAttribute(key, value);
    }
    el.append(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
    return el;
  }

  function formatSize(bytes) {
    return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
  }

  function errorFrom(data, fallback) {
    return typeof data.detail === "string" ? data.detail : fallback;
  }

  function setStatus(el, message, isError = false) {
    el.textContent = message;
    el.classList.toggle("error", isError);
    el.hidden = !message;
  }

  // --- Upload -------------------------------------------------------------------

  const dropzone = $("dropzone");
  const uploadStatus = $("upload-status");

  async function scanFile(file) {
    if (!file) return;
    if (file.size > 64 * 1048576) {
      setStatus(uploadStatus, "That file is too large. The limit is 64 MB.", true);
      return;
    }
    dropzone.classList.add("busy");
    setStatus(uploadStatus, `Scanning ${file.name}…`);
    try {
      const response = await fetch(`/api/scan?filename=${encodeURIComponent(file.name)}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(errorFrom(data, "The scan failed. Please try again."));
      setStatus(uploadStatus, "");
      showReport(data);
    } catch (error) {
      setStatus(uploadStatus, error.message, true);
    } finally {
      dropzone.classList.remove("busy");
      $("file-input").value = "";
    }
  }

  $("file-input").addEventListener("change", (event) => scanFile(event.target.files[0]));
  for (const type of ["dragenter", "dragover"]) {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.add("dragging");
    });
  }
  for (const type of ["dragleave", "drop"]) {
    dropzone.addEventListener(type, () => dropzone.classList.remove("dragging"));
  }
  dropzone.addEventListener("drop", (event) => {
    event.preventDefault();
    scanFile(event.dataTransfer.files[0]);
  });

  // --- Report -------------------------------------------------------------------

  function detailRows(pairs) {
    return pairs.filter(([, value]) => value).flatMap(([label, value, mono]) => [
      h("dt", {}, label),
      h("dd", { class: mono ? "mono" : null }, value),
    ]);
  }

  function attackLink(id, name) {
    if (!id || !/^T\d{4}(\.\d{3})?$/.test(id)) return null;
    const href = `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
    return h("a", { class: "attack", href, target: "_blank", rel: "noopener noreferrer" }, `MITRE ATT&CK ${id}: ${name}`);
  }

  function findingCard(finding) {
    const serious = ["critical", "high"].includes(finding.severity);
    const evidence = h("ul", { class: "evidence mono" }, finding.evidence.map((e) =>
      h("li", {}, e.text, e.location ? h("span", { class: "where" }, `in ${e.location}`) : null)));
    const more = finding.evidence_total > finding.evidence.length
      ? h("div", { class: "more" }, `…and ${finding.evidence_total - finding.evidence.length} more`) : null;
    return h("details", { class: "finding", open: serious || null },
      h("summary", {}, h("span", { class: `sev ${finding.severity}` }, finding.severity), finding.title),
      h("div", { class: "finding-body" }, h("p", {}, finding.description), attackLink(finding.attack_id, finding.attack_name),
        evidence, more));
  }

  function showReport(report) {
    currentReport = report;
    $("upload-view").hidden = true;
    $("report-view").hidden = false;
    window.scrollTo({ top: 0 });

    $("verdict").className = `verdict ${report.verdict}`;
    $("verdict-label").textContent = report.verdict_label;
    $("verdict-advice").textContent = ADVICE[report.verdict] || "";
    $("score-value").textContent = report.score;
    $("score-bar").style.width = `${Math.min(100, Math.max(2, report.score))}%`;

    $("file-details").replaceChildren(...detailRows([
      ["Name", report.file_name],
      ["Type", report.file_type],
      ["Size", formatSize(report.file_size)],
      ["Contents", `${report.stats.files.toLocaleString()} files, ${report.stats.classes.toLocaleString()} classes`],
      ["SHA-256", report.sha256, true],
    ]));
    $("virustotal").href = `https://www.virustotal.com/gui/file/${encodeURIComponent(report.sha256)}`;

    const mod = report.mods[0];
    $("mod-card").hidden = !mod;
    if (mod) {
      $("mod-details").replaceChildren(...detailRows([
        ["Loader", mod.loader],
        ["Name", mod.name || mod.id],
        ["Version", mod.version],
        ["Authors", mod.authors.join(", ")],
        ["Description", mod.description],
      ]));
    }

    $("findings").replaceChildren(...(report.findings.length
      ? report.findings.map(findingCard)
      : [h("p", { class: "empty" }, "Nothing matched any rule.")]));

    const addresses = [
      ...report.urls.map((u) => h("li", {}, h("span", { class: "mono" }, u.url), h("span", { class: "where" }, `  in ${u.location}`))),
      ...report.ips.map((i) => h("li", {}, h("span", { class: "mono" }, i.ip), h("span", { class: "where" }, `  in ${i.location}`))),
    ];
    $("addresses-card").hidden = addresses.length === 0;
    $("addresses").replaceChildren(...addresses);

    $("notes-card").hidden = report.notes.length === 0;
    $("notes").replaceChildren(...report.notes.map((n) => h("li", {}, n)));

    $("ai-result").hidden = true;
    setStatus($("ai-status"), "");
  }

  $("scan-another").addEventListener("click", () => {
    currentReport = null;
    $("report-view").hidden = true;
    $("upload-view").hidden = false;
    $("file-input").focus();
  });

  $("download-json").addEventListener("click", () => {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
    const link = h("a", { href: URL.createObjectURL(blob), download: `${currentReport.sha256.slice(0, 12)}-modscan.json` });
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });

  // --- Claude explanation (bring your own key) ------------------------------------

  // The key lives in this page's memory. It's kept in sessionStorage (cleared when the tab closes)
  // only if the user ticks the box, and never in localStorage.
  function savedKey() {
    try {
      return sessionStorage.getItem(KEY_STORAGE) || "";
    } catch {
      return "";
    }
  }
  function rememberKey(key) {
    try {
      if (key) sessionStorage.setItem(KEY_STORAGE, key);
      else sessionStorage.removeItem(KEY_STORAGE);
    } catch {
      /* storage unavailable: the key just isn't remembered */
    }
  }

  const initialKey = savedKey();
  $("api-key").value = initialKey;
  $("remember-key").checked = Boolean(initialKey);
  $("remember-key").addEventListener("change", (event) => {
    rememberKey(event.target.checked ? $("api-key").value.trim() : "");
  });

  $("ai-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!currentReport) return;
    const key = $("api-key").value.trim();
    const status = $("ai-status");
    const button = $("ai-button");
    rememberKey($("remember-key").checked ? key : "");
    button.disabled = true;
    setStatus(status, "Asking Claude…");
    try {
      const response = await fetch("/api/summary", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Anthropic-Key": key },
        body: JSON.stringify(currentReport),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(errorFrom(data, "Couldn't get an explanation. Please try again."));
      $("ai-text").replaceChildren(...data.summary.split(/\n{2,}/).map((p) => h("p", {}, p.trim())));
      $("ai-result").hidden = false;
      setStatus(status, "");
    } catch (error) {
      setStatus(status, error.message, true);
    } finally {
      button.disabled = false;
    }
  });
})();
