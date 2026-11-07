(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const token = window.__SCAN_TOKEN__;
  let state = { status: "idle", results: [], completed: 0, total: 0, online: 0, openPorts: 0, elapsed: 0 };
  let pollTimer = null;
  let toastTimer = null;
  let lastResultSignature = "";
  let historyRecords = [];
  let currentView = "dashboard";

  // While a scan runs the page refreshes often so the table feels alive; when
  // it is idle a slow heartbeat keeps the page in sync with changes that were
  // triggered elsewhere (a second window, the API, a restarted service).
  const POLL_ACTIVE = 400;
  const POLL_IDLE = 2000;
  const POLL_RETRY = 3000;

  const elements = {
    form: $("#scanForm"), start: $("#startButton"), stop: $("#stopButton"),
    body: $("#resultsBody"), empty: $("#emptyState"), noMatches: $("#noMatches"),
    search: $("#searchInput"), filter: $("#resultFilter"), export: $("#exportButton")
  };

  function syncThemeButton() {
    const isDark = document.documentElement.dataset.theme === "dark";
    const label = isDark ? "切换到日间模式" : "切换到夜间模式";
    const button = $("#themeToggle");
    button.setAttribute("aria-label", label);
    button.setAttribute("aria-pressed", String(isDark));
    button.title = label;
    button.querySelector("use").setAttribute("href", isDark ? "#i-sun" : "#i-moon");
  }

  function setTheme(theme, remember = false) {
    document.documentElement.dataset.theme = theme;
    if (remember) localStorage.setItem("netscope-theme", theme);
    syncThemeButton();
  }

  $("#themeToggle").addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark", true);
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", event => {
    if (!localStorage.getItem("netscope-theme")) setTheme(event.matches ? "dark" : "light");
  });
  syncThemeButton();

  if (window.__UI_MODE__ === "browser") {
    const shutdownButton = $("#shutdownButton");
    shutdownButton.hidden = false;
    shutdownButton.addEventListener("click", async () => {
      if (!window.confirm("确定要退出 NetScope 吗？退出后本地扫描服务会停止。")) return;
      clearTimeout(pollTimer);
      pollTimer = null;
      shutdownButton.disabled = true;
      shutdownButton.querySelector("span").textContent = "正在退出…";
      try {
        await request("/api/shutdown", { method: "POST", body: "{}" });
        document.body.innerHTML = `<main class="shutdown-screen"><div><h1>NetScope 已退出</h1><p>本地服务已停止，可以关闭这个页面。</p></div></main>`;
      } catch (error) {
        shutdownButton.disabled = false;
        shutdownButton.querySelector("span").textContent = "退出程序";
        toast(error.message, true);
      }
    });
  }

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
  }

  async function request(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { "Content-Type": "application/json", "X-NetScope-Token": token, ...(options.headers || {}) }
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `请求失败 (${response.status})`);
    return data;
  }

  function toast(message, isError = false) {
    const box = $("#toast");
    box.querySelector("span").textContent = message;
    box.classList.toggle("error", isError);
    box.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => box.classList.remove("show"), 3200);
  }

  async function saveCSV(recordId = null) {
    const api = window.pywebview?.api;
    if (window.__UI_MODE__ !== "desktop" || typeof api?.save_csv !== "function") {
      window.location.href = recordId
        ? `/api/history/export?id=${encodeURIComponent(recordId)}&token=${encodeURIComponent(token)}`
        : `/api/export?token=${encodeURIComponent(token)}`;
      return;
    }
    try {
      const result = await api.save_csv(recordId || "");
      if (!result || result.cancelled) return;
      if (result.error) { toast(result.error, true); return; }
      toast(`CSV 已保存：${result.path}`);
    } catch (error) {
      toast(error?.message || "保存 CSV 失败", true);
    }
  }

  function statusLabel(status) {
    return ({ idle: "等待开始", running: "扫描中", stopping: "正在停止", completed: "已完成", stopped: "已停止", error: "出错了" })[status] || status;
  }

  function formatHistoryTime(timestamp) {
    if (!timestamp) return "—";
    return new Date(timestamp * 1000).toLocaleString("zh-CN", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
    }).replaceAll("/", "-");
  }

  function renderHistory() {
    const query = $("#historySearch").value.trim().toLowerCase();
    const records = historyRecords.filter(record => !query || record.targetSpec.toLowerCase().includes(query));
    $("#historyBadge").textContent = `${historyRecords.length} 条记录`;
    $("#clearHistoryButton").disabled = historyRecords.length === 0;
    $("#historyBody").innerHTML = records.map(record => `<tr data-record-row="${record.id}" tabindex="0" role="button" aria-label="查看 ${escapeHTML(record.targetSpec)} 的扫描详情">
      <td class="history-time">${formatHistoryTime(record.finishedAt)}</td>
      <td class="history-target" title="${escapeHTML(record.targetSpec)}">${escapeHTML(record.targetSpec)}</td>
      <td><span class="scan-status ${escapeHTML(record.status)}">${statusLabel(record.status)}</span></td>
      <td>${record.completed} / ${record.total}</td>
      <td class="history-number ${record.online ? "has-devices" : ""}">${record.online}</td>
      <td class="history-number">${record.openPorts}</td>
      <td>${Number(record.elapsed).toFixed(1)}s</td>
      <td><div class="history-actions"><button class="history-action" data-view-record="${record.id}">查看详情</button><button class="history-delete" data-delete-record="${record.id}" aria-label="删除这条记录"><svg><use href="#i-trash"/></svg></button></div></td>
    </tr>`).join("");
    $("#historyEmpty").hidden = historyRecords.length > 0;
    $("#historyNoMatches").hidden = !historyRecords.length || records.length > 0;
    $("#historySummary").textContent = historyRecords.length ? `显示 ${records.length} 条，共 ${historyRecords.length} 条记录` : "记录仅保存在当前设备";
  }

  async function loadHistory() {
    historyRecords = await request("/api/history");
    renderHistory();
  }

  function showView(view, updateHash = true) {
    currentView = view === "history" ? "history" : "dashboard";
    $("#dashboardView").hidden = currentView !== "dashboard";
    $("#historyView").hidden = currentView !== "history";
    $$('[data-view]').forEach(item => {
      const active = item.dataset.view === currentView;
      item.classList.toggle("active", active);
      if (active) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
    const historyActive = currentView === "history";
    $("#pageTitle").textContent = historyActive ? "扫描历史" : "网络扫描";
    $("#breadcrumbCurrent").textContent = historyActive ? "扫描历史" : "扫描控制台";
    if (updateHash) window.history.replaceState(null, "", historyActive ? "#history" : "#dashboard");
    if (historyActive) loadHistory().catch(error => toast(error.message, true));
  }

  function openHistoryRecord(record) {
    $("#recordTitle").textContent = record.targetSpec;
    const resultRows = record.results.map(item => {
      const ports = item.ports.slice(0, 6).map(port => `<span class="port-badge" title="${escapeHTML(port.service)}">${port.port}</span>`).join("") + (item.ports.length > 6 ? `<span class="port-badge">+${item.ports.length - 6}</span>` : "");
      return `<tr><td class="ip-cell">${escapeHTML(item.ip)}</td><td class="hostname-cell" title="${escapeHTML(item.hostname)}">${escapeHTML(item.hostname || "—")}</td><td><span class="device-type ${item.deviceType === "未知设备" || !item.deviceType ? "unknown" : ""}" title="${escapeHTML(item.deviceType || "未知设备")}">${escapeHTML(item.deviceType || "未知设备")}</span></td><td class="mac-cell" title="${escapeHTML(item.mac || "未获取到 MAC 地址")}">${escapeHTML(item.mac || "—")}</td><td>${item.ports.length ? `<div class="port-list">${ports}</div>` : '<span class="no-port">未发现开放端口</span>'}</td></tr>`;
    }).join("");
    $("#recordContent").innerHTML = `${record.error ? `<div class="record-error">${escapeHTML(record.error)}</div>` : ""}
      <div class="record-meta"><div class="detail-item"><span>状态</span><strong>${statusLabel(record.status)}</strong></div><div class="detail-item"><span>扫描地址</span><strong>${record.completed} / ${record.total}</strong></div><div class="detail-item"><span>在线设备</span><strong>${record.online}</strong></div><div class="detail-item"><span>开放端口</span><strong>${record.openPorts}</strong></div></div>
      <div class="record-section-title"><h4>当时发现的设备</h4><span>扫描端口：${record.ports.slice(0, 12).join(", ")}${record.ports.length > 12 ? ` 等 ${record.ports.length} 个` : ""}</span></div>
      ${record.results.length ? `<div class="record-results"><table><thead><tr><th>IP 地址</th><th>主机名</th><th>设备类型</th><th>MAC 地址</th><th>开放端口</th></tr></thead><tbody>${resultRows}</tbody></table></div>` : '<div class="modal-note">这次扫描未发现在线设备。</div>'}
      <div class="record-footer"><span>${formatHistoryTime(record.finishedAt)} · 用时 ${Number(record.elapsed).toFixed(1)} 秒</span><button id="exportRecord" class="secondary-button" ${record.results.length ? "" : "disabled"}><svg><use href="#i-download"/></svg>导出此次结果</button></div>`;
    $("#recordModal").showModal();
    $("#exportRecord").addEventListener("click", () => saveCSV(record.id));
  }

  function setRunning(running) {
    elements.start.hidden = running;
    elements.stop.hidden = !running;
    $$("#scanForm input, #scanForm .preset, #scanForm summary").forEach(control => {
      if (control.tagName === "SUMMARY") control.style.pointerEvents = running ? "none" : "";
      else control.disabled = running;
    });
  }

  function updateStats() {
    const progress = state.total ? Math.min(100, Math.round(state.completed / state.total * 100)) : 0;
    $("#progressValue").innerHTML = `${progress}<span>%</span>`;
    $("#progressCount").textContent = `${state.completed} / ${state.total}`;
    $("#miniProgress").style.width = `${progress}%`;
    $("#onlineCount").textContent = state.online;
    $("#portCount").textContent = state.openPorts;
    $("#elapsed").innerHTML = `${Number(state.elapsed).toFixed(1)}<span>s</span>`;
    const badge = $("#scanState");
    badge.textContent = statusLabel(state.status);
    badge.classList.toggle("running", ["running", "stopping"].includes(state.status));
  }

  function filteredResults() {
    const query = elements.search.value.trim().toLowerCase();
    const filter = elements.filter.value;
    return state.results.filter(item => {
      const matchesQuery = !query || item.ip.includes(query) || (item.hostname || "").toLowerCase().includes(query) || (item.mac || "").toLowerCase().includes(query) || (item.deviceType || "").toLowerCase().includes(query) || item.ports.some(port => String(port.port).includes(query));
      const matchesFilter = filter === "all" || (filter === "ports" ? item.ports.length > 0 : item.ports.length === 0);
      return matchesQuery && matchesFilter;
    });
  }

  function renderResults(force = false) {
    const signature = JSON.stringify([state.results, state.completed, state.status, elements.search.value, elements.filter.value]);
    if (!force && signature === lastResultSignature) return;
    lastResultSignature = signature;
    const rows = filteredResults();
    $("#resultBadge").textContent = `${state.results.length} 台设备`;
    elements.export.disabled = state.results.length === 0;
    elements.body.innerHTML = rows.map(item => {
      const ports = item.ports.slice(0, 4).map(port => `<span class="port-badge">${port.port}</span>`).join("") + (item.ports.length > 4 ? `<span class="port-badge">+${item.ports.length - 4}</span>` : "");
      const services = [...new Set(item.ports.map(port => port.service))].slice(0, 2).join(", ");
      return `<tr>
        <td><span class="host-status"><i></i>在线</span></td>
        <td class="ip-cell">${escapeHTML(item.ip)}</td>
        <td class="hostname-cell" title="${escapeHTML(item.hostname)}">${escapeHTML(item.hostname || "—")}</td>
        <td><span class="device-type ${item.deviceType === "未知设备" || !item.deviceType ? "unknown" : ""}" title="${escapeHTML(item.deviceType || "未知设备")}">${escapeHTML(item.deviceType || "未知设备")}</span></td>
        <td class="mac-cell" title="${escapeHTML(item.mac || "未获取到 MAC 地址")}">${escapeHTML(item.mac || "—")}</td>
        <td>${item.ports.length ? `<div class="port-list">${ports}</div>` : '<span class="no-port">未发现开放端口</span>'}</td>
        <td class="service-cell" title="${escapeHTML(services)}">${escapeHTML(services || "—")}</td>
        <td><button class="row-button" data-ip="${item.ip}" aria-label="查看 ${item.ip} 详情"><svg><use href="#i-chevron"/></svg></button></td>
      </tr>`;
    }).join("");
    const hasAny = state.results.length > 0;
    elements.empty.hidden = hasAny;
    elements.noMatches.hidden = !hasAny || rows.length > 0;
    if (!hasAny) {
      const running = ["running", "stopping"].includes(state.status);
      const finished = ["completed", "stopped", "error"].includes(state.status);
      $("#emptyTitle").textContent = running ? "正在聆听网络…" : finished ? "未发现在线设备" : "准备探索你的网络";
      $("#emptyText").textContent = running ? `已检查 ${state.completed} / ${state.total} 个地址，发现设备后会立即显示。` : finished ? "目标没有响应，可尝试增加超时时间或检查目标范围。" : "设置目标网段并开始扫描，发现的在线设备将显示在这里。";
    }
    $("#tableSummary").textContent = hasAny ? `显示 ${rows.length} 台，共发现 ${state.results.length} 台在线设备` : state.total ? `已检查 ${state.completed} / ${state.total} 个地址` : "尚未开始扫描";
  }

  function applyState(next) {
    const previousStatus = state.status;
    state = next;
    updateStats();
    renderResults();
    const active = ["running", "stopping"].includes(state.status);
    setRunning(active);
    elements.stop.disabled = state.status === "stopping";
    schedulePoll(active ? POLL_ACTIVE : POLL_IDLE);
    if (previousStatus !== state.status) {
      if (state.status === "completed") toast(`扫描完成，发现 ${state.online} 台在线设备`);
      if (state.status === "stopped") toast("扫描已停止，已保留当前结果");
      if (state.status === "error") toast(state.error || "扫描失败", true);
      if (["completed", "stopped", "error"].includes(state.status) && currentView === "history") {
        setTimeout(() => loadHistory().catch(error => toast(error.message, true)), 350);
      }
    }
  }

  function schedulePoll(delay) {
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
    pollTimer = setTimeout(async () => {
      pollTimer = null;
      await refreshState();
    }, delay);
  }

  async function refreshState() {
    try {
      const next = await request("/api/state");
      applyState(next);
    }
    catch (error) {
      // Keep retrying: the service may come back, and a dead page is worse
      // than a slow one.
      $(".connection").innerHTML = "<i style='background:#df7373'></i> 本地服务连接中断";
      toast(error.message, true);
      schedulePoll(POLL_RETRY);
    }
  }

  elements.form.addEventListener("submit", async event => {
    event.preventDefault();
    if (["running", "stopping"].includes(state.status)) return;
    const payload = {
      targets: $("#targets").value.trim(), ports: $("#ports").value.trim(),
      timeout: Number($("#timeout").value), concurrency: Number($("#concurrency").value),
      scanPorts: $("#scanPorts").checked, resolveNames: $("#resolveNames").checked
    };
    elements.start.disabled = true;
    elements.start.querySelector("span").textContent = "正在启动…";
    try {
      lastResultSignature = "";
      applyState(await request("/api/scan", { method: "POST", body: JSON.stringify(payload) }));
      toast("扫描任务已启动");
    } catch (error) { toast(error.message, true); }
    finally {
      elements.start.disabled = false;
      elements.start.querySelector("span").textContent = "开始扫描";
    }
  });

  elements.stop.addEventListener("click", async () => {
    elements.stop.disabled = true;
    try {
      applyState(await request("/api/stop", { method: "POST", body: "{}" }));
      toast("正在停止扫描…");
    } catch (error) { toast(error.message, true); elements.stop.disabled = false; }
  });

  $$(".preset").forEach(button => button.addEventListener("click", () => {
    $("#ports").value = button.dataset.ports;
    $$(".preset").forEach(item => item.classList.toggle("selected", item === button));
  }));
  $("#ports").addEventListener("input", () => $$(".preset").forEach(item => item.classList.toggle("selected", item.dataset.ports === $("#ports").value)));
  elements.search.addEventListener("input", () => renderResults(true));
  elements.filter.addEventListener("change", () => renderResults(true));
  elements.export.addEventListener("click", () => saveCSV());

  $$('[data-view]').forEach(item => item.addEventListener("click", event => {
    event.preventDefault();
    showView(item.dataset.view);
  }));
  [$("#newScanButton"), $("#emptyNewScan")].forEach(button => button.addEventListener("click", () => {
    showView("dashboard");
    $("#targets").focus();
  }));
  $("#historySearch").addEventListener("input", renderHistory);
  $("#clearHistoryButton").addEventListener("click", async () => {
    if (!historyRecords.length || !window.confirm(`确定清空全部 ${historyRecords.length} 条扫描记录吗？此操作无法撤销。`)) return;
    try {
      const response = await request("/api/history/clear", { method: "POST", body: "{}" });
      historyRecords = response.records;
      renderHistory();
      toast("扫描历史已清空");
    } catch (error) { toast(error.message, true); }
  });
  $("#historyBody").addEventListener("click", async event => {
    const viewButton = event.target.closest("[data-view-record]");
    const deleteButton = event.target.closest("[data-delete-record]");
    const row = event.target.closest("[data-record-row]");
    const trigger = viewButton || row;
    try {
      if (deleteButton) {
        if (!window.confirm("确定删除这条扫描记录吗？")) return;
        const response = await request("/api/history/delete", { method: "POST", body: JSON.stringify({ id: deleteButton.dataset.deleteRecord }) });
        historyRecords = response.records;
        renderHistory();
        toast("记录已删除");
      } else if (trigger && !trigger.dataset.loading) {
        trigger.dataset.loading = "true";
        if (viewButton) viewButton.disabled = true;
        const id = viewButton ? viewButton.dataset.viewRecord : row.dataset.recordRow;
        try {
          const record = await request(`/api/history/${encodeURIComponent(id)}`);
          openHistoryRecord(record);
        } finally {
          delete trigger.dataset.loading;
          if (viewButton) viewButton.disabled = false;
        }
      }
    } catch (error) { toast(error.message, true); }
  });
  $("#historyBody").addEventListener("keydown", event => {
    const row = event.target.closest("[data-record-row]");
    if (row && event.target === row && ["Enter", " "].includes(event.key)) {
      event.preventDefault();
      row.querySelector("[data-view-record]").click();
    }
  });
  $("#closeRecord").addEventListener("click", () => $("#recordModal").close());

  elements.body.addEventListener("click", event => {
    const button = event.target.closest("[data-ip]");
    if (!button) return;
    const item = state.results.find(result => result.ip === button.dataset.ip);
    if (!item) return;
    $("#detailIp").textContent = item.ip;
    $("#detailContent").innerHTML = `<div class="detail-grid">
      <div class="detail-item"><span>主机名</span><strong>${escapeHTML(item.hostname || "未解析")}</strong></div>
      <div class="detail-item"><span>设备类型</span><strong>${escapeHTML(item.deviceType || "未知设备")}</strong></div>
      <div class="detail-item"><span>MAC 地址</span><strong class="detail-mac">${escapeHTML(item.mac || "未获取到")}</strong></div>
      <div class="detail-item"><span>开放端口</span><strong>${item.ports.length} 个</strong></div>
    </div><span class="eyebrow">端口与服务</span><div class="detail-ports" style="margin-top:10px">${item.ports.length ? item.ports.map(port => `<div class="detail-port"><strong>${port.port}/tcp</strong><span>${escapeHTML(port.service)}</span></div>`).join("") : '<p class="modal-note">本次未发现开放端口。设备在线不代表其所有服务均对外开放。</p>'}</div>
    <div class="detail-actions"><button id="copyIp"><svg><use href="#i-copy"/></svg>复制 IP 地址</button></div>`;
    $("#detailModal").showModal();
    $("#copyIp").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(item.ip); toast("IP 地址已复制"); }
      catch { toast("无法访问剪贴板，请手动复制", true); }
    });
  });
  $(".close-detail").addEventListener("click", () => $("#detailModal").close());

  const modalContent = {
    guide: `<h3>三步开始扫描</h3><p>NetScope 通过系统 Ping 和 TCP 连接发现设备，无需安装额外驱动。</p><ol class="guide-list"><li><strong>设置扫描目标</strong>输入网段（192.168.1.0/24）、单个 IP，或地址范围（192.168.1.1-50）。</li><li><strong>选择端口与性能</strong>从常用预设开始。网络较慢时可增加超时；主机名解析会略微延长扫描。</li><li><strong>查看并导出结果</strong>在线设备实时显示，点击行尾箭头查看详情，或导出 CSV 进一步分析。</li></ol><div class="modal-note">单次最多扫描 1024 个地址、1024 个端口。请仅扫描你拥有或明确获授权的网络；端口开放情况也可能受防火墙影响。</div>`,
    about: `<h3>关于 NetScope</h3><p>一个轻量、私密的本地网络可见性工具。界面与扫描引擎都在你的设备上运行，不依赖云端服务。</p><ol class="guide-list"><li><strong>双重主机发现</strong>优先使用 ICMP Ping，再通过常用 TCP 端口补充探测。</li><li><strong>并发 TCP 检测</strong>使用标准 TCP Connect 判断端口是否可连接，不发送漏洞利用或认证请求。</li><li><strong>本地隐私保护</strong>服务仅绑定 127.0.0.1，写操作带有随机会话令牌，结果不上传。</li></ol><div class="modal-note">NetScope v1.0.0 · Python 标准库 · IPv4</div>`
  };
  $$('[data-modal]').forEach(button => button.addEventListener("click", () => {
    $("#modalContent").innerHTML = modalContent[button.dataset.modal];
    $("#infoModal").showModal();
  }));
  $("#closeModal").addEventListener("click", () => $("#infoModal").close());
  $$('dialog').forEach(dialog => dialog.addEventListener("click", event => {
    if (event.target === dialog) {
      const box = dialog.getBoundingClientRect();
      if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) dialog.close();
    }
  }));

  async function init() {
    try {
      const network = await request("/api/network");
      $("#localNetwork").textContent = network.network;
      $("#targets").value = network.network;
      $("#targets").title = `本机 ${network.hostname} · ${network.address}`;
    } catch {
      $("#localNetwork").textContent = "未检测到网络";
      $("#targets").value = "127.0.0.1";
    }
    await refreshState();
    showView(window.location.hash === "#history" ? "history" : "dashboard", false);
  }
  init();
})();
