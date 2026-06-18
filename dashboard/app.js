function resolveDashboardApiUrl() {
  if (window.DASHBOARD_API_URL) {
    return window.DASHBOARD_API_URL;
  }

  return "/dashboard";
}

function resolveDashboardApiFallbackUrls() {
  if (window.DASHBOARD_API_URL) {
    return [window.DASHBOARD_API_URL];
  }

  const protocol = window.location.protocol === "file:" ? "http:" : window.location.protocol;
  const hostname = window.location.hostname || "127.0.0.1";
  const sameHostApiUrl = `${protocol}//${hostname}:8000/dashboard`;
  const localApiUrl = "http://127.0.0.1:8000/dashboard";

  return [
    DASHBOARD_API_URL,
    sameHostApiUrl,
    localApiUrl,
  ].filter((url, index, urls) => urls.indexOf(url) === index);
}

function resolveDashboardEventsFallbackUrls() {
  if (window.DASHBOARD_EVENTS_URL) {
    return [window.DASHBOARD_EVENTS_URL];
  }

  return DASHBOARD_API_FALLBACK_URLS.map((url) => `${url.replace(/\/dashboard$/, "")}/dashboard/events`);
}

const DASHBOARD_API_URL = resolveDashboardApiUrl();
const DASHBOARD_API_FALLBACK_URLS = resolveDashboardApiFallbackUrls();
const DASHBOARD_EVENTS_FALLBACK_URLS = resolveDashboardEventsFallbackUrls();
const SNAPSHOT_POLL_INTERVAL_MS = 5000;
const MAX_SYSTEM_POINTS = 20;
const MAX_LIVE_ATTACKS = 20;
const THEME_STORAGE_KEY = "ojs-dashboard-theme";

const THEME_PALETTES = {
  dark: {
    chartText: "#64748b",
    chartTick: "#475569",
    chartGrid: "rgba(148, 163, 184, 0.08)",
    chartGradientEnd: "rgba(11, 17, 32, 0)",
    chartBorder: "#0f1829",
  },
  light: {
    chartText: "#64748b",
    chartTick: "#475569",
    chartGrid: "rgba(15, 23, 42, 0.08)",
    chartGradientEnd: "rgba(248, 250, 252, 0)",
    chartBorder: "#ffffff",
  },
};

const state = {
  ramSamples: [],
  cpuSamples: [],
  timeLabels: [],
  liveAttacks: [],
  latestAttackId: 0,
  eventSource: null,
  eventSourceUrlIndex: 0,
  charts: {},
  theme: "dark",
};

const el = {
  themeToggle: document.getElementById("themeToggle"),
  lastUpdated: document.getElementById("lastUpdated"),
  attacks1Day: document.getElementById("attacks1Day"),
  attacks7Days: document.getElementById("attacks7Days"),
  attacks30Days: document.getElementById("attacks30Days"),
  attackRows: document.getElementById("attackRows"),
  attackTypeLegend: document.getElementById("attackTypeLegend"),
  countryList: document.getElementById("countryList"),
  ramCurrent: document.getElementById("ramCurrent"),
  cpuCurrent: document.getElementById("cpuCurrent"),
  databaseStatus: document.getElementById("databaseStatus"),
  modelStatus: document.getElementById("modelStatus"),
  alertChannelStatus: document.getElementById("alertChannelStatus"),
};

function getStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) || "dark";
  } catch (_error) {
    return "dark";
  }
}

function getThemePalette(theme = state.theme) {
  return THEME_PALETTES[theme] || THEME_PALETTES.dark;
}

function setChartDefaults(theme = state.theme) {
  const palette = getThemePalette(theme);

  Chart.defaults.color = palette.chartText;
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  Chart.defaults.plugins.legend.display = false;
}

function applyTheme(theme, persist = false) {
  const nextTheme = theme === "light" ? "light" : "dark";

  state.theme = nextTheme;
  document.body.dataset.theme = nextTheme;

  if (persist) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch (_error) {
      // Ignore storage failures; the toggle should still work for this page.
    }
  }

  if (el.themeToggle) {
    el.themeToggle.textContent = nextTheme === "light" ? "☀ Dark" : "☾ Light";
    el.themeToggle.setAttribute(
      "aria-label",
      nextTheme === "light" ? "Switch to dark mode" : "Switch to light mode",
    );
  }

  setChartDefaults(nextTheme);
  refreshChartTheme();
}

function refreshChartTheme() {
  const palette = getThemePalette();

  if (state.charts.attackType) {
    state.charts.attackType.data.datasets[0].borderColor = palette.chartBorder;
    state.charts.attackType.update("none");
  }

  for (const chart of [state.charts.ram, state.charts.cpu]) {
    if (!chart) {
      continue;
    }

    chart.options.scales.x.grid.color = palette.chartGrid;
    chart.options.scales.y.grid.color = palette.chartGrid;
    chart.options.scales.x.ticks.color = palette.chartTick;
    chart.options.scales.y.ticks.color = palette.chartTick;
    chart.data.datasets[0].backgroundColor = makeGradient(
      chart.ctx,
      String(chart.data.datasets[0].borderColor).replace("1)", "0.2)"),
    );
    chart.update("none");
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(Number(value || 0));
}

function formatTime(value) {
  if (!value) {
    return "-";
  }

  const normalized = String(value).replace(" ", "T");
  const date = new Date(normalized);

  if (Number.isNaN(date.getTime())) {
    return String(value).slice(11, 19) || String(value);
  }

  return date.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatProbability(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }

  const numeric = Number(value);

  if (Number.isNaN(numeric)) {
    return "-";
  }

  const percent = numeric > 1 ? numeric : numeric * 100;
  return `${percent.toFixed(percent >= 99.95 ? 1 : 1)}%`;
}

function probabilityNumber(value) {
  const numeric = Number(value);

  if (Number.isNaN(numeric)) {
    return 0;
  }

  return Math.max(0, Math.min(100, numeric > 1 ? numeric : numeric * 100));
}

function formatAttackMs(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }

  const numeric = Number(value);

  if (Number.isNaN(numeric)) {
    return "-";
  }

  return `${numeric.toFixed(2)} ms`;
}

function attackClass(type) {
  const normalized = String(type || "").toUpperCase();

  if (normalized.includes("XSS")) {
    return "xss";
  }

  if (
    normalized.includes("RCE")
    || normalized.includes("UPLOAD")
    || normalized.includes("COMMAND")
  ) {
    return "rce";
  }

  return "unknown";
}

function displayAttackType(type) {
  const normalized = String(type || "Unknown");
  const upper = normalized.toUpperCase();

  if (upper.includes("XSS")) {
    return "XSS";
  }

  if (
    upper.includes("RCE")
    || upper.includes("UPLOAD")
    || upper.includes("COMMAND")
  ) {
    return "RCE";
  }

  return normalized;
}

function makeGradient(ctx, color) {
  const palette = getThemePalette();
  const gradient = ctx.createLinearGradient(0, 0, 0, 130);
  gradient.addColorStop(0, color);
  gradient.addColorStop(1, palette.chartGradientEnd);
  return gradient;
}

function createLineChart(canvasId, lineColor) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext("2d");
  const palette = getThemePalette();

  return new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          data: [],
          borderColor: lineColor,
          backgroundColor: makeGradient(ctx, lineColor.replace("1)", "0.2)")),
          borderWidth: 2,
          tension: 0.35,
          pointRadius: 0,
          fill: true,
        },
      ],
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      resizeDelay: 200,
      scales: {
        x: {
          grid: {
            color: palette.chartGrid,
          },
          ticks: {
            color: palette.chartTick,
            maxTicksLimit: 8,
            font: {
              size: 9,
              family: "JetBrains Mono",
            },
          },
        },
        y: {
          min: 0,
          max: 100,
          grid: {
            color: palette.chartGrid,
          },
          ticks: {
            stepSize: 25,
            color: palette.chartTick,
            font: {
              size: 9,
              family: "JetBrains Mono",
            },
          },
        },
      },
    },
  });
}

function createCharts() {
  const palette = getThemePalette();

  state.charts.attackType = new Chart(
    document.getElementById("attackTypeChart"),
    {
      type: "doughnut",
      data: {
        labels: ["XSS", "RCE"],
        datasets: [
          {
            data: [0, 0],
            backgroundColor: ["#f97316", "#ef4444"],
            borderColor: palette.chartBorder,
            borderWidth: 8,
            hoverOffset: 0,
          },
        ],
      },
      options: {
        animation: false,
        cutout: "62%",
        responsive: true,
        maintainAspectRatio: false,
        resizeDelay: 200,
      },
    },
  );

  state.charts.ram = createLineChart("ramChart", "rgba(34, 211, 238, 1)");
  state.charts.cpu = createLineChart("cpuChart", "rgba(34, 197, 94, 1)");
}

function updateCounts(counts = {}) {
  el.attacks1Day.textContent = formatNumber(counts.attacks_1_day);
  el.attacks7Days.textContent = formatNumber(counts.attacks_7_days);
  el.attacks30Days.textContent = formatNumber(counts.attacks_30_days);
}

function normalizeAttack(attack = {}) {
  return {
    id: Number(attack.id || 0),
    detected_at: attack.detected_at || "",
    attacker_ip: attack.attacker_ip || "-",
    attacker_country: attack.attacker_country || "Unknown",
    attack_type: attack.attack_type || "Unknown",
    attack_ms: attack.attack_ms,
    probability: attack.probability,
    attack_url: attack.attack_url || "",
  };
}

function setLiveAttacks(attacks = []) {
  state.liveAttacks = attacks
    .map(normalizeAttack)
    .sort((a, b) => Number(b.id || 0) - Number(a.id || 0))
    .slice(0, MAX_LIVE_ATTACKS);

  state.latestAttackId = Math.max(
    state.latestAttackId,
    ...state.liveAttacks.map((attack) => Number(attack.id || 0)),
    0,
  );

  renderAttackRows(state.liveAttacks);
}

function prependLiveAttack(attack = {}) {
  const nextAttack = normalizeAttack(attack);

  if (!nextAttack.id) {
    return;
  }

  const existingIndex = state.liveAttacks.findIndex((item) => item.id === nextAttack.id);

  if (existingIndex !== -1) {
    state.liveAttacks.splice(existingIndex, 1);
  }

  state.liveAttacks.unshift(nextAttack);
  state.liveAttacks = state.liveAttacks.slice(0, MAX_LIVE_ATTACKS);
  state.latestAttackId = Math.max(state.latestAttackId, nextAttack.id);
  renderAttackRows(state.liveAttacks);
}

function renderAttackRows(attacks = []) {
  if (!attacks.length) {
    el.attackRows.innerHTML = `
      <tr>
        <td colspan="6" class="empty-row">No attack history found yet.</td>
      </tr>
    `;
    return;
  }

  el.attackRows.innerHTML = attacks
    .map((attack) => {
      const type = displayAttackType(attack.attack_type);
      const confidence = probabilityNumber(attack.probability);
      const attackUrl = attack.attack_url ? ` title="${escapeHtml(attack.attack_url)}"` : "";

      return `
        <tr${attackUrl}>
          <td class="time-cell">${escapeHtml(formatTime(attack.detected_at))}</td>
          <td>${escapeHtml(attack.attacker_ip || "-")}</td>
          <td>${escapeHtml(attack.attacker_country || "Unknown")}</td>
          <td>
            <span class="attack-badge ${attackClass(type)}">${escapeHtml(type)}</span>
          </td>
          <td>${escapeHtml(formatAttackMs(attack.attack_ms))}</td>
          <td>
            <div class="confidence">
              <div class="confidence-bar"><span style="width: ${confidence}%"></span></div>
              <span>${escapeHtml(formatProbability(attack.probability))}</span>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
}

function updateAttackTypeChart(attackTypes = []) {
  const totals = {
    XSS: 0,
    RCE: 0,
  };

  for (const item of attackTypes) {
    const type = displayAttackType(item.attack_type);
    if (type in totals) {
      totals[type] += Number(item.total || 0);
    }
  }

  const values = [totals.XSS, totals.RCE];
  const total = values.reduce((sum, value) => sum + value, 0);
  state.charts.attackType.data.datasets[0].data = total ? values : [1, 1];
  state.charts.attackType.update();

  el.attackTypeLegend.innerHTML = ["XSS", "RCE"]
    .map((type, index) => {
      const colors = ["#f97316", "#ef4444"];
      const pct = total ? Math.round((values[index] / total) * 100) : 0;

      return `
        <div class="legend-item">
          <span class="legend-dot" style="background:${colors[index]}"></span>
          <span class="legend-label">${type}</span>
          <span class="legend-value" style="color:${colors[index]}">${pct}%</span>
        </div>
      `;
    })
    .join("");
}

function renderTopCountries(countries = []) {
  if (!countries.length) {
    el.countryList.innerHTML = `<div class="empty-row">No country data.</div>`;
    return;
  }

  const maxTotal = Math.max(...countries.map((item) => Number(item.total || 0)), 1);

  el.countryList.innerHTML = countries
    .slice(0, 5)
    .map((item) => {
      const total = Number(item.total || 0);
      const width = Math.max(3, Math.round((total / maxTotal) * 100));

      return `
        <div class="country-row">
          <div class="country-name">${escapeHtml(item.country || "Unknown")}</div>
          <div class="country-total">${formatNumber(total)}</div>
          <div class="country-bar"><span style="width: ${width}%"></span></div>
        </div>
      `;
    })
    .join("");
}

function updateSystemCharts(system = {}) {
  const ram = Number(system.ram_percent || 0);
  const cpu = Number(system.cpu_percent || 0);
  const now = new Date().toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  state.ramSamples.push(ram);
  state.cpuSamples.push(cpu);
  state.timeLabels.push(now);

  while (state.ramSamples.length > MAX_SYSTEM_POINTS) {
    state.ramSamples.shift();
    state.cpuSamples.shift();
    state.timeLabels.shift();
  }

  el.ramCurrent.textContent = `${ram.toFixed(1)}%`;
  el.cpuCurrent.textContent = `${cpu.toFixed(1)}%`;

  state.charts.ram.data.labels = state.timeLabels;
  state.charts.ram.data.datasets[0].data = state.ramSamples;
  state.charts.ram.update();

  state.charts.cpu.data.labels = state.timeLabels;
  state.charts.cpu.data.datasets[0].data = state.cpuSamples;
  state.charts.cpu.update();
}

function updateSystemStatus(status = {}) {
  const modelName = status.model_name || "Unavailable";
  const subscriptionLabel = status.telegram_subscription_label || "0/0 subscribed";

  if (el.modelStatus) {
    el.modelStatus.textContent = modelName;
    el.modelStatus.title = modelName;
  }

  if (el.alertChannelStatus) {
    el.alertChannelStatus.textContent = subscriptionLabel;
    el.alertChannelStatus.title = `${status.alert_channel || "Telegram"}: ${subscriptionLabel}`;
  }
}

function updateLastUpdated() {
  el.lastUpdated.textContent = new Date().toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

async function loadDashboard() {
  try {
    let data = null;
    let lastError = null;

    for (const apiUrl of DASHBOARD_API_FALLBACK_URLS) {
      try {
        const response = await fetch(apiUrl, {
          cache: "no-store",
        });

        if (!response.ok) {
          throw new Error(`Dashboard API returned ${response.status}`);
        }

        data = await response.json();
        break;
      } catch (error) {
        lastError = error;
      }
    }

    if (!data) {
      throw lastError || new Error("Dashboard API unavailable");
    }

    updateCounts(data.counts || {});
    setLiveAttacks(data.live_attacks || []);
    updateAttackTypeChart(data.attack_types || []);
    renderTopCountries(data.top_countries || []);
    updateSystemCharts(data.system || {});
    updateSystemStatus(data.system_status || {});
    updateLastUpdated();
    el.databaseStatus.textContent = "Connected";
    return data;
  } catch (error) {
    console.error(error);
    el.databaseStatus.textContent = "Unavailable";
    updateSystemStatus({
      model_name: "Unavailable",
      telegram_subscription_label: "Unavailable",
    });
    return null;
  }
}

function buildEventsUrl(baseUrl) {
  if (!state.latestAttackId) {
    return baseUrl;
  }

  const separator = baseUrl.includes("?") ? "&" : "?";
  return `${baseUrl}${separator}after_id=${encodeURIComponent(state.latestAttackId)}`;
}

function connectDashboardEvents() {
  if (!("EventSource" in window) || state.eventSource) {
    return;
  }

  const baseUrl = DASHBOARD_EVENTS_FALLBACK_URLS[state.eventSourceUrlIndex];

  if (!baseUrl) {
    return;
  }

  const source = new EventSource(buildEventsUrl(baseUrl));
  state.eventSource = source;

  source.addEventListener("open", () => {
    el.databaseStatus.textContent = "Connected";
  });

  source.addEventListener("attack", (event) => {
    try {
      prependLiveAttack(JSON.parse(event.data));
      updateLastUpdated();
      el.databaseStatus.textContent = "Connected";
    } catch (error) {
      console.error(error);
    }
  });

  source.addEventListener("error", () => {
    source.close();
    state.eventSource = null;
    state.eventSourceUrlIndex = (
      state.eventSourceUrlIndex + 1
    ) % DASHBOARD_EVENTS_FALLBACK_URLS.length;
    el.databaseStatus.textContent = "Reconnecting";
    window.setTimeout(connectDashboardEvents, 3000);
  });
}

applyTheme(getStoredTheme());

if (el.themeToggle) {
  el.themeToggle.addEventListener("click", () => {
    applyTheme(state.theme === "light" ? "dark" : "light", true);
  });
}

createCharts();
loadDashboard().finally(connectDashboardEvents);
setInterval(loadDashboard, SNAPSHOT_POLL_INTERVAL_MS);
