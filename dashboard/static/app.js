const socket = io();

const el = (id) => document.getElementById(id);
const alertsBody = document.querySelector("#alerts-table tbody");
const rulesBody = document.querySelector("#rules-table tbody");

let kindsChart = null;

function sevClass(sev) {
  return `sev-${(sev || "medium").toLowerCase()}`;
}

function renderStats(stats) {
  el("stat-total-alerts").textContent = stats.total_alerts ?? 0;
  el("stat-total-flows").textContent = stats.total_flows ?? 0;
  el("stat-high").textContent = (stats.alerts_by_severity && stats.alerts_by_severity.high) || 0;
  el("stat-kinds").textContent = Object.keys(stats.alerts_by_kind || {}).length;

  const byKind = stats.alerts_by_kind || {};
  const labels = Object.keys(byKind);
  const values = Object.values(byKind);

  if (kindsChart) {
    kindsChart.data.labels = labels;
    kindsChart.data.datasets[0].data = values;
    kindsChart.update();
  } else {
    kindsChart = new Chart(document.getElementById("chart-kinds"), {
      type: "bar",
      data: { labels, datasets: [{ label: "Alerts", data: values, backgroundColor: "#58a6ff" }] },
      options: { responsive: true, plugins: { legend: { display: false } } },
    });
  }
}

function prependAlertRow(alert) {
  const row = document.createElement("tr");
  const time = new Date(alert.ts * 1000).toLocaleTimeString();
  row.innerHTML = `
    <td>${time}</td>
    <td class="${sevClass(alert.severity)}">${(alert.severity || "").toUpperCase()}</td>
    <td>${alert.kind}</td>
    <td>${alert.src || ""}</td>
    <td>${alert.dst || ""}</td>
    <td>${alert.detail}</td>
  `;
  alertsBody.prepend(row);
  while (alertsBody.rows.length > 50) {
    alertsBody.deleteRow(-1);
  }
}

function renderRules(rules) {
  rulesBody.innerHTML = "";
  for (const rule of rules) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${rule.sid}</td>
      <td>${rule.msg}</td>
      <td>${rule.proto}</td>
      <td class="${sevClass(rule.severity)}">${rule.severity}</td>
    `;
    rulesBody.appendChild(row);
  }
}

socket.on("alert", prependAlertRow);
socket.on("stats", renderStats);

fetch("/api/stats").then((r) => r.json()).then(renderStats);
fetch("/api/alerts?limit=50").then((r) => r.json()).then((alerts) => alerts.reverse().forEach(prependAlertRow));
fetch("/api/rules").then((r) => r.json()).then(renderRules);
