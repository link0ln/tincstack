"""
diag_webui.py — Self-contained Single-Page WebUI for the tincstack Remote
Diagnostic Panel (shared across Windows and Android).

Zero external dependencies (works inside isolated VPN networks without internet
access). Communicates with the local/remote client via JSON REST endpoints:
  GET  /api/overview?net=<net>
  GET  /api/logs?net=<net>&source=tincd|app|events&lines=300
  GET  /api/config?net=<net>
  GET  /api/export?net=<net>
  POST /api/mark
  POST /api/action
  POST /api/probe
"""

from __future__ import annotations

DIAG_WEBUI_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tincstack — Remote Diagnostic Panel</title>
<style>
:root {
  --bg: #0f141c;
  --panel: #171f2c;
  --panel2: #1e293b;
  --border: #2c3a4f;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #3b82f6;
  --accent-hover: #2563eb;
  --ok: #22c55e;
  --warn: #f59e0b;
  --err: #ef4444;
  --purple: #a855f7;
  --cyan: #06b6d4;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 13.5px; line-height: 1.45;
}
header {
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  padding: 10px 18px;
  display: flex; flex-wrap: wrap; gap: 12px;
  align-items: center; justify-content: space-between;
  position: sticky; top: 0; z-index: 50;
}
.brand {
  display: flex; align-items: center; gap: 10px;
  font-weight: 700; font-size: 16px;
}
.badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 8px; border-radius: 999px;
  font-size: 11.5px; font-weight: 600;
  background: var(--panel2); border: 1px solid var(--border);
}
.badge.ok { background: rgba(34,197,94,0.15); color: #4ade80; border-color: rgba(34,197,94,0.35); }
.badge.warn { background: rgba(245,158,11,0.15); color: #fbbf24; border-color: rgba(245,158,11,0.35); }
.badge.err { background: rgba(239,68,68,0.15); color: #f87171; border-color: rgba(239,68,68,0.35); }
.badge.info { background: rgba(59,130,246,0.15); color: #60a5fa; border-color: rgba(59,130,246,0.35); }
.badge.purple { background: rgba(168,85,247,0.15); color: #c084fc; border-color: rgba(168,85,247,0.35); }

.top-controls {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
}
button, select, input, textarea {
  background: var(--panel2); color: var(--text);
  border: 1px solid var(--border); border-radius: 6px;
  padding: 6px 10px; font-size: 13px; font-family: inherit;
}
button {
  cursor: pointer; font-weight: 500;
  transition: background 0.15s, border-color 0.15s;
}
button:hover { background: #283548; border-color: #475569; }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
button.primary:hover { background: var(--accent-hover); }
button.danger { background: rgba(239,68,68,0.2); border-color: rgba(239,68,68,0.5); color: #fca5a5; }
button.danger:hover { background: rgba(239,68,68,0.35); }
button.warn-btn { background: rgba(245,158,11,0.2); border-color: rgba(245,158,11,0.5); color: #fde68a; }
button.warn-btn:hover { background: rgba(245,158,11,0.35); }
button.sm { padding: 3px 8px; font-size: 12px; }

.fleet-bar {
  background: #131b26;
  border-bottom: 1px solid var(--border);
  padding: 7px 18px;
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  font-size: 12.5px;
}
.fleet-link {
  text-decoration: none; color: var(--text);
  padding: 3px 9px; border-radius: 6px;
  background: var(--panel2); border: 1px solid var(--border);
  display: inline-flex; align-items: center; gap: 6px;
}
.fleet-link:hover { border-color: var(--accent); color: #93c5fd; }
.fleet-link.self { border-color: var(--accent); background: rgba(59,130,246,0.18); }

nav.tabs {
  display: flex; gap: 4px; padding: 10px 18px 0;
  border-bottom: 1px solid var(--border);
  background: var(--panel);
  overflow-x: auto;
}
nav.tabs button {
  background: transparent; border: none; border-bottom: 2px solid transparent;
  border-radius: 6px 6px 0 0; padding: 8px 14px;
  color: var(--muted); font-weight: 600;
}
nav.tabs button.active {
  color: var(--text); border-bottom-color: var(--accent);
  background: rgba(59,130,246,0.08);
}

main { padding: 16px 18px; max-width: 1600px; margin: 0 auto; }
.tab-pane { display: none; }
.tab-pane.active { display: block; }

.grid { display: grid; gap: 14px; }
.grid-2 { grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); }
.grid-4 { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }

.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
}
.card h3 {
  margin: 0 0 10px 0; font-size: 14px;
  display: flex; align-items: center; justify-content: space-between;
  color: #f8fafc;
}
.stat-val { font-size: 20px; font-weight: 700; margin: 2px 0; }
.stat-sub { font-size: 12px; color: var(--muted); }

.table-wrap { overflow-x: auto; }
table {
  width: 100%; border-collapse: collapse; font-size: 13px;
}
th, td {
  text-align: left; padding: 7px 9px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
th { color: var(--muted); font-weight: 600; font-size: 12px; background: rgba(0,0,0,0.15); }
tr:hover td { background: rgba(255,255,255,0.02); }

canvas.chart {
  width: 100%; height: 190px;
  background: #111822; border-radius: 6px;
  border: 1px solid var(--border);
}

pre.console {
  background: #0b0f16; color: #cbd5e1;
  border: 1px solid var(--border); border-radius: 6px;
  padding: 10px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 12px; overflow: auto; max-height: 460px;
  white-space: pre-wrap; word-break: break-all; margin: 0;
}
textarea.code-editor {
  width: 100%; min-height: 300px;
  background: #0b0f16; color: #e2e8f0;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 12.5px; line-height: 1.4;
}

.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.kv-list { display: grid; grid-template-columns: 150px 1fr; gap: 5px 10px; font-size: 12.5px; }
.kv-list .k { color: var(--muted); }

#toast {
  position: fixed; bottom: 18px; right: 18px;
  background: #1e293b; border: 1px solid var(--accent);
  color: #fff; padding: 10px 16px; border-radius: 8px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.5);
  display: none; z-index: 200; max-width: 420px;
}
.modal-backdrop {
  position: fixed; inset: 0; background: rgba(0,0,0,0.65);
  display: none; align-items: center; justify-content: center; z-index: 150;
}
.modal {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; width: min(760px, 94vw);
  max-height: 88vh; overflow: auto;
}
</style>
</head>
<body>

<header>
  <div class="brand">
    <span>🩺 tincstack Diagnostic Panel</span>
    <span id="hdr-platform" class="badge info">...</span>
    <span id="hdr-node" class="badge purple">...</span>
    <span id="hdr-state" class="badge">...</span>
  </div>
  <div class="top-controls">
    <label style="color:var(--muted);font-size:12px;">Network:</label>
    <select id="net-select" onchange="onNetworkChange()"></select>
    <button class="warn-btn" onclick="markLagPrompt()" title="Зафиксировать момент затупа/тормоза в журнале инцидентов">⚡ Зафиксировать затуп</button>
    <button onclick="exportBundle()" title="Скачать полный JSON-слепок диагностики">📦 Скачать слепок (.json)</button>
    <label style="color:var(--muted);font-size:12px;">
      <input type="checkbox" id="auto-refresh" checked> Авто (2.5с)
    </label>
    <button class="sm" onclick="refreshAll()">🔄 Обновить</button>
  </div>
</header>

<div class="fleet-bar" id="fleet-bar">
  <span style="color:var(--muted);">🌐 Ноды в сети VPN (быстрый переход в панель клиента):</span>
  <span id="fleet-links">Загрузка...</span>
</div>

<nav class="tabs">
  <button class="active" onclick="switchTab('overview', this)">📊 Обзор и Метрики</button>
  <button onclick="switchTab('peers', this)">🖧 Ноды и Протоколы</button>
  <button onclick="switchTab('tools', this)">🔬 Инструменты диагностики (Ping / Trace / PMTU)</button>
  <button onclick="switchTab('controls', this)">⚙️ Управление и Конфиг</button>
  <button onclick="switchTab('logs', this)">📜 Инциденты и Логи (<span id="inc-count">0</span>)</button>
</nav>

<main>
  <!-- TAB 1: OVERVIEW -->
  <div id="tab-overview" class="tab-pane active">
    <div class="grid grid-4" style="margin-bottom:14px;">
      <div class="card">
        <h3>Устройство и VPN IP</h3>
        <div class="stat-val" id="st-vpn-ip">—</div>
        <div class="stat-sub" id="st-host-info">—</div>
      </div>
      <div class="card">
        <h3>Связь с меш-сетью</h3>
        <div class="stat-val" id="st-peers-summary">—</div>
        <div class="stat-sub" id="st-modes-summary">—</div>
      </div>
      <div class="card">
        <h3>Трафик (RX / TX)</h3>
        <div class="stat-val" id="st-throughput">0 bps / 0 bps</div>
        <div class="stat-sub" id="st-totals">Всего: 0 B / 0 B</div>
      </div>
      <div class="card">
        <h3>Маршрутизация / Система</h3>
        <div class="stat-val" id="st-routing-mode">—</div>
        <div class="stat-sub" id="st-os-extra">—</div>
      </div>
    </div>

    <div class="grid grid-2" style="margin-bottom:14px;">
      <div class="card">
        <h3>
          <span>Пропускная способность туннеля (RX / TX)</span>
          <span style="font-size:11.5px;color:var(--muted);">🟢 RX &nbsp; 🔵 TX</span>
        </h3>
        <canvas id="chart-bw" class="chart" width="680" height="190"></canvas>
      </div>
      <div class="card">
        <h3>
          <span>RTT (мс) по нодам + маркеры инцидентов</span>
          <span style="font-size:11.5px;color:var(--muted);">🔴 = зафиксированный инцидент</span>
        </h3>
        <canvas id="chart-rtt" class="chart" width="680" height="190"></canvas>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <h3>
          <span>⚠️ Последние зафиксированные аномалии и затупы</span>
          <button class="sm" onclick="switchTab('logs', document.querySelectorAll('nav.tabs button')[4])">Все события →</button>
        </h3>
        <div class="table-wrap" style="max-height:260px;">
          <table>
            <thead><tr><th>Время</th><th>Тип</th><th>Нода</th><th>Детали</th></tr></thead>
            <tbody id="recent-incidents-body"></tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <h3>Состояние системы и окружения клиента</h3>
        <div id="sys-kv" class="kv-list"></div>
      </div>
    </div>
  </div>

  <!-- TAB 2: PEERS -->
  <div id="tab-peers" class="tab-pane">
    <div class="card" style="margin-bottom:14px;">
      <h3>
        <span>Таблица нод и быстрое переключение протоколов (Transports)</span>
        <div class="row" style="margin:0;">
          <button class="sm" onclick="runAction('retry', {})">🔄 Retry all connections</button>
          <button class="sm" onclick="runAction('purge', {})">🧹 Purge stale state</button>
          <button class="sm" onclick="runAction('reload', {})">♻️ Reload tincd</button>
        </div>
      </h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Нода</th>
              <th>VPN IP</th>
              <th>Внешний адрес</th>
              <th>Канал (Data path)</th>
              <th>Активный транспорт</th>
              <th>Выбор протокола</th>
              <th>Via / Nexthop</th>
              <th>RTT</th>
              <th>PMTU (min..max)</th>
              <th>RX / TX</th>
              <th>Флаги</th>
              <th>Подсети / Маршрут</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody id="peers-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 3: DIAGNOSTIC TOOLS -->
  <div id="tab-tools" class="tab-pane">
    <div class="grid grid-2" style="margin-bottom:14px;">
      <div class="card">
        <h3>1. Внутритуннельный пробник (In-Tunnel ICMP Ping / Traceroute / PMTU Sweep)</h3>
        <p style="color:var(--muted);margin-top:0;font-size:12px;">
          Инжектирует пакеты напрямую через движок маршрутизации <code>tincd</code> (работает даже на Android с <code>addDisallowedApplication</code> и при блокировке ICMP брандмауэром Windows).
        </p>
        <div class="row">
          <label>Цель (VPN IP):</label>
          <select id="probe-vpn-peer" onchange="if(this.value) document.getElementById('probe-vpn-ip').value=this.value"></select>
          <input type="text" id="probe-vpn-ip" placeholder="10.200.240.1" style="width:145px;">
          <label>Размер:</label>
          <input type="number" id="probe-vpn-size" value="56" min="0" max="1472" style="width:75px;">
          <label><input type="checkbox" id="probe-vpn-df"> DF (не фрагм.)</label>
        </div>
        <div class="row">
          <button class="primary" onclick="runProbe('in_tunnel_ping')">📡 Ping внутри VPN (4x)</button>
          <button onclick="runProbe('in_tunnel_trace')">🧭 Traceroute внутри VPN</button>
          <button class="warn-btn" onclick="runProbe('in_tunnel_pmtu')">📏 Поиск PMTU Blackhole (Sweep 500..1472B)</button>
        </div>
        <pre id="out-in-tunnel" class="console">Выберите ноду или введите VPN IP и запустите проверку...</pre>
      </div>

      <div class="card">
        <h3>2. Внешняя сеть (Underlay Ping / Traceroute / Проверка портов quic/https/obfs)</h3>
        <p style="color:var(--muted);margin-top:0;font-size:12px;">
          Проверяет физический маршрут и доступность портов транспорта до внешнего адреса ноды (в обход туннеля), чтобы сравнить потери снаружи и внутри VPN.
        </p>
        <div class="row">
          <label>Нода / Хост:</label>
          <select id="probe-ext-peer" onchange="onSelectExtPeer()"></select>
          <input type="text" id="probe-ext-host" placeholder="example.com или IP" style="width:170px;">
        </div>
        <div class="row">
          <button class="primary" onclick="runProbe('port_probe')">🔌 Проверить порты (TCP / TLS / UDP)</button>
          <button onclick="runProbe('underlay_ping')">🌐 Внешний Ping (OS)</button>
          <button onclick="runProbe('underlay_trace')">🗺️ Внешний Traceroute (OS)</button>
          <button onclick="runProbe('dns_lookup')">🔍 DNS &amp; Кэш адресов</button>
        </div>
        <pre id="out-underlay" class="console">Выберите ноду или укажите внешний адрес для проверки...</pre>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <h3>
          <span>3. Сетевые интерфейсы ОС, Таблица маршрутизации и Сокеты</span>
          <button class="sm primary" onclick="runProbe('os_net')">Снять состояние ОС</button>
        </h3>
        <pre id="out-os-net" class="console">Нажмите «Снять состояние ОС» для вывода интерфейсов, маршрутов и ARP...</pre>
      </div>
      <div class="card">
        <h3>
          <span>4. Внутренние таблицы демона tincd (dump / info / fsck)</span>
          <div class="row" style="margin:0;">
            <select id="tinc-dump-kind">
              <option value="nodes">dump nodes</option>
              <option value="connections">dump connections</option>
              <option value="edges">dump edges</option>
              <option value="subnets">dump subnets</option>
              <option value="graph">dump graph</option>
              <option value="traffic">dump traffic</option>
              <option value="fsck">fsck</option>
            </select>
            <button class="sm primary" onclick="runProbe('tinc_cmd')">Выполнить</button>
          </div>
        </h3>
        <pre id="out-tinc-cmd" class="console">Выберите команду tinc для просмотра низкоуровневого состояния демона...</pre>
      </div>
    </div>
  </div>

  <!-- TAB 4: CONTROLS & CONFIG -->
  <div id="tab-controls" class="tab-pane">
    <div class="grid grid-2" style="margin-bottom:14px;">
      <div class="card">
        <h3>Управление демоном VPN и режимами работы</h3>
        <div class="row">
          <button class="primary" onclick="runAction('daemon', {op:'start'})">▶ Start VPN</button>
          <button class="danger" onclick="runAction('daemon', {op:'stop'})">⏹ Stop VPN</button>
          <button class="warn-btn" onclick="runAction('daemon', {op:'restart'})">🔄 Restart VPN</button>
          <button onclick="runAction('daemon', {op:'reload'})">♻️ Reload Config</button>
        </div>
        <div class="row" style="margin-top:12px;">
          <label>Уровень логирования <code>tincd</code> (Debug Level):</label>
          <select id="ctl-debug-level">
            <option value="0">0 — Стандартный (Notice/Error)</option>
            <option value="1">1 — Соединения (Connections)</option>
            <option value="2">2 — Протокол и статус</option>
            <option value="3">3 — Мета-протокол (REQ_KEY / ANS_KEY)</option>
            <option value="4">4 — Трафик и пакеты (Debug Traffic)</option>
            <option value="5">5 — Максимальный (Scary Things)</option>
          </select>
          <button onclick="runAction('daemon', {op:'debug', level: parseInt(document.getElementById('ctl-debug-level').value)})">Применить</button>
        </div>
        <hr style="border:none;border-top:1px solid var(--border);margin:12px 0;">
        <h3>Приглашение новой ноды (Invite)</h3>
        <div class="row">
          <input type="text" id="invite-node-name" placeholder="имя_новой_ноды (напр. phone2)" style="width:210px;">
          <button onclick="generateInvite()">✉️ Сгенерировать инвайт</button>
        </div>
        <pre id="invite-output" class="console" style="display:none;max-height:90px;margin-top:8px;"></pre>
      </div>

      <div class="card">
        <h3>Глобальные настройки транспорта и сети</h3>
        <div class="row">
          <label style="width:170px;">Принимаемые (Transports):</label>
          <input type="text" id="cfg-transports" placeholder="plain, sf, obfs, quic, https" style="flex:1;">
        </div>
        <div class="row">
          <label style="width:170px;">Приоритет (Preferred):</label>
          <input type="text" id="cfg-pref-transports" placeholder="quic, https, obfs, sf, plain" style="flex:1;">
        </div>
        <div class="row">
          <label style="width:170px;">Full-Tunnel (выход в интернет):</label>
          <select id="cfg-full-tunnel" style="flex:1;">
            <option value="">Выключено (только подсети VPN)</option>
          </select>
        </div>
        <div class="row" id="android-extra-settings" style="display:none;">
          <label><input type="checkbox" id="cfg-reconnect-net"> Переподключать при смене сети (Wi-Fi/LTE)</label>
          <label><input type="checkbox" id="cfg-pause-lock"> Пауза при выключении экрана</label>
        </div>
        <div class="row">
          <button class="primary" onclick="saveTransportSettings()">💾 Сохранить и применить настройки</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>
        <span>Прямой редактор <code>tinc.yaml</code></span>
        <div class="row" style="margin:0;">
          <button class="sm" onclick="loadConfigTab()">🔄 Перечитать с диска</button>
          <button class="sm primary" onclick="saveRawYaml()">💾 Сохранить tinc.yaml и перезагрузить демон</button>
        </div>
      </h3>
      <textarea id="raw-yaml-editor" class="code-editor" spellcheck="false"></textarea>
    </div>
  </div>

  <!-- TAB 5: INCIDENTS & LOGS -->
  <div id="tab-logs" class="tab-pane">
    <div class="card" style="margin-bottom:14px;">
      <h3>
        <span>Хронология зафиксированных инцидентов, переключений и затупов</span>
        <div class="row" style="margin:0;">
          <input type="text" id="inc-filter" placeholder="Фильтр по ноде или типу..." oninput="renderIncidents()">
          <button class="sm warn-btn" onclick="markLagPrompt()">⚡ Добавить метку затупа</button>
          <button class="sm" onclick="runAction('clear_incidents', {})">🧹 Очистить журнал</button>
        </div>
      </h3>
      <div class="table-wrap" style="max-height:280px;">
        <table>
          <thead><tr><th>Время</th><th>Уровень</th><th>Событие</th><th>Нода</th><th>Описание и параметры</th></tr></thead>
          <tbody id="all-incidents-body"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3>
        <span>Журнал логов в реальном времени</span>
        <div class="row" style="margin:0;">
          <select id="log-source" onchange="refreshLogs()">
            <option value="tincd">Лог демона (tincd.log)</option>
            <option value="app">Лог приложения (tincmgr / logcat)</option>
            <option value="events">Сырой JSONL инцидентов</option>
          </select>
          <input type="text" id="log-filter" placeholder="Поиск в логах (напр. ERROR, SPTPS, QUIC)..." oninput="renderLogText()">
          <button class="sm" onclick="refreshLogs()">🔄 Обновить лог</button>
        </div>
      </h3>
      <pre id="log-console" class="console" style="max-height:500px;">Загрузка логов...</pre>
    </div>
  </div>
</main>

<!-- Modal for peer info / host editor -->
<div id="modal-backdrop" class="modal-backdrop" onclick="if(event.target===this) closeModal()">
  <div class="modal">
    <h3 id="modal-title" style="margin-top:0;">Детали ноды</h3>
    <div id="modal-body"></div>
    <div class="row" style="justify-content:flex-end;margin-top:12px;margin-bottom:0;">
      <button onclick="closeModal()">Закрыть</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
let STATE = {
  net: "",
  overview: null,
  rawLogs: "",
  activeTab: "overview"
};

function showToast(msg, isErr=false) {
  const el = document.getElementById("toast");
  el.style.borderColor = isErr ? "var(--err)" : "var(--accent)";
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.style.display = "none"; }, 4000);
}

function fmtBytes(n) {
  n = Number(n || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + units[i];
}

function fmtBps(n) {
  n = Number(n || 0);
  const units = ["bps", "Kbps", "Mbps", "Gbps"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + units[i];
}

function fmtTime(epoch) {
  if (!epoch) return "—";
  const d = new Date(epoch * 1000);
  return d.toLocaleTimeString("ru-RU", {hour12: false}) + "." + String(d.getMilliseconds()).padStart(3, "0").slice(0,2);
}

function switchTab(tab, btn) {
  STATE.activeTab = tab;
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  document.getElementById("tab-" + tab).classList.add("active");
  document.querySelectorAll("nav.tabs button").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  if (tab === "logs") refreshLogs();
  if (tab === "controls") loadConfigTab();
}

async function apiGet(path) {
  const r = await fetch(path, {cache: "no-store"});
  if (!r.ok) throw new Error("HTTP " + r.status);
  return await r.json();
}

async function apiPost(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body || {})
  });
  return await r.json();
}

function onNetworkChange() {
  STATE.net = document.getElementById("net-select").value;
  refreshAll();
}

async function refreshAll() {
  try {
    const q = STATE.net ? ("?net=" + encodeURIComponent(STATE.net)) : "";
    const data = await apiGet("/api/overview" + q);
    STATE.overview = data;
    if (!STATE.net && data.net) STATE.net = data.net;
    renderOverview(data);
    if (STATE.activeTab === "logs") refreshLogs();
  } catch (e) {
    console.error(e);
  }
}

function renderOverview(d) {
  document.getElementById("hdr-platform").textContent = (d.platform || "client").toUpperCase() + " " + (d.version || "");
  document.getElementById("hdr-node").textContent = "Node: " + (d.self_node || "—");
  const stEl = document.getElementById("hdr-state");
  stEl.textContent = d.running ? "● RUNNING" : "○ STOPPED";
  stEl.className = "badge " + (d.running ? "ok" : "err");

  // Networks dropdown
  const sel = document.getElementById("net-select");
  const nets = d.networks || [];
  if (sel.options.length !== nets.length || Array.from(sel.options).some((o,i) => o.value !== nets[i])) {
    sel.innerHTML = nets.map(n => `<option value="${n}" ${n===d.net?'selected':''}>${n}</option>`).join("");
  }

  // Fleet links
  const port = d.diag_port || location.port || 8655;
  const nodes = d.nodes || [];
  const fleetHtml = nodes.filter(n => n.vpn_address).map(n => {
    const isLocalSelf = n.is_self && (location.hostname === "127.0.0.1" || location.hostname === "localhost");
    const url = isLocalSelf ? `http://127.0.0.1:${port}/` : `http://${n.vpn_address}:${port}/`;
    const cls = n.is_self ? "fleet-link self" : "fleet-link";
    const dot = n.is_self ? "★" : (n.reachable ? "🟢" : "⚪");
    return `<a class="${cls}" href="${url}" target="_blank" title="Открыть диагностическую панель ${n.name} (${url})">${dot} <b>${n.name}</b> <code>${n.vpn_address}</code></a>`;
  }).join("");
  document.getElementById("fleet-links").innerHTML = fleetHtml || "<span style='color:var(--muted)'>Нет нод с известным VPN IP</span>";

  // Top stat cards
  document.getElementById("st-vpn-ip").textContent = d.self_vpn_ip || "—";
  document.getElementById("st-host-info").textContent = `${d.hostname || ""} · PID: ${d.pid || "—"}`;

  const peers = nodes.filter(n => !n.is_self);
  const reach = peers.filter(n => n.reachable);
  const dUdp = reach.filter(n => n.link === "direct-udp").length;
  const dTcp = reach.filter(n => n.link === "direct-tcp").length;
  const rel = reach.filter(n => n.link === "relay").length;
  document.getElementById("st-peers-summary").textContent = `${reach.length} / ${peers.length} онлайн`;
  document.getElementById("st-modes-summary").textContent = `Direct UDP: ${dUdp} · Direct TCP: ${dTcp} · Relay: ${rel}`;

  const bw = d.current_bw || {rx_bps: 0, tx_bps: 0, total_rx: 0, total_tx: 0};
  document.getElementById("st-throughput").textContent = `↓ ${fmtBps(bw.rx_bps)} / ↑ ${fmtBps(bw.tx_bps)}`;
  document.getElementById("st-totals").textContent = `Всего: ↓ ${fmtBytes(bw.total_rx)} / ↑ ${fmtBytes(bw.total_tx)}`;

  document.getElementById("st-routing-mode").textContent = d.full_tunnel ? `Full-Tunnel → ${d.full_tunnel}` : "Split / Subnets";
  document.getElementById("st-os-extra").textContent = d.os_summary || "";

  // System KV
  const sys = d.system_info || {};
  document.getElementById("sys-kv").innerHTML = Object.entries(sys).map(([k,v]) =>
    `<div class="k">${k}</div><div>${String(v)}</div>`
  ).join("");

  // Incidents
  const incs = d.incidents || [];
  document.getElementById("inc-count").textContent = incs.length;
  document.getElementById("recent-incidents-body").innerHTML = incs.slice(0, 8).map(inc => {
    const bcls = inc.severity === "error" ? "err" : (inc.severity === "warn" ? "warn" : "info");
    return `<tr>
      <td>${fmtTime(inc.ts)}</td>
      <td><span class="badge ${bcls}">${inc.kind}</span></td>
      <td><b>${inc.peer || "—"}</b></td>
      <td style="white-space:normal;">${inc.message || ""}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="4" style="color:var(--muted);">Аномалий пока не зафиксировано</td></tr>`;

  renderIncidents();
  renderPeersTable(d);
  populateProbeDropdowns(d);
  drawCharts(d);
}

function renderIncidents() {
  if (!STATE.overview) return;
  const q = (document.getElementById("inc-filter").value || "").toLowerCase();
  const incs = (STATE.overview.incidents || []).filter(i =>
    !q || (i.kind||"").toLowerCase().includes(q) || (i.peer||"").toLowerCase().includes(q) || (i.message||"").toLowerCase().includes(q)
  );
  document.getElementById("all-incidents-body").innerHTML = incs.map(inc => {
    const bcls = inc.severity === "error" ? "err" : (inc.severity === "warn" ? "warn" : "info");
    return `<tr>
      <td>${fmtTime(inc.ts)}</td>
      <td><span class="badge ${bcls}">${inc.severity}</span></td>
      <td><code>${inc.kind}</code></td>
      <td><b>${inc.peer || "—"}</b></td>
      <td style="white-space:normal;">${inc.message || ""}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="5" style="color:var(--muted);">Нет записей</td></tr>`;
}

function renderPeersTable(d) {
  const tbody = document.getElementById("peers-tbody");
  const nodes = d.nodes || [];
  const choices = ["auto", "quic", "https", "obfs", "sf", "sftcp", "plain"];
  tbody.innerHTML = nodes.map(n => {
    const linkBadge = n.is_self ? `<span class="badge info">★ this node</span>` :
      (n.link === "direct-udp" ? `<span class="badge ok">● direct UDP</span>` :
       n.link === "direct-tcp" ? `<span class="badge warn">◐ direct TCP</span>` :
       n.link === "relay" ? `<span class="badge warn">↻ relay</span>` :
       `<span class="badge err">○ down</span>`);

    const trBadge = n.transport ? `<span class="badge purple">${n.transport}</span>` : "—";
    const pref = n.preferred_transport || "auto";
    const selHtml = n.is_self ? "—" : `<select onchange="setPeerTransport('${n.name}', this.value)">
      ${choices.map(c => `<option value="${c}" ${c===pref?'selected':''}>${c === 'auto' ? 'auto' : '📌 ' + c}</option>`).join("")}
    </select>`;

    const flags = [];
    if (n.status) {
      if (n.status.validkey) flags.push("🔑key");
      if (n.status.waitingforkey) flags.push("⏳wait_key");
      if (n.status.udp_confirmed) flags.push("⚡udp");
      if (n.status.ping_sent) flags.push("📡ping");
      if (n.status.sptps_route_stale) flags.push("⚠️stale");
    }

    const actions = n.is_self ? `<button class="sm" onclick="editPeerHost('${n.name}')">✏️ Host</button>` : `
      <button class="sm" onclick="showPeerInfo('${n.name}')" title="tinc info">ℹ️ Info</button>
      <button class="sm" onclick="editPeerHost('${n.name}')" title="Редактировать конфиг хоста">✏️ Host</button>
      <button class="sm warn-btn" onclick="runAction('peer_reconnect', {peer:'${n.name}'})" title="Переподключить ноду">🔌 Reconnect</button>
      <button class="sm" onclick="quickPingPeer('${n.vpn_address}', '${n.name}')" title="Ping внутри VPN">📡 Ping</button>
    `;

    return `<tr>
      <td><b>${n.name}</b></td>
      <td><code>${n.vpn_address || "—"}</code></td>
      <td><code>${n.address && n.address !== "MYSELF" ? (n.address + ":" + (n.port||"655")) : "—"}</code></td>
      <td>${linkBadge}</td>
      <td>${trBadge}</td>
      <td>${selHtml}</td>
      <td>${n.via && n.via !== n.name ? `via <b>${n.via}</b>` : (n.nexthop || "—")}</td>
      <td>${n.rtt > 0 ? n.rtt.toFixed(1) + " ms" : "—"}</td>
      <td>${n.pmtu > 0 ? `${n.pmtu} <span style="color:var(--muted)">(${n.pmtu_min}..${n.pmtu_max})</span>` : "—"}</td>
      <td>↓${fmtBytes(n.rx_bytes)} / ↑${fmtBytes(n.tx_bytes)}</td>
      <td><span style="font-size:11.5px;color:var(--muted);">${flags.join(" ") || "—"}</span></td>
      <td><code>${(n.subnets || []).join(", ") || "—"}</code></td>
      <td>${actions}</td>
    </tr>`;
  }).join("");
}

function populateProbeDropdowns(d) {
  const nodes = (d.nodes || []).filter(n => !n.is_self);
  const vpnSel = document.getElementById("probe-vpn-peer");
  if (vpnSel.options.length !== nodes.length + 1) {
    vpnSel.innerHTML = `<option value="">— Выберите ноду —</option>` +
      nodes.filter(n => n.vpn_address).map(n => `<option value="${n.vpn_address}">${n.name} (${n.vpn_address})</option>`).join("");
    if (!document.getElementById("probe-vpn-ip").value && nodes[0] && nodes[0].vpn_address) {
      document.getElementById("probe-vpn-ip").value = nodes[0].vpn_address;
    }
  }
  const extSel = document.getElementById("probe-ext-peer");
  if (extSel.options.length !== nodes.length + 1) {
    extSel.innerHTML = `<option value="">— Выберите ноду —</option>` +
      nodes.map(n => `<option value="${n.name}" data-addr="${n.configured_address || n.address || ''}">${n.name} (${n.configured_address || n.address || '—'})</option>`).join("");
    if (!document.getElementById("probe-ext-host").value && nodes[0]) {
      document.getElementById("probe-ext-host").value = nodes[0].configured_address || nodes[0].address || "";
    }
  }
}

function onSelectExtPeer() {
  const sel = document.getElementById("probe-ext-peer");
  const opt = sel.options[sel.selectedIndex];
  if (opt && opt.dataset.addr && opt.dataset.addr !== "unknown") {
    document.getElementById("probe-ext-host").value = opt.dataset.addr;
  }
}

function drawCharts(d) {
  const hist = d.history || [];
  // 1. Bandwidth chart
  const bwCanvas = document.getElementById("chart-bw");
  const ctx1 = bwCanvas.getContext("2d");
  ctx1.clearRect(0, 0, bwCanvas.width, bwCanvas.height);
  if (hist.length >= 2) {
    const maxBps = Math.max(1000, ...hist.map(p => Math.max(p.rx_bps || 0, p.tx_bps || 0))) * 1.15;
    drawGrid(ctx1, bwCanvas.width, bwCanvas.height, fmtBps(maxBps));
    drawSeries(ctx1, bwCanvas.width, bwCanvas.height, hist.map(p => p.rx_bps || 0), maxBps, "#22c55e");
    drawSeries(ctx1, bwCanvas.width, bwCanvas.height, hist.map(p => p.tx_bps || 0), maxBps, "#3b82f6");
  }

  // 2. RTT chart
  const rttCanvas = document.getElementById("chart-rtt");
  const ctx2 = rttCanvas.getContext("2d");
  ctx2.clearRect(0, 0, rttCanvas.width, rttCanvas.height);
  if (hist.length >= 2) {
    const peerNames = Object.keys(hist[hist.length - 1].peer_rtt || {});
    let maxRtt = 50;
    hist.forEach(p => {
      Object.values(p.peer_rtt || {}).forEach(v => { if (v > maxRtt) maxRtt = v; });
    });
    maxRtt *= 1.2;
    drawGrid(ctx2, rttCanvas.width, rttCanvas.height, maxRtt.toFixed(0) + " ms");
    const colors = ["#a855f7", "#06b6d4", "#f59e0b", "#22c55e", "#ec4899"];
    peerNames.forEach((name, idx) => {
      const vals = hist.map(p => (p.peer_rtt && p.peer_rtt[name]) || 0);
      drawSeries(ctx2, rttCanvas.width, rttCanvas.height, vals, maxRtt, colors[idx % colors.length]);
    });
    // Plot incident markers
    const tMin = hist[0].ts, tMax = hist[hist.length - 1].ts;
    if (tMax > tMin) {
      ctx2.strokeStyle = "rgba(239,68,68,0.75)";
      ctx2.lineWidth = 1.5;
      (d.incidents || []).forEach(inc => {
        if (inc.ts >= tMin && inc.ts <= tMax) {
          const x = 10 + ((inc.ts - tMin) / (tMax - tMin)) * (rttCanvas.width - 20);
          ctx2.beginPath(); ctx2.moveTo(x, 8); ctx2.lineTo(x, rttCanvas.height - 8); ctx2.stroke();
        }
      });
    }
  }
}

function drawGrid(ctx, w, h, topLabel) {
  ctx.strokeStyle = "rgba(148,163,184,0.12)";
  ctx.lineWidth = 1;
  for (let i = 1; i <= 3; i++) {
    const y = (h / 4) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  ctx.fillStyle = "#94a3b8";
  ctx.font = "11px sans-serif";
  ctx.fillText(topLabel, 8, 14);
}

function drawSeries(ctx, w, h, values, maxVal, color) {
  if (!values.length || maxVal <= 0) return;
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath();
  values.forEach((v, i) => {
    const x = 10 + (i / Math.max(1, values.length - 1)) * (w - 20);
    const y = h - 10 - Math.min(1, v / maxVal) * (h - 24);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

async function setPeerTransport(peer, transport) {
  try {
    const res = await apiPost("/api/action", {net: STATE.net, action: "peer_transport", peer, transport});
    showToast(res.message || `Транспорт для ${peer} → ${transport}`, !res.ok);
    setTimeout(refreshAll, 600);
  } catch (e) {
    showToast("Ошибка: " + e.message, true);
  }
}

async function runAction(action, params) {
  try {
    const res = await apiPost("/api/action", Object.assign({net: STATE.net, action}, params || {}));
    showToast(res.message || (res.ok ? "Выполнено" : "Ошибка"), !res.ok);
    setTimeout(refreshAll, 500);
  } catch (e) {
    showToast("Ошибка: " + e.message, true);
  }
}

async function markLagPrompt() {
  const note = prompt("Опишите кратко симптом (необязательно, например: 'завис SSH / пропал пинг в браузере'):", "Замечен затуп/обрыв сессии");
  if (note === null) return;
  try {
    const res = await apiPost("/api/mark", {net: STATE.net, note});
    showToast(res.message || "Метка затупа сохранена!");
    refreshAll();
  } catch (e) {
    showToast("Ошибка: " + e.message, true);
  }
}

function exportBundle() {
  const q = STATE.net ? ("?net=" + encodeURIComponent(STATE.net)) : "";
  window.open("/api/export" + q, "_blank");
}

function quickPingPeer(vpnIp, name) {
  switchTab("tools", document.querySelectorAll("nav.tabs button")[2]);
  if (vpnIp) document.getElementById("probe-vpn-ip").value = vpnIp;
  runProbe("in_tunnel_ping");
}

async function runProbe(kind) {
  const body = {net: STATE.net, kind};
  let outEl = document.getElementById("out-in-tunnel");
  if (kind.startsWith("in_tunnel")) {
    body.dst_ip = document.getElementById("probe-vpn-ip").value.trim();
    body.size = parseInt(document.getElementById("probe-vpn-size").value || "56");
    body.df = document.getElementById("probe-vpn-df").checked;
    outEl = document.getElementById("out-in-tunnel");
  } else if (kind === "port_probe" || kind === "underlay_ping" || kind === "underlay_trace" || kind === "dns_lookup") {
    body.peer = document.getElementById("probe-ext-peer").value;
    body.host = document.getElementById("probe-ext-host").value.trim();
    outEl = document.getElementById("out-underlay");
  } else if (kind === "os_net") {
    outEl = document.getElementById("out-os-net");
  } else if (kind === "tinc_cmd") {
    body.cmd = document.getElementById("tinc-dump-kind").value;
    outEl = document.getElementById("out-tinc-cmd");
  }
  outEl.textContent = "⏳ Выполнение диагностики (" + kind + ")...";
  try {
    const res = await apiPost("/api/probe", body);
    outEl.textContent = res.formatted || JSON.stringify(res, null, 2);
  } catch (e) {
    outEl.textContent = "Ошибка выполнения: " + e.message;
  }
}

async function showPeerInfo(peer) {
  document.getElementById("modal-title").textContent = "Информация о ноде: " + peer;
  document.getElementById("modal-body").innerHTML = `<pre class="console">Загрузка...</pre>`;
  document.getElementById("modal-backdrop").style.display = "flex";
  const res = await apiPost("/api/action", {net: STATE.net, action: "peer_info", peer});
  document.getElementById("modal-body").innerHTML = `<pre class="console">${res.output || res.message || "Нет данных"}</pre>`;
}

async function editPeerHost(peer) {
  const q = "?net=" + encodeURIComponent(STATE.net);
  const cfg = await apiGet("/api/config" + q);
  const bodyText = (cfg.hosts && cfg.hosts[peer]) || "";
  document.getElementById("modal-title").textContent = "Конфигурация хоста: " + peer;
  document.getElementById("modal-body").innerHTML = `
    <p style="color:var(--muted);font-size:12px;margin-top:0;">Опции хоста (Address, Port, QuicPort, HttpsPort, ObfsPort, Subnet, PreferredTransports и ключи):</p>
    <textarea id="modal-host-text" class="code-editor" style="min-height:240px;"></textarea>
    <div class="row" style="margin-top:10px;">
      <button class="primary" onclick="savePeerHost('${peer}')">💾 Сохранить хост и перезагрузить tincd</button>
    </div>
  `;
  document.getElementById("modal-host-text").value = bodyText;
  document.getElementById("modal-backdrop").style.display = "flex";
}

async function savePeerHost(peer) {
  const text = document.getElementById("modal-host-text").value;
  const res = await apiPost("/api/action", {net: STATE.net, action: "peer_save_host", peer, text});
  showToast(res.message || "Сохранено", !res.ok);
  if (res.ok) { closeModal(); refreshAll(); }
}

function closeModal() {
  document.getElementById("modal-backdrop").style.display = "none";
}

async function loadConfigTab() {
  const q = "?net=" + encodeURIComponent(STATE.net);
  const cfg = await apiGet("/api/config" + q);
  document.getElementById("cfg-transports").value = cfg.transports || "";
  document.getElementById("cfg-pref-transports").value = cfg.preferred_transports || "";
  document.getElementById("raw-yaml-editor").value = cfg.raw_yaml || "";

  const ftSel = document.getElementById("cfg-full-tunnel");
  const peers = (STATE.overview && STATE.overview.nodes || []).filter(n => !n.is_self);
  ftSel.innerHTML = `<option value="">Выключено (только подсети VPN)</option>` +
    peers.map(n => `<option value="${n.name}" ${cfg.full_tunnel===n.name?'selected':''}>Весь трафик (0.0.0.0/0) через ${n.name}</option>`).join("");

  const androidBox = document.getElementById("android-extra-settings");
  if (STATE.overview && STATE.overview.platform === "android") {
    androidBox.style.display = "flex";
    document.getElementById("cfg-reconnect-net").checked = !!cfg.reconnect_on_net_change;
    document.getElementById("cfg-pause-lock").checked = !!cfg.disconnect_on_screen_off;
  } else {
    androidBox.style.display = "none";
  }
}

async function saveTransportSettings() {
  const body = {
    net: STATE.net,
    action: "save_settings",
    transports: document.getElementById("cfg-transports").value.trim(),
    preferred_transports: document.getElementById("cfg-pref-transports").value.trim(),
    full_tunnel: document.getElementById("cfg-full-tunnel").value,
    reconnect_on_net_change: document.getElementById("cfg-reconnect-net").checked,
    disconnect_on_screen_off: document.getElementById("cfg-pause-lock").checked
  };
  const res = await apiPost("/api/action", body);
  showToast(res.message || "Настройки сохранены", !res.ok);
  loadConfigTab();
  refreshAll();
}

async function saveRawYaml() {
  const raw_yaml = document.getElementById("raw-yaml-editor").value;
  const res = await apiPost("/api/action", {net: STATE.net, action: "save_raw_yaml", raw_yaml});
  showToast(res.message || "YAML сохранён", !res.ok);
  refreshAll();
}

async function generateInvite() {
  const name = document.getElementById("invite-node-name").value.trim();
  if (!name) { showToast("Введите имя новой ноды", true); return; }
  const out = document.getElementById("invite-output");
  out.style.display = "block";
  out.textContent = "⏳ Генерация приглашения...";
  const res = await apiPost("/api/action", {net: STATE.net, action: "invite", peer: name});
  out.textContent = res.output || res.message || "Ошибка";
}

async function refreshLogs() {
  const src = document.getElementById("log-source").value;
  const q = `?net=${encodeURIComponent(STATE.net)}&source=${encodeURIComponent(src)}&lines=350`;
  try {
    const res = await apiGet("/api/logs" + q);
    STATE.rawLogs = res.text || "";
    renderLogText();
  } catch (e) {
    document.getElementById("log-console").textContent = "Ошибка чтения логов: " + e.message;
  }
}

function renderLogText() {
  const filter = (document.getElementById("log-filter").value || "").toLowerCase();
  const lines = (STATE.rawLogs || "").split("\n");
  const filtered = filter ? lines.filter(l => l.toLowerCase().includes(filter)) : lines;
  const el = document.getElementById("log-console");
  el.textContent = filtered.join("\n") || "(пусто)";
  el.scrollTop = el.scrollHeight;
}

setInterval(() => {
  if (document.getElementById("auto-refresh").checked) {
    refreshAll();
  }
}, 2500);

refreshAll();
</script>
</body>
</html>
"""
