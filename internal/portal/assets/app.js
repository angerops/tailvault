"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const app = $("#app");
const dialog = $("#dialog");
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const paths = {
  vault:
    '<rect x="4" y="4" width="16" height="16" rx="4"/><circle cx="12" cy="12" r="3"/><path d="M12 6v3m0 6v3M6 12h3m6 0h3"/>',
  key: '<circle cx="8" cy="8" r="4"/><path d="M10.4 10.4c2.4 1.9 3 5 5.4 6.9 1.5 1.2 3.1 1.7 5 1-1.3 1.9-3.8 2.1-5.9.4-2.5-2-3-5.3-5.4-7.1Z" fill="currentColor" stroke="none"/><path d="m13 14.5 2.2-2.2m.1 4.8 2.3-2.3"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10H3Z"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  settings: '<path d="m9 3-.6 2.4-2.1 1.2L4 6l-2 3.5 1.7 1.8v2.4L2 15.5 4 19l2.3-.6 2.1 1.2L9 22h4l.6-2.4 2.1-1.2 2.3.6 2-3.5-1.7-1.8v-2.4L20 9.5 18 6l-2.3.6-2.1-1.2L13 3Z"/><circle cx="11" cy="12.5" r="3"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M15 8V3H3v13h5"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
  upload: '<path d="M12 16V4m-5 5 5-5 5 5M4 16v5h16v-5"/>',
  edit: '<path d="m15 4 5 5L9 20H4v-5L15 4Zm-3 3 5 5"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  refresh:
    '<path d="M20 10a8 8 0 0 0-14-5L3 8m0-5v5h5m-4 6a8 8 0 0 0 14 5l3-3m0 5v-5h-5"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  shield:
    '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  history: '<path d="M3 10a9 9 0 1 1 1 7M3 4v6h6m3-3v6l4 2"/>',
  file: '<path d="M14 3H5v18h14V8l-5-5Zm0 0v5h5M8 13h8m-8 4h5"/>',
};
const icon = (name, cls = "") =>
  `<svg class="icon ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.key}</svg>`;
const button = (label, action, glyph, cls = "", attrs = "") =>
  `<button type="button" class="${cls}" data-action="${action}" ${attrs}>${glyph ? icon(glyph) : ""}${label}</button>`;
const state = {
  settings: null,
  session: null,
  secrets: [],
  selected: null,
  path: "",
  collapsedPaths: new Set(),
  query: "",
  tab: "overview",
  busy: false,
  epoch: 0,
  loading: true,
  error: "",
};
const requests = new Set();
const revealStates = new Map();
let connectionTimer,
  toastTimer,
  selectionSequence = 0;

async function request(url, body) {
  const controller = new AbortController();
  const epoch = state.epoch;
  requests.add(controller);
  try {
    const res = await fetch(url, {
      method: body === undefined ? "GET" : "POST",
      credentials: "omit",
      cache: "no-store",
      signal: controller.signal,
      headers: {
        "X-TailVault-Connection": state.session?.connection || "",
        ...(url === "/ui-api/settings" ? { "X-TailVault-Settings": state.settings?.settingsToken || "" } : {}),
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (epoch !== state.epoch)
      throw new DOMException("Vault locked", "AbortError");
    if (res.status === 401) {
      const message =
        (await res.text()).trim() || "Open the vault to reconnect.";
      lockView(message);
      throw new Error(message);
    }
    if (!res.ok)
      throw new Error(
        (await res.text()).slice(0, 240).trim() ||
          "The request could not be completed.",
      );
    const result = res.status === 204 ? null : await res.json();
    if (epoch !== state.epoch) throw new DOMException("Vault hidden", "AbortError");
    return result;
  } finally {
    requests.delete(controller);
  }
}
const validVersion = (value) => Number.isInteger(value) && value > 0 && value <= 4294967295;
function metadata(item) {
  if (!item || typeof item.Name !== "string" || !item.Name ||
      !Array.isArray(item.Versions) || !item.Versions.length ||
      !item.Versions.every(validVersion) || !validVersion(item.ActiveVersion) ||
      !item.Versions.includes(item.ActiveVersion) ||
      new Set(item.Versions).size !== item.Versions.length)
    throw new Error("Setec returned invalid secret metadata.");
  return { Name: item.Name, Versions: item.Versions, ActiveVersion: item.ActiveVersion };
}
async function api(op, body = {}) {
  const result = await request(`/ui-api/${op}`, body);
  if (op === "info") return metadata(result);
  if (op !== "list") return result;
  if (result === null) return [];
  if (!Array.isArray(result)) throw new Error("Setec returned invalid secret metadata.");
  return result.map(metadata);
}

function notify(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = error ? "error" : "";
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(
    () => {
      toast.hidden = true;
      toast.textContent = "";
    },
    error ? 9000 : 5000,
  );
}

function hideValue(reveal) {
  const entry = revealStates.get(reveal);
  if (!entry) return;
  clearTimeout(entry.timer);
  revealStates.delete(reveal);
  const { field } = entry;
  field.removeAttribute("aria-busy");
  if (field.id === "secret-value") {
    field.textContent = "••••••••••••••••••••••••";
    field.classList.add("masked");
    const label = $(".value-version");
    if (label) label.textContent = "Active version";
  } else {
    field.textContent = "";
    field.hidden = true;
  }
  reveal.innerHTML = icon("eye") + "Reveal";
  reveal.dataset.revealed = "";
  reveal.setAttribute("aria-expanded", "false");
  if (reveal.dataset.version)
    reveal.setAttribute("aria-label", `Reveal version ${reveal.dataset.version}`);
}

function clearValue() {
  selectionSequence++;
  for (const reveal of revealStates.keys()) hideValue(reveal);
}

function lockView(message = "", preserveSettings = false) {
  state.epoch++;
  for (const controller of requests) controller.abort();
  requests.clear();
  clearInterval(connectionTimer);
  clearValue();
  state.session = null;
  state.busy = false;
  state.secrets = [];
  state.selected = null;
  state.path = "";
  state.collapsedPaths.clear();
  state.query = "";
  state.error = message;
  if (!preserveSettings) {
    dialog.close();
    dialog.innerHTML = "";
  }
  $("#toast").hidden = true;
  $("#toast").textContent = "";
  renderConnection();
}

function renderConnection() {
  if (state.settings && !state.settings.server) return renderOnboarding();
  app.innerHTML = `<div class="login-page"><div class="login-brand"><img src="/icon.svg" alt="" width="32" height="32"><b>Tail<span class="wordmark-vault">Vault</span></b></div>
    ${button("Settings", "settings", "settings", "connection-settings", 'title="Settings (⌘,)"')}
    <main class="login-card"><img class="login-symbol" src="/icon.svg" alt="" width="88" height="88">
    <h1>Tail<span class="wordmark-vault">Vault</span></h1>${state.error ? `<p>${esc(state.error)}</p>` : `<div class="login-lock" role="img" aria-label="Vault hidden">${icon("lock")}</div>`}
    ${button("Open vault", "open-vault", "arrow", "primary login-button")}</main></div>`;
}

const serverField = (server = "") => `<label class="form-label">Setec server<input name="server" type="url" required maxlength="2048" value="${esc(server)}" placeholder="https://secrets.example.ts.net" autocomplete="off" spellcheck="false" autocapitalize="off" aria-describedby="server-hint"></label><p id="server-hint" class="server-hint">Use the HTTPS address provided by your Setec administrator.</p>`;

function bindServerForm(form, onboarding) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = $('button[type="submit"]', form);
    if (submit.disabled) return;
    const server = String(new FormData(form).get("server")).trim();
    const errorMessage = $(".server-error", form);
    errorMessage.hidden = true;
    const controls = form.querySelectorAll("button, input");
    controls.forEach((control) => { control.disabled = true; });
    submit.textContent = "Saving…";
    dialog.dataset.saving = "true";
    // Drop pending reads and all old vault data before changing destinations.
    if (!onboarding) lockView("", true);
    try {
      state.settings = await api("settings", { server });
      dialog.close();
      dialog.innerHTML = "";
      await load(true);
      notify("Server address saved.");
    } catch (error) {
      if (error.name !== "AbortError" && form.isConnected) {
        errorMessage.textContent = error.message;
        errorMessage.hidden = false;
      }
    } finally {
      controls.forEach((control) => { control.disabled = false; });
      submit.textContent = onboarding ? "Save and open vault" : "Save";
      delete dialog.dataset.saving;
    }
  });
}

function renderOnboarding() {
  app.innerHTML = `<div class="login-page"><div class="login-brand"><img src="/icon.svg" alt="" width="32" height="32"><b>Tail<span class="wordmark-vault">Vault</span></b></div>
    <main class="login-card setup-card"><img class="login-symbol" src="/icon.svg" alt="" width="72" height="72"><h1>Connect to Setec</h1><p class="setup-description">Add your server address to open your vault. Tailscale handles your identity and access.</p>
    <form id="setup-form">${serverField()}${state.settings?.error ? `<p class="form-error" role="alert">${esc(state.settings.error)}</p>` : ""}<p class="form-error server-error" id="setup-error" role="alert" hidden></p><button type="submit" class="primary setup-submit">Save and open vault</button><p class="server-hint">Saved on this Mac. You can change it later in Settings.</p></form></main></div>`;
  bindServerForm($("#setup-form"), true);
  $('input[name="server"]').focus();
}

let settingsOpening = false;
async function openSettings() {
  if (dialog.open || settingsOpening || !state.settings?.server) return;
  clearValue();
  settingsOpening = true;
  try {
    state.settings = await request("/ui-api/settings");
  } finally {
    settingsOpening = false;
  }
  if (dialog.open) return;
  dialog.dataset.kind = "settings";
  dialog.setAttribute("aria-labelledby", "settings-title");
  dialog.innerHTML = `<form id="settings-form"><div class="modal-heading"><h2 id="settings-title">Settings</h2>${button("", "close-dialog", "close", "icon-button", 'aria-label="Close dialog"')}</div><p class="modal-description">Setec connection</p>${serverField(state.settings.server)}<p class="server-hint">Saving reconnects the vault using your current Tailscale identity.</p><p class="form-error server-error" role="alert" hidden></p><div class="modal-actions">${button("Cancel", "close-dialog", "", "outlined")}<button type="submit" class="primary">Save</button></div></form>`;
  bindServerForm($("#settings-form"), false);
  dialog.showModal();
  $('input[name="server"]', dialog).focus();
}

async function initialize() {
  try {
    state.settings = await request("/ui-api/settings");
    if (!state.settings.server) renderOnboarding();
    else await load(true);
  } catch (error) {
    if (error.name !== "AbortError") {
      state.error = "Settings could not be loaded. Reopen TailVault to try again.";
      renderConnection();
    }
  }
}

let checkingConnection = false;
async function checkConnection() {
  if (!state.session || checkingConnection || dialog.dataset.kind === "settings") return;
  checkingConnection = true;
  try {
    await request("/ui-api/status");
  } catch (error) {
    if (error.name !== "AbortError" && state.session)
      lockView(
        "Tailscale connection unavailable. Open the vault to reconnect.",
      );
  } finally {
    checkingConnection = false;
  }
}
window.addEventListener("focus", checkConnection);

function basename(name) {
  return name.split("/").filter(Boolean).pop() || name;
}
function parent(name) {
  const index = name.lastIndexOf("/");
  return index < 0 ? "" : name.slice(0, index);
}
function kind(name) {
  return /\.(pem|crt|key|json|yaml|yml|env|txt)$/.test(name) ? "file" : "key";
}
function visible() {
  return state.secrets.filter(
    (s) =>
      (!state.path || s.Name.startsWith(state.path + "/")) &&
      s.Name.toLowerCase().includes(state.query.toLowerCase()),
  );
}
function allPaths() {
  const found = new Set();
  for (const s of state.secrets) {
    const parts = s.Name.split("/");
    parts.pop();
    for (let i = 1; i <= parts.length; i++)
      found.add(parts.slice(0, i).join("/"));
  }
  return [...found].filter(Boolean).sort((a, b) => a.localeCompare(b));
}

function pathTree() {
  const paths = allPaths();
  if (!paths.length)
    return '<p class="side-note">Accessible paths appear here as you add secrets.</p>';
  const children = new Map();
  const ids = new Map();
  paths.forEach((path, index) => {
    const group = parent(path);
    if (!children.has(group)) children.set(group, []);
    children.get(group).push(path);
    ids.set(path, `path-children-${index}`);
  });
  const branch = (group) =>
    (children.get(group) || [])
      .map((path) => {
        const hasChildren = children.has(path);
        const collapsed = state.collapsedPaths.has(path);
        const label = `${collapsed ? "Expand" : "Collapse"} ${path}`;
        return `<li><div class="path-row ${state.path === path ? "active" : ""}">
        ${hasChildren ? button('<span aria-hidden="true">/</span>', "toggle-path", "", "path-toggle", `data-path="${esc(path)}" aria-label="${esc(label)}" aria-expanded="${!collapsed}" aria-controls="${ids.get(path)}"`) : '<span class="path-toggle-space" aria-hidden="true"></span>'}
        <button type="button" class="nav-item ${state.path === path ? "active" : ""}" data-action="path" data-path="${esc(path)}" aria-label="${esc(path)}" ${state.path === path ? 'aria-current="location"' : ""}><span>${esc(basename(path))}</span></button>
        </div>${hasChildren ? `<ul class="path-tree" id="${ids.get(path)}" ${collapsed ? "hidden" : ""}>${branch(path)}</ul>` : ""}</li>`;
      })
      .join("");
  return `<ul class="path-tree">${branch("")}</ul>`;
}

function togglePath(target) {
  const path = target.dataset.path;
  const collapsed = !state.collapsedPaths.has(path);
  if (collapsed) state.collapsedPaths.add(path);
  else state.collapsedPaths.delete(path);
  document.getElementById(target.getAttribute("aria-controls")).hidden =
    collapsed;
  target.setAttribute("aria-expanded", String(!collapsed));
  const label = `${collapsed ? "Expand" : "Collapse"} ${path}`;
  target.setAttribute("aria-label", label);
}

function render() {
  if (!state.session) return renderConnection();
  const name = state.session.name || state.session.login;
  const serverHost = new URL(state.session.server).hostname;
  app.innerHTML = `<div class="workspace">
    <aside class="sidebar"><a href="/" class="brand"><img src="/icon.svg" alt="" width="35" height="35"><b>Tail<span class="wordmark-vault">Vault</span></b></a>
      <label class="search">${icon("search")}<input id="search" type="search" autocomplete="off" placeholder="Search…" aria-label="Search secrets" value="${esc(state.query)}"><kbd>⌘ K</kbd></label>
      <nav aria-label="Vault paths"><button class="nav-item ${!state.path ? "active" : ""}" data-action="path" data-path="">${icon("vault")}<span>All secrets</span><span class="count">${state.secrets.length}</span></button>
      <div class="side-heading path-heading">PATHS<span>${allPaths().length}</span></div><div id="paths">${pathTree()}</div></nav>
      <div class="sidebar-bottom">
      ${button("Settings", "settings", "settings", "sidebar-settings", 'title="Settings (⌘,)"')}
      <div class="profile"><div class="avatar">${esc(name.slice(0, 1).toUpperCase())}</div><div><strong>${esc(name)}</strong><small>${esc(state.session.login)}</small><small class="profile-server" title="Setec server: ${esc(serverHost)}">${esc(serverHost)}</small></div>${button("", "lock", "lock", "icon-button", 'aria-label="Hide vault" title="Hide vault"')}</div></div>
    </aside>
    <section class="main">
      ${state.session.preview ? '<div class="preview-banner">INTERFACE PREVIEW · SAMPLE DATA ONLY</div>' : ""}
      <div class="vault-content"><section class="secret-list" aria-label="Secrets"><header class="list-heading"><div class="vault-heading"><h1 id="view-title" title="${esc(state.path || "All secrets")}">${esc(state.path ? basename(state.path) : "All secrets")}</h1><span id="view-count" class="view-count">${visible().length}</span></div>${button("", "refresh", "refresh", "icon-button", 'aria-label="Refresh secrets" title="Refresh secrets"')}</header><div class="secret-list-body"><div id="secret-rows"></div><div id="list-scrollbar" class="list-scrollbar" aria-hidden="true"><div></div></div></div></section>
      <div class="detail-pane"><header class="vault-actions">${button("", "new", "plus", "primary icon-button", 'aria-label="New secret" title="New secret (⌘N)"')}</header><section id="detail" class="detail" aria-label="Secret details"></section></div></div>
    </section></div>`;
  renderRows();
  renderDetail();
}

function renderRows() {
  const rows = $("#secret-rows");
  if (!rows) return;
  const matches = visible();
  $("#view-count").textContent = matches.length;
  rows.innerHTML = state.loading
    ? '<div class="list-empty" role="status">Loading secrets…</div>'
    : state.error
      ? `<div class="list-empty"><b>Couldn’t load secrets</b><p>${esc(state.error)}</p>${button("Try again", "refresh", "refresh")}</div>`
      : matches.length
        ? matches
            .map(
              (s) =>
                `<button class="secret-row ${state.selected?.Name === s.Name ? "selected" : ""}" data-action="select" data-name="${esc(s.Name)}" aria-pressed="${state.selected?.Name === s.Name}"><span class="secret-icon ${kind(s.Name)}">${icon(kind(s.Name))}</span><span class="row-copy"><strong>${esc(basename(s.Name))}</strong><small>${esc(parent(s.Name) || "Root path")}</small></span>${icon("chevron")}</button>`,
            )
            .join("")
        : `<div class="list-empty">${icon("search")}<b>${state.query ? "No matching secrets" : "No secrets"}</b><p>${state.query ? "Try another name or path." : "Only secrets visible to your Tailscale identity appear here."}</p>${!state.query ? button("Create a secret", "new", "plus", "subtle") : ""}</div>`;
  syncListScrollbar();
}

function syncListScrollbar() {
  const rows = $("#secret-rows"), scrollbar = $("#list-scrollbar");
  if (!rows || !scrollbar) return;
  scrollbar.hidden = rows.scrollHeight <= rows.clientHeight;
  scrollbar.firstElementChild.style.height = `${rows.scrollHeight}px`;
  scrollbar.scrollTop = rows.scrollTop;
}

function renderDetail() {
  clearValue();
  const detail = $("#detail");
  if (!detail) return;
  const s = state.selected;
  if (!s) {
    detail.innerHTML = `<div class="detail-empty"><img class="empty-illustration" src="/icon.svg" alt="" width="88" height="88"><h2>No secret selected</h2><p>Select a secret to view its details.</p>${button("New secret", "new", "plus", "primary")}</div>`;
    return;
  }
  detail.innerHTML = `<div class="detail-header"><span class="secret-icon hero-icon ${kind(s.Name)}">${icon(kind(s.Name))}</span><div class="detail-heading"><h2>${esc(basename(s.Name))}</h2><div class="detail-path"><code>${esc(s.Name)}</code>${button("", "copy-path", "copy", "icon-button", 'aria-label="Copy secret path" title="Copy path"')}</div></div>${button("Edit", "edit", "edit", "outlined")}</div>
    <div class="detail-tabs" role="tablist" aria-label="Secret views"><button role="tab" aria-selected="${state.tab === "overview"}" data-action="tab" data-tab="overview" class="${state.tab === "overview" ? "active" : ""}">Overview</button><button role="tab" aria-selected="${state.tab === "versions"}" data-action="tab" data-tab="versions" class="${state.tab === "versions" ? "active" : ""}">Versions <span>${s.Versions?.length ?? "—"}</span></button><button role="tab" aria-selected="${state.tab === "terminal"}" data-action="tab" data-tab="terminal" class="${state.tab === "terminal" ? "active" : ""}">Use in terminal</button></div>
    <div class="detail-body">${state.tab === "overview" ? overview(s) : state.tab === "versions" ? versions(s) : terminal(s)}</div>
    <div class="detail-bottom">${icon("shield")}Access controlled by Setec${button("Delete secret", "delete", "trash", "danger subtle")}</div>`;
  if (state.tab === "terminal") updateCurlPreview();
}

function overview(s) {
  return `<div class="value-panel"><div class="field-label">Value<span class="value-version">Active version</span></div><pre id="secret-value" class="masked" aria-live="polite">••••••••••••••••••••••••</pre><div class="value-actions">${button("Reveal", "reveal", "eye", "subtle", 'aria-controls="secret-value" aria-expanded="false"')}${button("Copy", "copy", "copy", "subtle")}${button("Download", "download", "download", "subtle")}${button("Copy curl", "copy-curl", "copy", "subtle")}</div></div>`;
}

function terminal(s) {
  return `<div class="section-title"><div><h3>Fetch this secret with curl</h3><p>Run it from a device with Tailscale access to this path.</p></div></div>
    <div class="curl-options"><label>Version<select id="curl-version"><option value="0">Active version</option>${(
      s.Versions || []
    )
      .slice()
      .sort((a, b) => b - a)
      .map(
        (v) =>
          `<option value="${esc(v)}">Version ${esc(v)}${v === s.ActiveVersion ? " (currently active)" : ""}</option>`,
      )
      .join(
        "",
      )}</select></label><label>Output<select id="curl-output"><option value="json">JSON response</option><option value="decoded">Decoded secret bytes</option></select></label></div>
    <div class="curl-panel"><div class="field-label">SHELL COMMAND${button("Copy curl", "copy-curl", "copy", "outlined", "disabled")}</div><pre id="curl-command" tabindex="0" aria-label="curl command">Preparing command…</pre></div>
    <p id="curl-help" class="curl-help">JSON includes a base64-encoded Value and the version number.</p>
    <div class="soft-note compact">${icon("shield")}The command uses the caller’s Tailscale permissions. It contains no secret value or sign-in credentials.</div>`;
}

function curlInput() {
  return {
    Name: state.selected.Name,
    Version: Number($("#curl-version")?.value || 0),
    Decode: $("#curl-output")?.value === "decoded",
  };
}

async function updateCurlPreview() {
  const preview = $("#curl-command");
  const copyButton = $('[data-action="copy-curl"]', $("#detail"));
  if (!copyButton || !state.selected) return;
  const input = curlInput();
  const key = JSON.stringify(input);
  copyButton.dataset.request = key;
  copyButton.disabled = true;
  if (preview) {
    preview.textContent = "Preparing command…";
    $("#curl-help").textContent = input.Decode
      ? "Requires Python 3. Writes the exact secret bytes to standard output."
      : "JSON includes a base64-encoded Value and the version number.";
  }
  try {
    const result = await api("curl", input);
    if (!copyButton.isConnected || copyButton.dataset.request !== key) return;
    if (preview) preview.textContent = result.command;
    copyButton.disabled = false;
  } catch (error) {
    if (
      copyButton.isConnected &&
      copyButton.dataset.request === key &&
      error.name !== "AbortError"
    ) {
      if (preview) preview.textContent = error.message;
      else notify(error.message, true);
    }
  }
}

async function copyCurl() {
  const input = curlInput();
  const epoch = state.epoch;
  await api("copy-curl", input);
  if (epoch === state.epoch) notify("curl command copied.");
}

function versions(s) {
  return `<div class="section-title"><div><h3>Version history</h3><p>The active version is served to your clients.</p></div>${button("Import version", "import", "upload", "subtle")}</div>
    ${
      (s.Versions || [])
        .slice()
        .sort((a, b) => b - a)
        .map(
          (v) =>
            `<div class="version-row"><span class="version-number">${icon("history")}<strong>Version ${esc(v)}</strong>${v === s.ActiveVersion ? '<span class="tag green">Active</span>' : '<span class="tag">Inactive</span>'}</span><div class="version-actions">${button("Reveal", "reveal", "eye", "subtle", `data-version="${esc(v)}" aria-label="Reveal version ${esc(v)}" aria-controls="version-value-${esc(v)}" aria-expanded="false"`)}${button("", "download", "download", "icon-button", `data-version="${esc(v)}" aria-label="Download version ${esc(v)}"`)}${v !== s.ActiveVersion ? button("Activate", "activate", "", "outlined", `data-version="${esc(v)}"`) + button("", "delete-version", "trash", "icon-button danger", `data-version="${esc(v)}" aria-label="Delete version ${esc(v)}"`) : ""}</div><pre id="version-value-${esc(v)}" class="version-value" aria-label="Version ${esc(v)} value" aria-live="polite" tabindex="0" hidden></pre></div>`,
        )
        .join("") ||
      '<p class="muted">Version metadata is not available for this path. Reading its value may still be allowed.</p>'
    }`;
}

async function load(initial = false) {
  // Refresh must never reopen a hidden or revoked view.
  if (!initial && !state.session) return;
  if (!state.settings?.server) return initial ? initialize() : undefined;
  if (state.busy) return;
  state.busy = true;
  const epoch = state.epoch;
  try {
    if (initial) {
      const session = await request("/ui-api/session");
      if (epoch !== state.epoch) return;
      state.session = session;
      clearInterval(connectionTimer);
      connectionTimer = setInterval(checkConnection, 5000);
      state.loading = true;
      render();
    }
    const secrets = await api("list");
    if (epoch !== state.epoch) return;
    state.secrets = (secrets || []).sort((a, b) =>
      a.Name.localeCompare(b.Name),
    );
    if (state.selected && !state.selected.direct)
      state.selected =
        state.secrets.find((s) => s.Name === state.selected.Name) || null;
    const paths = new Set(allPaths());
    if (state.path && !paths.has(state.path)) state.path = "";
    for (const path of state.collapsedPaths)
      if (!paths.has(path)) state.collapsedPaths.delete(path);
    state.error = "";
    state.loading = false;
    render();
  } catch (error) {
    if (error.name !== "AbortError" && state.session && epoch === state.epoch) {
      state.secrets = [];
      state.selected = null;
      state.loading = false;
      state.error = error.message;
      render();
    } else if (error.name !== "AbortError" && !state.session) {
      if (epoch === state.epoch) state.error = error.message;
      renderConnection();
    }
  } finally {
    if (epoch === state.epoch) state.busy = false;
  }
}

function openDialog(title, content, submit, label = "Save", danger = false) {
  if (dialog.open || !state.session) return;
  clearValue();
  delete dialog.dataset.kind;
  dialog.setAttribute("aria-labelledby", "modal-title");
  dialog.innerHTML = `<form id="modal-form"><div class="modal-heading"><h2 id="modal-title">${esc(title)}</h2>${button("", "close-dialog", "close", "icon-button", 'aria-label="Close dialog"')}</div>${content}<p id="form-error" class="form-error" role="alert" hidden></p><div class="modal-actions">${button("Cancel", "close-dialog", "", "outlined")}<button type="submit" class="${danger ? "destructive" : "primary"}">${esc(label)}</button></div></form>`;
  const epoch = state.epoch;
  $("#modal-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitButton = $('button[type="submit"]', dialog);
    if (submitButton.disabled) return;
    submitButton.disabled = true;
    const cancelButtons = dialog.querySelectorAll(
      '[data-action="close-dialog"]',
    );
    cancelButtons.forEach((b) => {
      b.disabled = true;
    });
    dialog.dataset.saving = "true";
    $("#form-error").hidden = true;
    try {
      await submit(new FormData(event.target));
      if (epoch !== state.epoch) return;
      dialog.close();
      dialog.innerHTML = "";
    } catch (error) {
      if (
        epoch === state.epoch &&
        error.name !== "AbortError" &&
        $("#form-error")
      ) {
        $("#form-error").textContent = error.message;
        $("#form-error").hidden = false;
      }
    } finally {
      submitButton.disabled = false;
      cancelButtons.forEach((b) => {
        b.disabled = false;
      });
      delete dialog.dataset.saving;
    }
  });
  dialog.showModal();
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192)
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}
function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
function textValue(bytes) {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return /[\x00-\x08\x0e-\x1f]/.test(text) ? null : text;
  } catch {
    return null;
  }
}

function editSecret(mode = "new") {
  if (dialog.open || settingsOpening || !state.session) return;
  const epoch = state.epoch;
  const s = state.selected;
  const existing = mode !== "new";
  const name = existing ? s.Name : state.path ? state.path + "/" : "";
  openDialog(
    mode === "import"
      ? "Import a specific version"
      : existing
        ? "Save a new version"
        : "New secret",
    `
    <p class="modal-description">${mode === "import" ? "Import an unused version number. Setec immediately makes this version active." : existing ? "Enter a replacement value. Existing versions remain available." : "Give your secret a path, then add a value or upload a file."}</p>
    <label class="form-label">Secret path<input name="name" required maxlength="4096" placeholder="personal/service/api-key" value="${esc(name)}" ${existing ? "readonly" : ""} autocomplete="off" spellcheck="false"></label>
    ${mode === "import" ? '<label class="form-label">Version number<input name="version" required type="number" min="1" max="4294967295" step="1" placeholder="e.g. 5"></label>' : ""}
    <label class="form-label">Value<textarea name="value" rows="5" placeholder="Enter the secret value…" autocomplete="off" spellcheck="false" autocapitalize="off" class="secret-input"></textarea></label>
    <div class="editor-tools"><label class="checkbox"><input id="show-input" type="checkbox">Show value</label>${button("Generate password", "generate", "key", "subtle")}</div>
    <label class="file-drop">${icon("upload")}<strong>Or choose a file</strong><span>Up to 1 MiB · file bytes are preserved</span><span class="file-picker" aria-hidden="true">Choose file</span><span class="file-name" id="selected-file" aria-live="polite">No file selected</span><input name="file" type="file" aria-label="Upload a secret file" aria-describedby="selected-file"></label>
    <label class="checkbox"><input name="empty" type="checkbox">Allow an empty value</label>
    ${existing && mode !== "import" ? '<label class="checkbox"><input name="activate" type="checkbox">Activate this version after saving</label>' : ""}`,
    async (form) => {
      const path = String(form.get("name"));
      if (!path || path.trim() !== path)
        throw new Error("Enter a path without surrounding spaces.");
      const file = form.get("file");
      const text = String(form.get("value"));
      if (file?.name && text)
        throw new Error("Use either a text value or a file.");
      if (file?.size > 1048576)
        throw new Error("Choose a file no larger than 1 MiB.");
      const bytes = file?.name
        ? new Uint8Array(await file.arrayBuffer())
        : new TextEncoder().encode(text);
      if (bytes.length > 1048576)
        throw new Error("The value must be no larger than 1 MiB.");
      if (!bytes.length && !form.has("empty"))
        throw new Error(
          "Enter a value, select a file, or allow an empty value.",
        );
      let version;
      try {
        if (mode === "import") {
          version = Number(form.get("version"));
          await api("create-version", {
            Name: path,
            Version: version,
            Value: bytesToBase64(bytes),
          });
        } else
          version = await api("put", {
            Name: path,
            Value: bytesToBase64(bytes),
          });
      } finally {
        bytes.fill(0);
      }
      if (epoch !== state.epoch)
        throw new DOMException("Vault locked", "AbortError");
      let message = `Version ${version} saved${mode === "import" || version === 1 ? " and active" : ". Activate it when ready"}.`;
      if (existing && mode !== "import" && form.has("activate")) {
        try {
          await api("activate", { Name: path, Version: version });
          message = `Version ${version} saved and activated.`;
        } catch (error) {
          if (error.name === "AbortError" || epoch !== state.epoch || !state.session) throw error;
          message = `Version ${version} was saved, but activation failed: ${error.message}`;
        }
      }
      if (epoch !== state.epoch || !state.session)
        throw new DOMException("Vault hidden", "AbortError");
      await load();
      if (epoch !== state.epoch || !state.session)
        throw new DOMException("Vault locked", "AbortError");
      state.selected = state.secrets.find((s) => s.Name === path) || {
        Name: path,
        direct: true,
      };
      state.tab = "overview";
      renderRows();
      renderDetail();
      notify(message);
    },
    mode === "import" ? "Import and activate" : "Save version",
  );
  $("#show-input").addEventListener("change", (e) =>
    $("textarea", dialog).classList.toggle("secret-input", !e.target.checked),
  );
}

async function secretValue(action, version, reveal) {
  if (!state.selected) return;
  if (action === "download" || action === "copy") {
    const result = await api(action, { Name: state.selected.Name, Version: version || 0 });
    if (action === "copy") notify("Secret copied to clipboard.");
    else if (result?.saved) notify("Secret saved to file.");
    return;
  }
  const field = document.getElementById(reveal.getAttribute("aria-controls"));
  if (!field) return;
  hideValue(reveal);
  const entry = { field, timer: null };
  revealStates.set(reveal, entry);
  const name = state.selected.Name,
    sequence = selectionSequence,
    epoch = state.epoch;
  const current = () =>
    epoch === state.epoch &&
    sequence === selectionSequence &&
    revealStates.get(reveal) === entry &&
    name === state.selected?.Name &&
    field.isConnected &&
    !dialog.open &&
    !document.hidden &&
    document.hasFocus();
  field.classList.add("masked");
  field.textContent = "••••••••••••••••••••••••";
  field.setAttribute("aria-busy", "true");
  field.hidden = false;
  reveal.innerHTML = icon("eye") + "Hide";
  reveal.dataset.revealed = "true";
  reveal.setAttribute("aria-expanded", "true");
  if (version) reveal.setAttribute("aria-label", `Hide version ${version}`);
  let bytes;
  try {
    const value = await api("get", { Name: name, Version: version || 0 });
    if (!current()) return;
    if (!Number.isInteger(value.Version) || value.Version < 1 || value.Version > 4294967295 ||
        (version && value.Version !== version))
      throw new Error("Setec returned an invalid secret version.");
    bytes = base64ToBytes(value.Value);
    const text = textValue(bytes);
    if (text === null) {
      hideValue(reveal);
      notify("This is a binary secret. Use Download to preserve its bytes.");
      return;
    }
    if (!version) $(".value-version").textContent = `Version ${value.Version}`;
    field.textContent = text || "(empty value)";
    field.classList.remove("masked");
    field.removeAttribute("aria-busy");
    entry.timer = setTimeout(() => hideValue(reveal), 30000);
  } catch (error) {
    if (!current()) return;
    hideValue(reveal);
    throw error;
  } finally {
    bytes?.fill(0);
  }
}

function confirmAction(op, version) {
  const s = state.selected;
  const removing = op === "delete" || op === "delete-version";
  const title =
    op === "delete"
      ? "Delete this secret?"
      : op === "delete-version"
        ? `Delete version ${version}?`
        : `Activate version ${version}?`;
  openDialog(
    title,
    `<p class="modal-description">${op === "delete" ? "This permanently removes every version of this secret from Setec." : op === "delete-version" ? "This permanently removes this inactive version. Its version number cannot be reused." : "Clients will receive this version the next time they fetch the active secret."}</p><code class="confirm-path">${esc(s.Name)}</code>${removing ? '<label class="form-label">Type the full secret path to confirm<input name="confirm" required autocomplete="off" spellcheck="false"></label>' : ""}`,
    async (form) => {
      if (removing && form.get("confirm") !== s.Name)
        throw new Error("The path does not match.");
      await api(op, { Name: s.Name, ...(version ? { Version: version } : {}) });
      await load();
      notify(
        op === "activate"
          ? `Version ${version} is now active.`
          : "Deleted from Setec.",
      );
    },
    removing ? "Delete permanently" : "Activate version",
    removing,
  );
}

async function dispatchAction(action, target) {
  if (target?.disabled) return;
  // Native menus, shortcuts, and DOM controls share the same availability rules.
  if (dialog.open && action !== "lock" &&
      (!target || !dialog.contains(target) || dialog.dataset.saving)) return;
  if (settingsOpening && action !== "lock") return;
  if (!["settings", "open-vault", "close-dialog"].includes(action) && !state.session) return;
  try {
    switch (action) {
      case "search":
        $("#search")?.focus();
        break;
      case "settings":
        await openSettings();
        break;
      case "toggle-path":
        togglePath(target);
        break;
      case "open-vault":
        await load(true);
        break;
      case "lock":
        try {
          await api("close");
        } finally {
          lockView();
        }
        break;
      case "path":
        state.path = target.dataset.path;
        state.collapsedPaths.delete(state.path);
        state.selected = null;
        state.query = "";
        selectionSequence++;
        render();
        break;
      case "select":
        state.selected = state.secrets.find(
          (s) => s.Name === target.dataset.name,
        );
        state.tab = "overview";
        selectionSequence++;
        renderRows();
        renderDetail();
        break;
      case "tab":
        state.tab = target.dataset.tab;
        selectionSequence++;
        renderDetail();
        break;
      case "refresh":
        clearValue();
        await load();
        break;
      case "new":
        editSecret();
        break;
      case "edit":
        editSecret("edit");
        break;
      case "import":
        editSecret("import");
        break;
      case "close-dialog":
        dialog.close();
        dialog.innerHTML = "";
        break;
      case "copy-path":
        await api("copy-path", { Name: state.selected.Name });
        notify("Path copied.");
        break;
      case "copy-curl":
        await copyCurl();
        break;
      case "reveal":
        if (target.dataset.revealed) hideValue(target);
        else await secretValue(action, Number(target.dataset.version) || 0, target);
        break;
      case "copy":
      case "download":
        await secretValue(action, Number(target.dataset.version) || 0);
        break;
      case "delete":
      case "delete-version":
      case "activate":
        confirmAction(action, Number(target.dataset.version));
        break;
      case "generate": {
        const bytes = crypto.getRandomValues(new Uint8Array(24));
        $("textarea", dialog).value = bytesToBase64(bytes);
        bytes.fill(0);
        break;
      }
    }
  } catch (error) {
    if (error.name !== "AbortError" && (state.session || action === "settings"))
      notify(error.message, true);
  }
}
window.tailvaultAction = (action) => dispatchAction(action);
document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (target) void dispatchAction(target.dataset.action, target);
});

// Capture scrolls from each pane independently, including newly rendered editors.
const scrollbarTimers = new WeakMap();
function showScrollbar(pane) {
  clearTimeout(scrollbarTimers.get(pane));
  pane.classList.add("auto-scrollbar", "scrollbar-active");
  scrollbarTimers.set(pane, setTimeout(() => {
    pane.classList.remove("scrollbar-active");
    scrollbarTimers.delete(pane);
  }, 900));
}
document.addEventListener("scroll", (event) => {
  const pane = event.target === document ? document.scrollingElement : event.target;
  if (!(pane instanceof Element)) return;
  if (pane.id === "secret-rows") {
    const scrollbar = $("#list-scrollbar");
    scrollbar.scrollTop = pane.scrollTop;
    showScrollbar(scrollbar);
  } else if (pane.id === "list-scrollbar") {
    $("#secret-rows").scrollTop = pane.scrollTop;
  }
  showScrollbar(pane);
}, { capture: true, passive: true });
window.addEventListener("resize", syncListScrollbar);

document.addEventListener("input", (event) => {
  if (event.target.id === "search") {
    state.query = event.target.value;
    renderRows();
  }
});
document.addEventListener("change", (event) => {
  if (event.target.matches('.file-drop input[type="file"]')) {
    $(".file-name", event.target.closest(".file-drop")).textContent =
      event.target.files[0]?.name || "No file selected";
  }
  if (event.target.id === "curl-version" || event.target.id === "curl-output")
    updateCurlPreview();
});
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "," && !dialog.open) {
    event.preventDefault();
    void dispatchAction("settings");
  }
  const disclosure = event.target.closest('[data-action="toggle-path"]');
  if (disclosure && (event.key === "ArrowLeft" || event.key === "ArrowRight")) {
    event.preventDefault();
    const expand = event.key === "ArrowRight";
    if ((disclosure.getAttribute("aria-expanded") === "true") !== expand)
      togglePath(disclosure);
    return;
  }
  if (
    (event.metaKey || event.ctrlKey) &&
    event.key.toLowerCase() === "k" &&
    !dialog.open
  ) {
    event.preventDefault();
    void dispatchAction("search");
  }
  if (
    (event.metaKey || event.ctrlKey) &&
    event.key.toLowerCase() === "n" &&
    !dialog.open &&
    state.session
  ) {
    event.preventDefault();
    void dispatchAction("new");
  }
  if (
    (event.metaKey || event.ctrlKey) &&
    event.shiftKey &&
    event.key.toLowerCase() === "l" &&
    state.session
  ) {
    event.preventDefault();
    void dispatchAction("lock");
  }
});
document.addEventListener("dragover", (event) => {
  if (event.dataTransfer?.types.includes("Files")) event.preventDefault();
});
document.addEventListener("drop", (event) => {
  if (!event.dataTransfer?.files.length) return;
  event.preventDefault();
  const input = $('input[type="file"]', dialog);
  if (!dialog.open || !input || dialog.dataset.saving) {
    notify("Open New secret or Edit to drop a file.");
    return;
  }
  if (event.dataTransfer.files.length !== 1) {
    notify("Drop one secret file at a time.", true);
    return;
  }
  input.files = event.dataTransfer.files;
  input.dispatchEvent(new Event("change", { bubbles: true }));
});
dialog.addEventListener("cancel", (event) => {
  if (dialog.dataset.saving) event.preventDefault();
});
dialog.addEventListener("close", () => {
  if (!dialog.open) {
    dialog.innerHTML = "";
    delete dialog.dataset.kind;
    dialog.removeAttribute("aria-labelledby");
    checkConnection();
  }
});
document.addEventListener("visibilitychange", () => {
  clearValue();
  if (!document.hidden && state.session && !dialog.open) load();
});
window.addEventListener("blur", clearValue);
window.addEventListener("pagehide", lockView);
initialize();
