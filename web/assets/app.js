// VortexSSH web UI. Plain browser JavaScript, no build step.
//
// Each tab opens one WebSocket to the server, which holds one SSH
// connection: terminal bytes travel as binary frames, everything else as
// JSON (see web/src/conn.rs). Text from the server or remote machines is
// only ever inserted with textContent, never as HTML.
"use strict";

const $ = (selector, root = document) => root.querySelector(selector);

const SEND_CHUNK = 64 * 1024;

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== undefined && value !== null && value !== false) node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children) if (child != null) node.append(child);
  return node;
}

// The access token arrives in the link's #fragment (never sent to any
// server) and is kept in localStorage, which only this origin, i.e. this
// port, can read. It goes with every request as a header; there is no
// cookie, because browsers send cookies to every port on 127.0.0.1.
const TOKEN_KEY = "vortexssh-token";
{
  const match = location.hash.match(/token=([0-9a-f]+)/);
  if (match) {
    localStorage.setItem(TOKEN_KEY, match[1]);
    history.replaceState(null, "", "/");
  }
}
const token = () => localStorage.getItem(TOKEN_KEY) || "";

/// Shown when there is no valid token (e.g. the server was restarted).
/// Only forgets `refused`, not a newer token another tab stored meanwhile.
function needLink(refused) {
  if (token() === refused) localStorage.removeItem(TOKEN_KEY);
  $("#welcome").replaceChildren(
    el("img", { src: "/assets/icon.svg", alt: "", width: "72", height: "72" }),
    el("h1", { text: "VortexSSH" }),
    el("p", { class: "muted", text: "Open the link that vortexssh-web printed when it started." }));
  for (const b of document.querySelectorAll("#sidebar button")) b.disabled = true;
}

async function api(method, url, body) {
  const used = token();
  const options = { method, headers: { Authorization: `Bearer ${used}` } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  if (response.status === 401) needLink(used);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `${response.status} ${response.statusText}`);
  }
  return response.status === 204 ? null : response.json();
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = -1;
  do { value /= 1024; unit++; } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function formatTime(seconds) {
  if (seconds == null) return "";
  return new Date(seconds * 1000).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function formatMode(perm, dir, link) {
  if (perm == null) return "";
  const kind = link ? "l" : dir ? "d" : "-";
  let text = kind;
  for (const shift of [6, 3, 0]) {
    const bits = (perm >> shift) & 7;
    text += (bits & 4 ? "r" : "-") + (bits & 2 ? "w" : "-") + (bits & 1 ? "x" : "-");
  }
  return text;
}

function joinPath(dir, name) {
  return dir.endsWith("/") ? dir + name : `${dir}/${name}`;
}

function parentPath(path) {
  if (path === "/" || !path.includes("/")) return "/";
  const parent = path.replace(/\/+$/, "").replace(/\/[^/]*$/, "");
  return parent === "" ? "/" : parent;
}

// ---------------------------------------------------------------------------
// Dialogs. Questions (login prompts, confirmations) are queued so that two
// tabs asking at once take turns.

const askDialog = $("#ask-dialog");
const askQueue = [];
let asking = null;

/// Shows a question; resolves with the answer, or null when cancelled.
/// `spec`: { title, message, fields: [{label, secret, value}], ok, cancel,
///           danger, monospace, owner }
function ask(spec) {
  return new Promise((resolve) => {
    askQueue.push({ spec, resolve });
    if (!asking) nextQuestion();
  });
}

function nextQuestion() {
  asking = askQueue.shift() || null;
  if (!asking) return;
  const { spec } = asking;
  $(".title", askDialog).textContent = spec.title;
  const message = $(".message", askDialog);
  message.textContent = spec.message || "";
  message.hidden = !spec.message;
  const fields = $(".fields", askDialog);
  fields.replaceChildren();
  if (spec.monospace) fields.append(el("div", { class: "fingerprint", text: spec.monospace }));
  for (const field of spec.fields || []) {
    const input = el("input", {
      type: field.secret ? "password" : "text",
      autocomplete: field.secret ? "off" : "off",
      spellcheck: "false",
    });
    input.value = field.value || "";
    fields.append(el("label", { text: field.label }, input));
  }
  const ok = $(".ok", askDialog);
  ok.textContent = spec.ok || "OK";
  ok.classList.toggle("danger", !!spec.danger);
  ok.classList.toggle("primary", !spec.danger);
  $(".cancel", askDialog).textContent = spec.cancel || "Cancel";
  askDialog.returnValue = "";
  askDialog.showModal();
  // Dangerous confirmations start on Cancel, so a stray Enter is harmless.
  const first = $("input", fields);
  (first || (spec.danger ? $(".cancel", askDialog) : ok)).focus();
}

askDialog.addEventListener("close", () => {
  if (!asking) return;
  const current = asking;
  let answer = null;
  if (askDialog.returnValue === "ok") {
    const values = [...askDialog.querySelectorAll(".fields input")].map((i) => i.value);
    answer = current.spec.fields && current.spec.fields.length ? values : true;
  }
  $(".fields", askDialog).replaceChildren(); // drop typed secrets
  asking = null;
  current.resolve(answer);
  nextQuestion();
});

/// Drops the questions of a closed tab, or only the one with `serverId`.
function cancelQuestions(owner, serverId) {
  const matches = (spec) => spec.owner === owner && (serverId === undefined || spec.serverId === serverId);
  for (let i = askQueue.length - 1; i >= 0; i--) {
    if (matches(askQueue[i].spec)) askQueue.splice(i, 1)[0].resolve(null);
  }
  if (asking && matches(asking.spec)) askDialog.close("cancel");
}

// ---------------------------------------------------------------------------
// Tabs

const tabsBar = $("#tabs");
const views = $("#views");
const welcome = $("#welcome");
const tabs = [];
let selected = null;

const encoder = new TextEncoder();

const TERMINAL_THEME = {
  background: "#0b0d11",
  foreground: "#d7dce5",
  cursor: "#d7dce5",
  selectionBackground: "#3a4a6b",
  black: "#1c2028", red: "#f0605a", green: "#3fb950", yellow: "#d29922",
  blue: "#4f8cff", magenta: "#c678dd", cyan: "#39c5cf", white: "#d7dce5",
  brightBlack: "#5c6370", brightRed: "#ff7b72", brightGreen: "#56d364", brightYellow: "#e3b341",
  brightBlue: "#79c0ff", brightMagenta: "#d2a8ff", brightCyan: "#56d4dd", brightWhite: "#ffffff",
};

const FORWARD_HELP = {
  local: "[bind:]port:host:hostport. Connections to this machine's port go through the server to host:hostport.",
  remote: "[bind:]port:host:hostport. Connections to the server's port come back to host:hostport from here.",
  dynamic: "[bind:]port. A SOCKS5 proxy on this machine that connects through the server.",
};

class Tab {
  /// `target`: what to send in `connect` ({target, port, identity} or {profile}).
  constructor(title, target) {
    this.title = title;
    this.target = target;
    this.conn = null;
    this.ws = null;
    this.nextId = 1;
    this.replies = new Map();
    this.cwd = null;

    this.button = el("div", { class: "tab", role: "tab", tabindex: "0", title, onclick: () => select(this) },
      el("span", { class: "label", text: title }),
      el("button", { class: "close", title: "Close", "aria-label": "Close tab",
        onclick: (e) => { e.stopPropagation(); this.close(); } }, "×"));
    this.button.addEventListener("keydown", (e) => { if (e.key === "Enter") select(this); });
    tabsBar.append(this.button);

    this.view = $("#tab-view").content.firstElementChild.cloneNode(true);
    views.append(this.view);
    this.status = $(".status-text", this.view);
    this.warnings = $(".warnings", this.view);
    this.filesPanel = $(".files-panel", this.view);
    this.forwardsPanel = $(".forwards-panel", this.view);
    this.filesButton = $(".toggle-files", this.view);
    this.forwardsButton = $(".toggle-forwards", this.view);

    this.term = new Terminal({
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", "Fira Code", "DejaVu Sans Mono", ui-monospace, monospace',
      fontSize: 14,
      scrollback: 10000,
      theme: TERMINAL_THEME,
      allowProposedApi: false,
    });
    this.fit = new FitAddon.FitAddon();
    this.term.loadAddon(this.fit);
    this.term.open($(".terminal", this.view));
    this.term.onData((data) => this.sendBytes(encoder.encode(data)));
    this.term.onBinary((data) => this.sendBytes(Uint8Array.from(data, (c) => c.charCodeAt(0) & 0xff)));
    this.term.onResize(({ cols, rows }) => this.sendJson({ type: "resize", cols, rows }));
    // The tab keeps the host name, so tabs stay distinguishable; the
    // shell's window title goes into the tooltip.
    this.term.onTitleChange((t) => { this.button.title = t ? `${title} — ${t}` : title; });
    this.resizer = new ResizeObserver(() => this.refit());
    this.resizer.observe($(".terminal-wrap", this.view));

    this.setupFiles();
    this.setupForwards();
    $(".toggle-files", this.view).addEventListener("click", () => this.togglePanel(this.filesPanel));
    $(".toggle-forwards", this.view).addEventListener("click", () => this.togglePanel(this.forwardsPanel));
    for (const close of this.view.querySelectorAll(".close-panel")) {
      close.addEventListener("click", () => this.togglePanel(close.closest(".panel"), false));
    }

    tabs.push(this);
    select(this);
    this.connect();
  }

  refit() {
    if (this.view.hidden) return;
    try { this.fit.fit(); } catch (_) { /* not laid out yet */ }
  }

  setState(state, text) {
    this.view.classList.toggle("connected", state === "connected");
    this.view.classList.toggle("closed", state === "closed");
    this.status.textContent = text;
    const ready = state === "connected";
    this.filesButton.disabled = !ready;
    this.forwardsButton.disabled = !ready;
    if (!ready) {
      this.togglePanel(this.filesPanel, false);
      this.togglePanel(this.forwardsPanel, false);
    }
  }

  connect() {
    $(".closed-banner", this.view)?.remove();
    this.warnings.replaceChildren();
    this.warnings.hidden = true;
    this.conn = null;
    this.setCwd(null);
    this.entries = [];
    this.fileRows.replaceChildren();
    this.filesMessage.textContent = "";
    this.abortUploads();
    this.transfers.replaceChildren();
    const forwardError = $(".forward-error", this.forwardsPanel);
    forwardError.textContent = "";
    forwardError.hidden = true;
    this.setState("connecting", `Connecting to ${this.title}…`);
    this.refit();

    const ws = new WebSocket(`ws://${location.host}/ws`, ["vortexssh", `token-${token()}`]);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    ws.onopen = () => {
      this.sendJson({ type: "connect", ...this.target, cols: this.term.cols, rows: this.term.rows });
    };
    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        this.term.write(new Uint8Array(event.data));
      } else {
        this.handle(JSON.parse(event.data));
      }
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      for (const { reject } of this.replies.values()) reject(new Error("disconnected"));
      this.replies.clear();
      cancelQuestions(this);
      if (!this.view.classList.contains("closed")) {
        // Whatever answers on this port now may not be the server that
        // started this page (and a restarted one has a new token), so
        // offer no Reconnect that would send it a login.
        this.closed("Lost the connection to vortexssh-web. Start it again and open the new link it prints.",
          { serverLost: true });
      }
    };
  }

  sendJson(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(message));
  }

  /// Large pastes go in chunks: the server refuses messages over 1 MiB.
  sendBytes(bytes) {
    if (!(this.conn && this.ws && this.ws.readyState === WebSocket.OPEN)) return;
    for (let i = 0; i < bytes.length; i += SEND_CHUNK) this.ws.send(bytes.subarray(i, i + SEND_CHUNK));
  }

  /// Sends a request that the server answers with a `reply`.
  request(message) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error("not connected"));
        return;
      }
      const id = this.nextId++;
      this.replies.set(id, { resolve, reject });
      this.sendJson({ ...message, id });
    });
  }

  async handle(msg) {
    switch (msg.type) {
      case "ask":
        this.sendJson({ type: "answer", id: msg.id, value: await this.answer(msg) });
        break;
      case "ask_cancel":
        cancelQuestions(this, msg.id);
        break;
      case "warning":
        this.warnings.append(el("div", { text: `⚠ ${msg.message}` }));
        this.warnings.hidden = false;
        break;
      case "ready":
        this.conn = msg.conn;
        this.setState("connected", msg.label);
        this.renderForwards(msg.forwards);
        this.term.focus();
        break;
      case "reply": {
        const pending = this.replies.get(msg.id);
        if (!pending) break;
        this.replies.delete(msg.id);
        if (msg.ok) pending.resolve(msg.data);
        else pending.reject(new Error(msg.error));
        break;
      }
      case "forwards":
        this.renderForwards(msg.list);
        break;
      case "closed":
        this.closed(msg.reason);
        break;
    }
  }

  /// Turns a server question into a dialog; returns the answer to send.
  async answer(q) {
    if (q.kind === "secret") {
      const values = await ask({ owner: this, serverId: q.id, title: this.title, message: q.prompt,
        fields: [{ label: "", secret: true }], ok: "Continue" });
      return values ? values[0] : null;
    }
    if (q.kind === "host_key") {
      const answer = await ask({
        owner: this,
        serverId: q.id,
        title: "Unknown host key",
        message: `The authenticity of ${q.host}:${q.port} can't be established. ` +
          "Check that this fingerprint matches the server before trusting it. " +
          "It will be saved to ~/.ssh/known_hosts.",
        monospace: q.fingerprint,
        ok: "Trust and connect",
      });
      return answer === true;
    }
    if (q.kind === "keyboard_interactive") {
      const message = [q.name, q.instructions].filter(Boolean).join("\n");
      if (q.prompts.length === 0) return [];
      return ask({ owner: this, serverId: q.id, title: this.title, message: message || "The server asks:",
        fields: q.prompts.map((p) => ({ label: p.text, secret: !p.echo })), ok: "Continue" });
    }
    return null;
  }

  closed(reason, { serverLost = false } = {}) {
    this.conn = null;
    this.abortUploads();
    this.setState("closed", reason);
    this.renderForwards([]); // the server stops them with the connection
    cancelQuestions(this);
    $(".closed-banner", this.view)?.remove();
    const banner = el("div", { class: "closed-banner" },
      el("span", { class: "text", text: reason }),
      serverLost ? null : el("button", { class: "primary", onclick: () => this.reconnect() }, "Reconnect"),
      el("button", { onclick: () => this.close() }, "Close tab"));
    $(".terminal-wrap", this.view).append(banner);
    if (this.ws) this.ws.close();
  }

  reconnect() {
    this.term.write("\r\n");
    this.connect();
  }

  close() {
    cancelQuestions(this);
    this.abortUploads();
    const ws = this.ws;
    this.ws = null;
    if (ws) ws.close();
    this.resizer.disconnect();
    this.term.dispose();
    this.view.remove();
    this.button.remove();
    const index = tabs.indexOf(this);
    tabs.splice(index, 1);
    if (selected === this) select(tabs[Math.min(index, tabs.length - 1)] || null);
  }

  togglePanel(panel, show) {
    const other = panel === this.filesPanel ? this.forwardsPanel : this.filesPanel;
    const visible = show ?? panel.hidden;
    panel.hidden = !visible;
    if (visible) other.hidden = true;
    this.filesButton.classList.toggle("active", !this.filesPanel.hidden);
    this.forwardsButton.classList.toggle("active", !this.forwardsPanel.hidden);
    if (visible && panel === this.filesPanel) this.listFiles(this.cwd ?? "");
    if (visible && panel === this.forwardsPanel) $(".forward-spec", panel).focus();
    if (!visible && this.conn) this.term.focus();
    requestAnimationFrame(() => this.refit());
  }

  // ------------------------------------------------------------------ files

  setupFiles() {
    const panel = this.filesPanel;
    this.pathInput = $(".path", panel);
    this.fileRows = $("tbody", panel);
    this.filesMessage = $(".files-message", panel);
    this.transfers = $(".transfers", panel);
    this.uploads = new Set();
    this.entries = [];
    this.listing = 0;
    this.folderButtons = [$(".mkdir", panel), $(".upload", panel), $(".refresh", panel), $(".up", panel)];
    $(".path-bar", panel).addEventListener("submit", (e) => {
      e.preventDefault();
      this.listFiles(this.pathInput.value.trim());
    });
    $(".up", panel).addEventListener("click", () => this.listFiles(parentPath(this.cwd ?? "/")));
    $(".refresh", panel).addEventListener("click", () => this.listFiles(this.cwd ?? ""));
    $(".mkdir", panel).addEventListener("click", () => this.makeDir());
    const fileInput = $(".file-input", panel);
    $(".upload", panel).addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
      this.uploadFiles([...fileInput.files]);
      fileInput.value = "";
    });

    const zone = $(".drop-zone", panel);
    zone.addEventListener("dragover", (e) => {
      if (!e.dataTransfer.types.includes("Files")) return;
      e.preventDefault();
      zone.classList.add("dragging");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("dragging"));
    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      zone.classList.remove("dragging");
      const files = [];
      let folders = 0;
      for (const item of e.dataTransfer.items) {
        if (item.kind !== "file") continue;
        const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
        if (entry && entry.isDirectory) { folders++; continue; }
        const file = item.getAsFile();
        if (file) files.push(file);
      }
      if (folders) this.filesMessage.textContent = "Folders can't be uploaded; drop the files inside them instead.";
      if (this.cwd !== null) this.uploadFiles(files);
    });
  }

  /// The folder shown; actions that need one are disabled without it.
  setCwd(path) {
    this.cwd = path;
    for (const b of this.folderButtons) b.disabled = path === null;
  }

  async listFiles(path) {
    if (!this.conn) return;
    // Only the latest listing counts, if replies arrive out of order.
    const listing = ++this.listing;
    this.filesMessage.textContent = "Loading…";
    try {
      const result = await this.request({ type: "sftp", op: "list", path });
      if (listing !== this.listing) return;
      this.setCwd(result.path);
      this.pathInput.value = result.path;
      this.renderFiles(result.entries);
      this.filesMessage.textContent = result.entries.length ? "" : "This folder is empty.";
    } catch (e) {
      if (listing !== this.listing) return;
      this.filesMessage.textContent = e.message;
      this.pathInput.value = this.cwd ?? path;
    }
  }

  renderFiles(entries) {
    this.entries = entries;
    entries.sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name));
    const rows = entries.map((entry) => {
      const path = joinPath(this.cwd, entry.name);
      const name = el("button", {
        class: entry.dir ? "dir" : "",
        title: entry.dir ? `Open ${entry.name}` : `Download ${entry.name}`,
        text: (entry.dir ? "📁 " : "📄 ") + entry.name + (entry.link ? " →" : ""),
        onclick: () => entry.dir ? this.listFiles(path) : this.download(path),
      });
      const actions = el("td", { class: "actions" },
        entry.dir ? null : el("button", { title: "Download", "aria-label": `Download ${entry.name}`,
          onclick: () => this.download(path) }, "⬇"),
        el("button", { title: "Rename", "aria-label": `Rename ${entry.name}`,
          onclick: () => this.rename(entry.name) }, "✎"),
        el("button", { title: "Delete", "aria-label": `Delete ${entry.name}`,
          onclick: () => this.remove(entry) }, "🗑"));
      return el("tr", { title: formatMode(entry.perm, entry.dir, entry.link) },
        el("td", { class: "name" }, name),
        el("td", { class: "num", text: entry.dir ? "" : formatSize(entry.size) }),
        el("td", { class: "when", text: formatTime(entry.mtime) }),
        actions);
    });
    this.fileRows.replaceChildren(...rows);
  }

  /// The browser downloads by itself (straight to disk) with a one-time
  /// ticket, since it can't send the token header for a plain link.
  async download(path) {
    try {
      const { ticket } = await api("POST", `/api/conn/${this.conn}/download`, { path });
      const link = el("a", { href: `/download/${ticket}`, download: path.split("/").pop() });
      document.body.append(link);
      link.click();
      link.remove();
    } catch (e) {
      this.filesMessage.textContent = e.message;
    }
  }

  async uploadFiles(files) {
    const dir = this.cwd;
    if (dir === null) return;
    for (const file of files) {
      const existing = this.entries.find((e) => e.name === file.name);
      if (existing?.dir) {
        this.transfers.append(this.failedRow(`${file.name}: there is a folder with this name in ${dir}`));
        continue;
      }
      if (existing) {
        const ok = await ask({ owner: this, title: "Replace file?",
          message: `${file.name} already exists in ${dir}. Replace it?`, ok: "Replace", danger: true });
        if (!ok) continue;
      }
      await this.upload(file, joinPath(dir, file.name));
    }
    if (this.cwd === dir) this.listFiles(dir);
  }

  failedRow(message) {
    const row = el("div", { class: "transfer failed" }, el("span", { text: message }));
    row.append(el("button", { class: "icon", "aria-label": "Dismiss", onclick: () => row.remove() }, "×"));
    return row;
  }

  abortUploads() {
    for (const xhr of this.uploads) xhr.abort();
    this.uploads.clear();
  }

  upload(file, path) {
    const progress = el("progress", { max: "100", value: "0" });
    const label = el("span", { text: `Uploading ${file.name} (${formatSize(file.size)})` });
    const row = el("div", { class: "transfer" }, label, progress);
    this.transfers.append(row);
    return new Promise((resolve) => {
      const xhr = new XMLHttpRequest();
      this.uploads.add(xhr);
      xhr.onloadend = () => this.uploads.delete(xhr);
      xhr.open("PUT", `/api/conn/${this.conn}/upload?path=${encodeURIComponent(path)}`);
      xhr.setRequestHeader("Authorization", `Bearer ${token()}`);
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) progress.value = (100 * e.loaded) / e.total;
      };
      const fail = (message) => {
        row.classList.add("failed");
        label.textContent = `${file.name}: ${message}`;
        progress.remove();
        row.append(el("button", { class: "icon", "aria-label": "Dismiss", onclick: () => row.remove() }, "×"));
        resolve();
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          row.remove();
          resolve();
        } else {
          fail(xhr.responseText || `HTTP ${xhr.status}`);
        }
      };
      xhr.onerror = () => fail("upload failed");
      xhr.onabort = () => fail("cancelled");
      xhr.send(file);
    });
  }

  async makeDir() {
    if (this.cwd === null) return;
    const values = await ask({ owner: this, title: "New folder", message: `In ${this.cwd}`,
      fields: [{ label: "Name" }], ok: "Create" });
    const name = values && values[0].trim();
    if (!name) return;
    await this.sftpAction({ op: "mkdir", path: joinPath(this.cwd, name) });
  }

  async rename(oldName) {
    if (this.cwd === null) return;
    const values = await ask({ owner: this, title: "Rename", fields: [{ label: "New name", value: oldName }],
      ok: "Rename" });
    const name = values && values[0].trim();
    if (!name || name === oldName) return;
    await this.sftpAction({ op: "rename", from: joinPath(this.cwd, oldName), to: joinPath(this.cwd, name) });
  }

  async remove(entry) {
    const what = entry.dir ? "folder" : "file";
    const ok = await ask({ owner: this, title: `Delete ${what}?`,
      message: `${joinPath(this.cwd, entry.name)} will be deleted from the server.` +
        (entry.dir ? " Only empty folders can be deleted." : ""),
      ok: "Delete", danger: true });
    if (!ok) return;
    await this.sftpAction({ op: "remove", path: joinPath(this.cwd, entry.name), dir: entry.dir && !entry.link });
  }

  async sftpAction(op) {
    try {
      await this.request({ type: "sftp", ...op });
      await this.listFiles(this.cwd);
    } catch (e) {
      this.filesMessage.textContent = e.message;
    }
  }

  // --------------------------------------------------------------- forwards

  setupForwards() {
    const panel = this.forwardsPanel;
    const kind = $(".forward-kind", panel);
    const spec = $(".forward-spec", panel);
    const help = $(".forward-help", panel);
    const error = $(".forward-error", panel);
    const placeholders = { local: "8080:localhost:80", remote: "9000:localhost:3000", dynamic: "1080" };
    const update = () => {
      help.textContent = FORWARD_HELP[kind.value];
      spec.placeholder = placeholders[kind.value];
    };
    kind.addEventListener("change", update);
    update();
    $(".forward-form", panel).addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!spec.value.trim()) return;
      error.hidden = true;
      try {
        await this.request({ type: "forward_add", kind: kind.value, spec: spec.value.trim() });
        spec.value = "";
      } catch (err) {
        error.textContent = err.message;
        error.hidden = false;
      }
    });
  }

  renderForwards(list) {
    const panel = this.forwardsPanel;
    const items = (list || []).map((f) => el("li", {},
      el("span", { class: "badge", text: { local: "L", remote: "R", dynamic: "SOCKS" }[f.kind] }),
      el("div", { class: "info" },
        el("div", { class: "spec", text: f.spec }),
        el("div", { class: "detail", text: `${f.listen} → ${f.dest}` })),
      el("button", { onclick: () => this.request({ type: "forward_stop", forward: f.id }).catch(() => {}) }, "Stop")));
    $(".forward-list", panel).replaceChildren(...items);
    $(".no-forwards", panel).hidden = items.length > 0;
    this.forwardsButton.textContent = items.length ? `Port forwards (${items.length})` : "Port forwards";
  }
}

function select(tab) {
  selected = tab;
  welcome.hidden = tabs.length > 0;
  for (const t of tabs) {
    const on = t === tab;
    t.view.hidden = !on;
    t.button.classList.toggle("selected", on);
    t.button.setAttribute("aria-selected", on);
  }
  if (tab) {
    requestAnimationFrame(() => {
      tab.refit();
      if (tab.conn) tab.term.focus();
    });
  }
}

// ---------------------------------------------------------------------------
// Sidebar: profiles and ssh_config aliases

let profiles = [];

async function loadHosts() {
  let data;
  try {
    data = await api("GET", "/api/hosts");
  } catch (e) {
    showHostErrors([e.message]);
    return;
  }
  profiles = data.profiles;
  $("#profiles").replaceChildren(...profiles.map((p) => el("li", {},
    el("button", { class: "host", title: `Connect to ${p.name}`,
      onclick: () => new Tab(p.name, { profile: p.name }) },
      el("span", { text: p.name }),
      el("span", { class: "sub", text: `${p.user}@${p.host}${p.port !== 22 ? `:${p.port}` : ""}` })),
    el("button", { class: "edit icon", title: "Edit", "aria-label": `Edit ${p.name}`,
      onclick: () => editProfile(p) }, "✎"))));
  $("#no-profiles").hidden = profiles.length > 0;
  $("#aliases").replaceChildren(...data.aliases.map((alias) => el("li", {},
    el("button", { class: "host", title: `Connect to ${alias}`,
      onclick: () => new Tab(alias, { target: alias }) }, el("span", { text: alias })))));
  $("#no-aliases").hidden = data.aliases.length > 0;
  showHostErrors(data.errors);
}

function showHostErrors(errors) {
  const node = $("#host-errors");
  node.textContent = errors.join("\n");
  node.hidden = errors.length === 0;
}

// New connection dialog

const connectDialog = $("#connect-dialog");

function openConnect() {
  $("form", connectDialog).reset();
  connectDialog.showModal();
}

connectDialog.addEventListener("close", () => {
  if (connectDialog.returnValue !== "ok") return;
  const form = $("form", connectDialog);
  const target = form.target.value.trim();
  if (!target) return;
  const port = form.port.value ? Number(form.port.value) : undefined;
  const identity = form.identity.value.trim() || undefined;
  new Tab(port ? `${target}:${port}` : target, { target, port, identity });
});

// Profile dialog

const profileDialog = $("#profile-dialog");
let editing = null;

const FLAGS = { local: "-L", remote: "-R", dynamic: "-D" };
const KINDS = { "-L": "local", "-R": "remote", "-D": "dynamic" };

function editProfile(profile) {
  editing = profile;
  const form = $("form", profileDialog);
  form.reset();
  $(".title", profileDialog).textContent = profile ? `Edit ${profile.name}` : "New profile";
  $(".delete", profileDialog).hidden = !profile;
  $(".error", profileDialog).hidden = true;
  if (profile) {
    form.name.value = profile.name;
    form.target.value = `${profile.user}@${profile.host}`;
    form.port.value = profile.port !== 22 ? profile.port : "";
    form.identity.value = profile.identity || "";
    form.forwards.value = profile.forwards.map((f) => `${FLAGS[f.kind]} ${f.spec}`).join("\n");
  }
  profileDialog.showModal();
}

function parseForwardLines(text) {
  const forwards = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const match = line.match(/^(-[LRD])\s*(\S+)$/);
    if (!match) throw new Error(`"${line}": write each forward as -L, -R or -D followed by the spec`);
    forwards.push({ kind: KINDS[match[1]], spec: match[2] });
  }
  return forwards;
}

$("form", profileDialog).addEventListener("submit", async (e) => {
  const action = e.submitter && e.submitter.value;
  if (action === "cancel") return;
  e.preventDefault();
  const form = e.target;
  const error = $(".error", profileDialog);
  error.hidden = true;
  try {
    if (action === "delete") {
      const ok = await ask({ title: "Delete profile?", message: `Delete the profile ${editing.name}?`,
        ok: "Delete", danger: true });
      if (!ok) return;
      await api("DELETE", `/api/profiles/${encodeURIComponent(editing.name)}`);
    } else {
      await api("POST", "/api/profiles", {
        name: form.name.value.trim(),
        target: form.target.value.trim(),
        port: form.port.value ? Number(form.port.value) : null,
        identity: form.identity.value.trim() || null,
        forwards: parseForwardLines(form.forwards.value),
        original: editing ? editing.name : null,
      });
    }
    profileDialog.close();
    loadHosts();
  } catch (err) {
    error.textContent = err.message;
    error.hidden = false;
  }
});

// ---------------------------------------------------------------------------

$("#new-connection").addEventListener("click", openConnect);
$("#welcome-connect").addEventListener("click", openConnect);
$("#new-profile").addEventListener("click", () => editProfile(null));
window.addEventListener("beforeunload", (e) => {
  if (tabs.some((t) => t.conn)) e.preventDefault();
});
loadHosts();
