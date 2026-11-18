// jaword web UI. No frameworks and no inline script. Every piece of server
// data reaches the page as a text node, never parsed as markup, so a stored
// value cannot turn into HTML or script. The access token lives in
// sessionStorage (gone when the tab closes).
"use strict";

const REVEAL_SECONDS = 30;
const IDLE_LOCK_MS = 10 * 60 * 1000;
const STALE_DAYS = 90;          // red: overdue for a change
const AGING_DAYS = 30;          // amber: getting old
const state = { token: null, me: null, view: "secrets", secrets: [], folders: [], folder: "", selected: null, sort: "name", onlyStale: false };
const root = document.getElementById("app");

try { state.token = sessionStorage.getItem("jaword.token"); } catch (_) { /* storage blocked */ }

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

let toastTimer;
function toast(msg, bad) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show" + (bad ? " bad" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ""; }, bad ? 5000 : 2200);
}

async function api(method, path, body) {
  const headers = {};
  if (state.token) headers.Authorization = "Bearer " + state.token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "omit", redirect: "error" });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const err = new Error((data && data.message) || "HTTP " + res.status);
    err.status = res.status;
    err.code = data && data.error;
    throw err;
  }
  return data;
}

const p2 = (n) => String(n).padStart(2, "0");
function fmt(ts) {
  if (!ts) return "never";
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
}
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function short(ts) { const d = new Date(ts * 1000); return `${MONTHS[d.getMonth()]} ${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`; }
const daysSince = (ts) => Math.max(0, Math.floor((Date.now() / 1000 - ts) / 86400));
const ageText = (days) => (days === 0 ? "today" : days === 1 ? "1 day" : days + " days");
const ageGrade = (days) => (days > STALE_DAYS ? "red" : days >= AGING_DAYS ? "amber" : "green");
// Only things that are meant to be changed regularly have an age worth showing.
const rotates = (s) => ["password", "api_key", "ssh_key"].includes(s.kind);
const lamp = (colour) => h("span", { class: "lamp " + (colour || ""), "aria-hidden": "true" });
const who = (actor) => (actor || "").split(":")[0] || "unknown";

// Folders are path prefixes. People see "Personal / Banks"; agents and access
// rules keep using the stable address personal/banks/chase.
const pretty = (seg) => { const t = seg.replace(/[-_]+/g, " "); return t.charAt(0).toUpperCase() + t.slice(1); };
const folderOf = (p) => { const i = p.lastIndexOf("/"); return i < 0 ? "" : p.slice(0, i); };
const leafOf = (p) => p.slice(p.lastIndexOf("/") + 1);
const folderLabel = (p) => (p ? p.split("/").map(pretty).join(" / ") : "No folder");
const slug = (t) => t.toLowerCase().normalize("NFKD").replace(/[^a-z0-9._-]+/g, "-").replace(/\.{2,}/g, ".").replace(/^[^a-z0-9]+|[-.]+$/g, "").slice(0, 60);
const itemName = (s) => s.meta.title || pretty(leafOf(s.path));

function logout() {
  state.token = null; state.me = null; state.selected = null; state.secrets = [];
  try { sessionStorage.removeItem("jaword.token"); } catch (_) { /* ignore */ }
  boot();
}

let idleTimer;
function armIdle() {
  clearTimeout(idleTimer);
  if (state.token) idleTimer = setTimeout(() => { toast("Signed out after 10 minutes without activity"); logout(); }, IDLE_LOCK_MS);
}
["pointerdown", "keydown"].forEach((e) => document.addEventListener(e, armIdle, { passive: true }));

function dialog(cls, ...kids) {
  const dlg = h("dialog", { class: cls || null }, ...kids);
  document.body.append(dlg);
  dlg.addEventListener("close", () => dlg.remove());
  return dlg;
}

// ------------------------------------------------------------------ gates
// A ring of approach lights: red while sealed, blue when ready for a token,
// and they run green one after another when the vault opens.

function ring(mode) {
  const el = h("div", { class: "ring " + mode, "aria-hidden": "true" });
  for (let i = 0; i < 24; i++) {
    const dot = h("i", {});
    dot.style.transform = `rotate(${i * 15}deg) translateY(-62px)`;
    dot.style.transitionDelay = i * 22 + "ms";
    el.append(dot);
  }
  return el;
}

function gate(mode, title, text, ...body) {
  root.replaceChildren(h("div", { class: "gate" }, h("div", { class: "card" }, ring(mode), h("h1", {}, title), h("p", {}, text), ...body)));
}

function gateForm(label, placeholder, button, onSubmit) {
  const input = h("input", { type: "password", autocomplete: "off", spellcheck: "false", placeholder, required: true });
  const err = h("div", { class: "error" });
  const btn = h("button", { class: "btn primary", type: "submit" }, button);
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true; err.textContent = "";
    try { await onSubmit(input.value); } catch (ex) { err.textContent = ex.message; btn.disabled = false; input.select(); }
  } }, h("label", {}, label), input, err, h("div", { class: "row" }, btn));
  setTimeout(() => input.focus(), 0);
  return form;
}

function runGreen(then) {
  const r = document.querySelector(".ring");
  if (r) r.className = "ring open";
  setTimeout(then, matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 760);
}

async function boot() {
  let st;
  try { st = await api("GET", "/v1/sys/status"); }
  catch (e) { return gate("sealed", "Vault unreachable", e.message, h("button", { class: "btn", onclick: boot }, "Try again")); }
  if (!st.initialized) {
    return gate("sealed", "Not set up yet", "Create the vault from a terminal on its host, so the recovery key never passes through a browser.",
      h("p", {}, h("code", {}, "jaword init")), h("button", { class: "btn", onclick: boot }, "Check again"));
  }
  if (st.sealed) {
    return gate("sealed", "Sealed", "Nothing can be read until the passphrase or recovery key is entered.",
      gateForm("Passphrase", "", "Unseal", async (v) => { await api("POST", "/v1/sys/unseal", { credential: v }); runGreen(boot); }));
  }
  if (state.token) {
    try { state.me = await api("GET", "/v1/whoami"); armIdle(); return shell(); }
    catch (e) { state.token = null; try { sessionStorage.removeItem("jaword.token"); } catch (_) { /* ignore */ } }
  }
  gate("ready", "jaword", "Paste your access token. It stays in this tab and is gone when you close it.",
    gateForm("Access token", "jw_…", "Open vault", async (v) => {
      state.token = v.trim();
      try { state.me = await api("GET", "/v1/whoami"); }
      catch (e) { state.token = null; throw e; }
      try { sessionStorage.setItem("jaword.token", state.token); } catch (_) { /* ignore */ }
      armIdle(); runGreen(shell);
    }));
}

// ------------------------------------------------------------------ shell

const isAdmin = () => state.me && state.me.role === "admin";
const MAC = /Mac|iPhone|iPad/.test(navigator.platform);

function shell() {
  const views = [["secrets", "Vault"]];
  if (isAdmin()) views.push(["tokens", "Tokens"], ["audit", "Audit log"], ["updates", "Updates"]);
  const main = h("main", { class: "main" });
  root.replaceChildren(
    h("header", { class: "bar" },
      h("div", { class: "brand" }, "jaword"),
      h("nav", { class: "tabs", "aria-label": "Sections" }, views.map(([id, label]) => h("button", { class: "tab" + (state.view === id ? " on" : ""), onclick: () => go(id) }, label))),
      h("button", { class: "cmd", onclick: palette, "aria-label": "Find an item or run a command" }, h("span", { class: "grow" }, "Find an item or run a command"), h("kbd", {}, MAC ? "⌘K" : "Ctrl K")),
      h("div", { class: "who" },
        h("span", { class: "state" }, lamp("green"), h("span", {}, "Unsealed")),
        h("span", { class: "name", title: state.me.role }, state.me.name),
        h("button", { class: "link", onclick: logout }, "Sign out"),
        isAdmin() && h("button", { class: "link danger", onclick: sealVault }, "Seal"))),
    main);
  ({ secrets: viewSecrets, tokens: viewTokens, audit: viewAudit, updates: viewUpdates })[state.view](main);
}
function go(view) { state.view = view; shell(); }

async function sealVault() {
  if (!confirm("Seal the vault? Nothing can be read or rotated until someone enters the passphrase again.")) return;
  try { await api("POST", "/v1/sys/seal", {}); logout(); } catch (e) { toast(e.message, true); }
}

function fail(e) {
  if (e.status === 401) { toast("Signed out", true); return logout(); }
  if (e.code === "sealed") return boot();
  toast(e.message, true);
}

// ---------------------------------------------------------- command palette

let vaultReload = null;   // set by the vault view so commands can refresh it

function palette() {
  if (!state.me || document.querySelector("dialog.palette")) return;
  const commands = [
    ["New item", () => secretDialog(null, vaultReload || (() => go("secrets")))],
    ["New folder", () => folderDialog(null, vaultReload || (() => go("secrets")))],
    ["Show passwords overdue for a change", () => { state.onlyStale = true; state.folder = ""; go("secrets"); }],
    ["Go to Vault", () => go("secrets")],
  ];
  if (isAdmin()) commands.push(["Go to Tokens", () => go("tokens")], ["Go to Audit log", () => go("audit")], ["Go to Updates", () => go("updates")], ["Seal the vault", sealVault]);
  commands.push(["Sign out", logout]);
  const input = h("input", { type: "text", placeholder: "Find an item or run a command", autocomplete: "off", spellcheck: "false", "aria-label": "Find an item or run a command" });
  const list = h("ul", { role: "listbox" });
  let rows = [], at = 0;
  const pick = (i) => { const r = rows[i]; if (!r) return; dlg.close(); r.run(); };
  function draw() {
    const q = input.value.trim().toLowerCase();
    const items = state.secrets.filter((s) => !q || itemName(s).toLowerCase().includes(q) || s.path.includes(q) || s.meta.url.toLowerCase().includes(q) || s.meta.username.toLowerCase().includes(q) || s.meta.tags.some((t) => t.toLowerCase().includes(q)))
      .slice(0, 8).map((s) => ({ label: itemName(s), side: [s.meta.username, folderLabel(folderOf(s.path))].filter(Boolean).join("   "), run: () => { state.selected = s.path; state.folder = ""; state.onlyStale = false; go("secrets"); } }));
    const cmds = commands.filter(([l]) => !q || l.toLowerCase().includes(q)).map(([label, run]) => ({ label, run, cmd: true }));
    rows = q ? [...items, ...cmds] : [...cmds, ...items];
    at = Math.min(at, Math.max(0, rows.length - 1));
    if (!rows.length) return list.replaceChildren(h("li", { class: "none" }, "Nothing matches."));
    list.replaceChildren(...rows.map((r, i) => h("li", { class: (i === at ? "on " : "") + (r.cmd ? "cmdrow" : ""), role: "option", "aria-selected": i === at ? "true" : "false", onclick: () => pick(i), onpointermove: () => { if (at !== i) { at = i; draw(); } } },
      h("span", { class: "grow" }, r.label), r.side && h("small", {}, r.side))));
    const on = list.querySelector(".on"); if (on) on.scrollIntoView({ block: "nearest" });
  }
  input.addEventListener("input", () => { at = 0; draw(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); at = Math.min(rows.length - 1, at + 1); draw(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); at = Math.max(0, at - 1); draw(); }
    else if (e.key === "Enter") { e.preventDefault(); pick(at); }
  });
  const dlg = dialog("palette", input, list);
  dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
  draw();
  dlg.showModal();
}
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette(); }
});

// ------------------------------------------------------------------ vault

function folderSelect(selected, opts) {
  const o = opts || {};
  const list = (state.folders || []).filter((f) => !o.exclude || (f.path !== o.exclude && !f.path.startsWith(o.exclude + "/")));
  return h("select", {},
    h("option", { value: "", selected: selected === "" }, o.rootLabel || "No folder"),
    list.map((f) => h("option", { value: f.path, selected: f.path === selected }, "  ".repeat(f.path.split("/").length - 1) + pretty(leafOf(f.path)))),
    o.allowNew && h("option", { value: "\u0000new" }, "+ New folder…"));
}

function ageCell(s) {
  if (!rotates(s)) return h("span", { class: "hint" }, "—");
  const days = daysSince(s.changed_at);
  const lit = Math.max(1, Math.ceil((Math.min(days, STALE_DAYS) / STALE_DAYS) * 8));
  const grade = ageGrade(days);
  return h("div", { class: "age " + grade, title: "Last changed " + fmt(s.changed_at) },
    h("span", { class: "lights", "aria-hidden": "true" }, Array.from({ length: 8 }, (_, i) => h("i", { class: i < lit ? "lit" : null }))),
    h("span", {}, ageText(days)));
}

async function viewSecrets(main) {
  const noticeEl = h("div", {});
  const treeEl = h("nav", { class: "tree", "aria-label": "Folders" });
  const tableEl = h("div", {});
  const detailEl = h("div", {});
  main.replaceChildren(noticeEl,
    h("div", { class: "deck" },
      h("div", { class: "folders" }, h("div", { class: "cap" }, "Folders"), treeEl),
      h("div", {}, tableEl),
      detailEl));

  const pick = (f) => { state.folder = f; state.onlyStale = false; render(); };
  const stale = () => state.secrets.filter((s) => rotates(s) && daysSince(s.changed_at) > STALE_DAYS);

  function renderNotice() {
    const old = stale();
    if (!old.length) return noticeEl.replaceChildren();
    const auto = old.filter((s) => s.has_driver);
    const names = old.slice(0, 3).map(itemName).join(", ") + (old.length > 3 ? ` and ${old.length - 3} more` : "");
    noticeEl.replaceChildren(h("div", { class: "notice", role: "status" }, lamp("red"),
      h("span", {}, `${old.length} ${old.length === 1 ? "password has" : "passwords have"} not changed in over ${STALE_DAYS} days.`),
      h("span", { class: "names grow" }, names),
      h("button", { class: "btn small", onclick: () => { state.onlyStale = !state.onlyStale; state.folder = ""; render(); } }, state.onlyStale ? "Show everything" : old.length === 1 ? "Show it" : "Show them"),
      auto.length > 0 && h("button", { class: "btn small danger outline", onclick: () => rotateMany(auto) }, auto.length === old.length ? (auto.length === 1 ? "Rotate it" : auto.length === 2 ? "Rotate both" : `Rotate all ${auto.length}`) : `Rotate the ${auto.length} that can`)));
  }

  async function rotateMany(list) {
    if (!confirm(`Rotate ${list.length} ${list.length === 1 ? "password" : "passwords"} on ${list.length === 1 ? "its" : "their"} live ${list.length === 1 ? "system" : "systems"} now?\n\n${list.map(itemName).join("\n")}`)) return;
    let ok = 0; const bad = [];
    for (const s of list) {
      toast(`Rotating ${itemName(s)}…`);
      try { const r = await api("POST", "/v1/secrets/rotate", { path: s.path }); if (r.rotated) ok++; else bad.push(itemName(s)); }
      catch (e) { if (e.status === 401) return fail(e); bad.push(itemName(s)); }
    }
    toast(bad.length ? `Rotated ${ok}. Failed, old password kept: ${bad.join(", ")}` : `Rotated ${ok}`, bad.length > 0);
    reload();
  }

  function renderTree() {
    const all = h("div", { class: "foldrow" }, h("button", { class: "fold" + (!state.folder ? " on" : ""), onclick: () => pick("") }, h("span", { class: "grow" }, "All items"), h("span", { class: "cnt" }, state.secrets.length)));
    const rows = state.folders.map((f) => {
      const b = h("button", { class: "fold" + (state.folder === f.path ? " on" : ""), onclick: () => pick(f.path), title: f.path },
        h("span", { class: "grow" }, pretty(leafOf(f.path))), h("span", { class: "cnt" }, f.count));
      b.style.paddingLeft = 10 + (f.path.split("/").length - 1) * 14 + "px";
      return h("div", { class: "foldrow" }, b,
        h("button", { class: "more", title: "Rename, move or delete", "aria-label": "Options for folder " + folderLabel(f.path), onclick: () => folderDialog(f, reload) }, "⋯"));
    });
    treeEl.replaceChildren(all, ...rows, h("button", { class: "link", onclick: () => folderDialog(null, reload) }, "+  New folder"));
  }

  function renderTable() {
    let rows = state.secrets.filter((s) => (!state.folder || s.path.startsWith(state.folder + "/")) && (!state.onlyStale || (rotates(s) && daysSince(s.changed_at) > STALE_DAYS)));
    if (state.sort === "age") rows = [...rows].sort((a, b) => (rotates(b) ? daysSince(b.changed_at) : -1) - (rotates(a) ? daysSince(a.changed_at) : -1));
    else rows = [...rows].sort((a, b) => itemName(a).localeCompare(itemName(b)));
    const sorter = (key, label) => h("button", { class: state.sort === key ? "on" : null, title: "Sort by " + label.toLowerCase(), onclick: () => { state.sort = key; renderTable(); } }, label);
    const newBtn = h("button", { class: "btn primary small", onclick: () => secretDialog(null, reload) }, "New item");
    const title = h("div", { class: "tablehead" }, h("div", { class: "cap grow" }, state.onlyStale ? "Overdue for a change" : state.folder ? folderLabel(state.folder) : "All items"), newBtn);
    title.style.marginBottom = "6px";
    if (!rows.length) {
      return tableEl.replaceChildren(title, h("div", { class: "empty" }, state.secrets.length ? (state.onlyStale ? "Nothing is overdue." : "This folder is empty.") : "The vault is empty. Add an item, or import from another password manager with `jaword import`."));
    }
    tableEl.replaceChildren(title, h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, h("th", {}, sorter("name", "Name")), h("th", { class: "us" }, "Username"), h("th", {}, sorter("age", "Last changed")), h("th", {}, "Rotation"), h("th", { class: "ver" }, "Ver"))),
      h("tbody", {}, rows.map((s) => h("tr", { class: state.selected === s.path ? "on" : null, tabindex: "0",
        onclick: () => { state.selected = s.path; renderTable(); renderDetail(); },
        onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); state.selected = s.path; renderTable(); renderDetail(); } } },
        h("td", { class: "nm" }, itemName(s), !state.folder && folderOf(s.path) && h("small", {}, folderLabel(folderOf(s.path)))),
        h("td", { class: "us" }, s.meta.username),
        h("td", {}, ageCell(s)),
        h("td", { class: "rot" + (s.has_driver ? " auto" : "") }, s.pending_rotation ? "Pending" : s.has_driver ? "Automatic" : rotates(s) ? "By hand" : "—"),
        h("td", { class: "ver" }, s.current_version))))));
  }

  async function renderDetail() {
    if (!state.selected) return detailEl.replaceChildren(h("div", { class: "insp empty" }, "Select an item to see it."));
    let d;
    try { d = await api("GET", "/v1/secrets/get?path=" + encodeURIComponent(state.selected)); }
    catch (e) { state.selected = null; return fail(e); }
    detailEl.replaceChildren(secretPanel(d, reload));
  }

  function render() { renderNotice(); renderTree(); renderTable(); }
  async function reload() {
    try { [state.secrets, state.folders] = await Promise.all([api("GET", "/v1/secrets"), api("GET", "/v1/folders")]); } catch (e) { return fail(e); }
    if (state.selected && !state.secrets.some((s) => s.path === state.selected)) state.selected = null;
    if (state.folder && !state.folders.some((f) => f.path === state.folder)) state.folder = "";
    render(); renderDetail();
  }
  vaultReload = reload;
  reload();
}

// Digits in amber, symbols in blue: easier to read back and to compare.
function paint(el, value) {
  el.replaceChildren(...[...value].map((c) => h("span", { class: /[0-9]/.test(c) ? "c-d" : /[A-Za-z]/.test(c) ? null : "c-s" }, c)));
}

function secretPanel(d, reload) {
  const MASK = "••••••••••••••••••••";
  const plate = h("div", { class: "plate" }, MASK);
  const note = h("span", { class: "hint" });
  const toggle = h("button", { class: "link", onclick: () => (plate.className.includes("shown") ? hide() : reveal()) }, "Reveal");
  let hideTimer, tick;
  function hide() { clearTimeout(hideTimer); clearInterval(tick); plate.textContent = MASK; plate.className = "plate"; note.textContent = ""; toggle.textContent = "Reveal"; }
  async function fetchValue(version) { return (await api("POST", "/v1/secrets/reveal", { path: d.path, version: version || null })).value; }
  async function reveal(version) {
    try {
      const v = await fetchValue(version);
      paint(plate, v); plate.className = "plate shown"; toggle.textContent = "Hide";
      let left = REVEAL_SECONDS;
      const label = version ? `v${version}, hides in ` : "Hides in ";
      note.textContent = `${label}${left}s`;
      clearTimeout(hideTimer); clearInterval(tick);
      tick = setInterval(() => { left -= 1; note.textContent = `${label}${left}s`; }, 1000);
      hideTimer = setTimeout(hide, REVEAL_SECONDS * 1000);
    } catch (e) { fail(e); }
  }
  async function copy() {
    try {
      const v = await fetchValue();
      await navigator.clipboard.writeText(v);
      toast("Copied. Clipboard clears in 30 seconds");
      setTimeout(async () => { try { if (await navigator.clipboard.readText() === v) await navigator.clipboard.writeText(""); } catch (_) { /* tab not focused */ } }, 30000);
    } catch (e) { fail(e); }
  }
  async function act(path, body, okMsg) {
    try {
      const r = await api("POST", path, body);
      if (r && r.rotated === false) toast("Rotation failed, old password kept: " + r.error, true); else toast(okMsg);
      reload();
    } catch (e) { fail(e); }
  }
  const m = d.meta;
  const days = daysSince(d.changed_at);
  const grade = rotates(d) ? ageGrade(days) : "green";
  const statusText = d.pending_rotation ? "Rotation pending" : grade === "red" ? "Overdue, v" + d.current_version : "Current, v" + d.current_version;
  const drv = d.driver ? (d.driver.type === "ssh" ? `SSH to ${d.driver.host}, ${d.driver.command}` : d.driver.argv.join(" ")) : d.has_driver ? "Automatic" : "By hand";
  return h("div", { class: "insp" },
    h("div", { class: "top" },
      h("div", { class: "grow" }, h("h3", {}, m.title || pretty(leafOf(d.path))), h("div", { class: "where" }, folderLabel(folderOf(d.path)))),
      h("div", { class: "status" }, lamp(d.pending_rotation ? "amber" : grade), statusText)),
    plate,
    h("div", { class: "under" }, toggle, h("button", { class: "link", onclick: copy }, "Copy"), note),
    h("dl", { class: "kv" },
      m.username && h("dt", {}, "Username"), m.username && h("dd", {}, m.username),
      m.url && h("dt", {}, "Website"), m.url && h("dd", {}, /^https?:\/\//i.test(m.url) ? h("a", { href: m.url, target: "_blank", rel: "noopener noreferrer" }, m.url.replace(/^https?:\/\//i, "")) : m.url),
      m.tags.length > 0 && h("dt", {}, "Tags"), m.tags.length > 0 && h("dd", {}, m.tags.map((t) => h("span", { class: "chiplet" }, t))),
      m.notes && h("dt", {}, "Notes"), m.notes && h("dd", {}, m.notes),
      h("dt", {}, "Changed"), h("dd", {}, `${days === 0 ? "Today" : ageText(days) + " ago"}, by ${who(d.changed_by)}`),
      h("dt", {}, "Address"), h("dd", { class: "mono", title: "What agents and access rules use to refer to this item" }, d.path),
      rotates(d) && h("dt", {}, "Rotation"), rotates(d) && h("dd", {}, drv)),
    h("div", { class: "row" },
      d.has_driver && h("button", { class: "btn go", onclick: () => confirm(`Rotate ${itemName(d)} on the live system now?`) && act("/v1/secrets/rotate", { path: d.path }, "Rotated") }, "Rotate now"),
      h("button", { class: "btn", onclick: () => secretDialog(d, reload) }, "Edit"),
      h("button", { class: "btn", onclick: () => moveDialog(d, reload) }, "Move"),
      isAdmin() && rotates(d) && h("button", { class: "btn", onclick: () => driverDialog(d, reload) }, d.has_driver ? "Rotation setup" : "Set up rotation"),
      d.pending_rotation && isAdmin() && h("button", { class: "btn", onclick: () => confirm("Make the pending version the current one? Do this only if the live system already uses it.") && act("/v1/secrets/resolve", { path: d.path, promote: true }, "Pending version is now current") }, "Keep pending"),
      d.pending_rotation && isAdmin() && h("button", { class: "btn", onclick: () => confirm("Discard the pending version?") && act("/v1/secrets/resolve", { path: d.path, promote: false }, "Pending version discarded") }, "Discard pending")),
    h("div", { class: "cap sep" }, "History"),
    h("ul", { class: "timeline" }, d.versions.map((v) => h("li", { class: v.state, title: v.state },
      h("span", { class: "v" }, "v" + v.version), h("span", {}, short(v.created_at)), h("span", {}, who(v.created_by)),
      v.state !== "current" && h("button", { class: "link", onclick: () => reveal(v.version) }, v.state === "failed" ? "Show (failed)" : "Show")))),
    h("div", { class: "row end" }, h("button", { class: "link danger", onclick: () => confirm(`Delete ${itemName(d)}?`) && act("/v1/secrets/delete", { path: d.path }, "Deleted") }, "Delete")));
}

// ---- password generator -------------------------------------------------
// Runs in the browser with the platform CSPRNG and rejection sampling (no
// modulo bias), mirroring the server's generator and its character sets.
const GEN = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!@#%^*-_=+", alike: "Il1O0o" };
const LEN_MIN = 12, LEN_MAX = 64, LIGHTS = 27;

function randInt(n) {
  const zone = 4294967296 - (4294967296 % n);
  const b = new Uint32Array(1);
  for (;;) { crypto.getRandomValues(b); if (b[0] < zone) return b[0] % n; }
}

function poolFor(o) {
  return ["lower", "upper", "digits", "symbols"].filter((k) => o[k]).map((k) => [...GEN[k]].filter((c) => !(o.plain && GEN.alike.includes(c))));
}

function makePassword(o) {
  const sets = poolFor(o);
  if (!sets.length) return "";
  const all = sets.flat();
  const out = sets.map((set) => set[randInt(set.length)]);
  while (out.length < o.length) out.push(all[randInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const k = randInt(i + 1); [out[i], out[k]] = [out[k], out[i]]; }
  return out.join("");
}

function generator(policy) {
  const o = { length: 24, lower: true, upper: true, digits: true, symbols: true, plain: false };
  if (policy && policy.type === "password") Object.assign(o, { length: Math.max(LEN_MIN, Math.min(LEN_MAX, policy.length || 24)), lower: policy.lower !== false, upper: policy.upper !== false, digits: policy.digits !== false, symbols: policy.symbols !== "", plain: !!policy.exclude_ambiguous });
  let typed = false;
  const field = h("input", { class: "pw", type: "text", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "Password. Type here to use your own" });
  // The length slider is a runway: lights come on up to the chosen length.
  const range = h("input", { type: "range", min: String(LEN_MIN), max: String(LEN_MAX), step: "1", value: String(o.length), "aria-label": "Password length" });
  const dots = Array.from({ length: LIGHTS }, () => h("i", {}));
  const strip = h("div", { class: "strip" }, dots, range);
  const verdict = h("div", { class: "verdict" });
  const chip = (key, label, title) => {
    const box = h("input", { type: "checkbox", checked: o[key], "aria-label": title });
    box.addEventListener("change", () => {
      o[key] = box.checked;
      if (!poolFor(o).length) { o[key] = true; box.checked = true; return; }   // keep at least one set
      roll();
    });
    return h("label", { class: "chip", title }, box, h("span", {}, label));
  };
  function meter() {
    const v = field.value;
    let bits;
    if (typed) {
      const pool = (/[a-z]/.test(v) ? 26 : 0) + (/[A-Z]/.test(v) ? 26 : 0) + (/[0-9]/.test(v) ? 10 : 0) + (/[^A-Za-z0-9]/.test(v) ? 20 : 0);
      bits = v.length * Math.log2(pool || 1);
    } else bits = o.length * Math.log2(poolFor(o).flat().length);
    const grade = bits < 60 ? "weak" : bits < 90 ? "fair" : "";
    verdict.className = "verdict " + grade;
    verdict.textContent = typed
      ? `Typed by hand, ${v.length} characters. ${grade === "weak" ? "Too easy to guess." : grade === "fair" ? "Acceptable." : "Strong, if it is not reused or a phrase."}`
      : `${o.length} characters. ${grade === "weak" ? "Weak" : grade === "fair" ? "Good" : "Strong"}, about ${Math.round(bits)} bits.`;
    const len = typed ? Math.max(LEN_MIN, Math.min(LEN_MAX, v.length)) : o.length;
    const lit = Math.round(((len - LEN_MIN) / (LEN_MAX - LEN_MIN)) * (LIGHTS - 1));
    dots.forEach((dEl, i) => { dEl.className = i === lit ? "lit knob" : i < lit ? "lit" : ""; });
  }
  function roll() { typed = false; field.value = makePassword(o); range.value = String(o.length); meter(); }
  range.addEventListener("input", () => { o.length = Number(range.value); roll(); });
  field.addEventListener("input", () => { typed = true; meter(); });
  const el = h("div", { class: "gen" },
    field,
    h("div", { class: "runway" }, h("span", {}, LEN_MIN), strip, h("span", {}, LEN_MAX)),
    verdict,
    h("div", { class: "opts" }, chip("lower", "a-z", "Lowercase letters"), chip("upper", "A-Z", "Capital letters"), chip("digits", "0-9", "Digits"), chip("symbols", "!@#", "Symbols"), chip("plain", "no l1O0", "Leave out characters that look alike")),
    h("div", { class: "foot" }, h("span", { class: "hint" }, "Or type your own above"),
      h("button", { class: "link", type: "button", onclick: roll }, "Regenerate"),
      h("button", { class: "link", type: "button", onclick: async () => { try { await navigator.clipboard.writeText(field.value); toast("Copied"); } catch (_) { toast("Copy failed, select it by hand", true); } } }, "Copy")));
  roll();
  return {
    el,
    value: () => field.value,
    // Remembered so rotations keep the same shape; null when typed by hand.
    policy: () => (typed ? null : { type: "password", length: o.length, lower: o.lower, upper: o.upper, digits: o.digits, symbols: o.symbols ? null : "", exclude_ambiguous: o.plain }),
  };
}

// Cmd/Ctrl+Enter submits the dialog's form from any field.
function quickSave(dlg) {
  dlg.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); const f = dlg.querySelector("form"); if (f) f.requestSubmit(); }
  });
}
const SAVE_HINT = (MAC ? "⌘" : "Ctrl") + " Enter to save";

function secretDialog(existing, done) {
  const m = existing ? existing.meta : { title: "", username: "", url: "", notes: "", tags: [] };
  const kinds = [["password", "Login or password"], ["api_key", "API key"], ["ssh_key", "SSH key"], ["config", "Configuration"], ["note", "Secure note"]];
  const f = {
    title: h("input", { class: "big", type: "text", placeholder: "Name, like GitHub or Proxmox root", value: m.title || "", autocomplete: "off", maxlength: "200", autofocus: true, required: !existing, "aria-label": "Name" }),
    folder: folderSelect(state.folder || "", { allowNew: true }),
    newFolder: h("input", { type: "text", placeholder: "Name of the new folder", autocomplete: "off" }),
    kind: h("select", {}, kinds.map(([k, l]) => h("option", { value: k }, l))),
    username: h("input", { type: "text", value: m.username, autocomplete: "off", placeholder: "Username", "aria-label": "Username" }),
    url: h("input", { type: "text", value: m.url, placeholder: "Website", autocomplete: "off", "aria-label": "Website" }),
    tags: h("input", { type: "text", value: m.tags.join(", "), placeholder: "Tags, separated with commas", autocomplete: "off", "aria-label": "Tags" }),
    notes: h("textarea", { placeholder: "Notes", "aria-label": "Notes" }, m.notes),
    content: h("textarea", { class: "mono", spellcheck: "false", placeholder: "Paste the key or text to keep safe" }),
  };
  const gen = generator(existing && existing.meta.policy);
  const err = h("div", { class: "error" });
  const where = h("span", { class: "hint" });
  const newFolderRow = h("div", { hidden: true }, h("label", {}, "New folder"), f.newFolder);
  const genRow = h("div", {}, gen.el);
  const contentRow = h("div", { hidden: true }, h("label", {}, "Content"), f.content);
  // When editing, the secret itself only changes if the person asks for that.
  let replacing = !existing;
  const replaceBtn = h("button", { class: "btn", type: "button", onclick: () => { replacing = true; sync(); } }, "Change the password");
  const generated = () => ["password", "api_key"].includes(existing ? existing.kind : f.kind.value);
  const target = () => {
    const folder = f.folder.value === "\u0000new" ? slug(f.newFolder.value) : f.folder.value;
    return (folder ? folder + "/" : "") + (slug(f.title.value) || "item");
  };
  const sync = () => {
    newFolderRow.hidden = f.folder.value !== "\u0000new";
    genRow.hidden = !replacing || !generated();
    contentRow.hidden = !replacing || generated();
    replaceBtn.hidden = replacing;
    if (!existing) where.textContent = "Agents will know it as " + target();
  };
  [f.title, f.newFolder].forEach((el) => el.addEventListener("input", sync));
  [f.folder, f.kind].forEach((el) => el.addEventListener("change", sync));
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const meta = { title: f.title.value.trim(), username: f.username.value, url: f.url.value, notes: f.notes.value, tags: f.tags.value.split(",").map((t) => t.trim()).filter(Boolean) };
      if (existing && existing.meta.policy) meta.policy = existing.meta.policy;
      const body = existing ? { path: existing.path, meta } : { path: target(), kind: f.kind.value, meta };
      if (replacing) {
        const value = generated() ? gen.value() : f.content.value;
        if (!value) { err.textContent = generated() ? "The password is empty." : "Add the content to keep."; return; }
        body.value = value;
        const pol = generated() ? gen.policy() : null;
        if (pol) { if (existing) meta.policy = pol; else body.policy = pol; }
      }
      try {
        if (!existing && f.folder.value === "\u0000new" && !slug(f.newFolder.value)) { err.textContent = "Give the new folder a name."; return; }
        await api("POST", existing ? "/v1/secrets/update" : "/v1/secrets/create", body);
        if (!existing) state.selected = body.path;
        dlg.close(); toast(existing ? "Saved" : "Added to the vault"); done();
      } catch (ex) {
        err.textContent = ex.status === 409 ? "This folder already has an item with that name."
          : ex.status === 403 && replacing ? "This access token may not set passwords by hand. Ask an admin for the write permission." : ex.message;
      }
    } },
      h("div", { class: "title" }, h("h3", {}, existing ? "Edit item" : "New item"), !existing && where),
      f.title,
      genRow, contentRow,
      h("div", { class: "two gap" }, f.username, f.url),
      !existing && h("div", { class: "two" }, h("div", {}, h("label", {}, "Folder"), f.folder), h("div", {}, h("label", {}, "Kind"), f.kind)),
      !existing && newFolderRow,
      h("div", { class: "stack" }, f.tags, f.notes),
      err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, existing ? "Save changes" : "Add to vault"),
        existing && replaceBtn,
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("span", { class: "hint" }, SAVE_HINT))));
  quickSave(dlg);
  sync();
  dlg.showModal();
}

function moveDialog(d, done) {
  const sel = folderSelect(folderOf(d.path));
  const err = h("div", { class: "error" });
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const np = (sel.value ? sel.value + "/" : "") + leafOf(d.path);
      if (np === d.path) return dlg.close();
      try { await api("POST", "/v1/secrets/move", { path: d.path, new_path: np }); state.selected = np; dlg.close(); toast("Moved to " + folderLabel(sel.value)); done(); }
      catch (ex) { err.textContent = ex.status === 409 ? "That folder already has an item with this name." : ex.message; }
    } },
      h("h3", {}, "Move " + (d.meta.title || pretty(leafOf(d.path)))),
      h("p", { class: "hint" }, "History and rotation setup move with it. Its address changes, so anything that refers to the old address must be updated."),
      h("label", {}, "Move to folder"), sel, err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Move"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"))));
  dlg.showModal();
}

function folderDialog(folder, done) {
  const err = h("div", { class: "error" });
  const name = h("input", { type: "text", value: folder ? pretty(leafOf(folder.path)) : "", placeholder: "Personal, Work, Business…", autocomplete: "off", required: true, autofocus: true });
  const parent = folderSelect(folder ? folderOf(folder.path) : state.folder || "", { exclude: folder && folder.path, rootLabel: "Top level" });
  const dest = () => { const leaf = slug(name.value); return leaf ? (parent.value ? parent.value + "/" : "") + leaf : ""; };
  const finish = (msg, sel) => { if (sel !== undefined) state.folder = sel; dlg.close(); toast(msg); done(); };
  async function save(e) {
    e.preventDefault(); err.textContent = "";
    const to = dest();
    if (!to) { err.textContent = "Use letters or numbers in the name."; return; }
    try {
      if (!folder) { await api("POST", "/v1/folders/create", { path: to }); return finish("Folder created", to); }
      if (to === folder.path) return dlg.close();
      await api("POST", "/v1/folders/move", { from: folder.path, to });
      finish("Folder updated", to);
    } catch (ex) { err.textContent = ex.status === 409 ? "Some items would collide with ones already there: " + ex.message : ex.message; }
  }
  let removal = null;
  if (folder) {
    const keep = h("input", { type: "radio", name: "what", checked: true });
    const drop = h("input", { type: "radio", name: "what" });
    const where = folderSelect(folderOf(folder.path), { exclude: folder.path, rootLabel: "Top level (no folder)" });
    const n = folder.count;
    removal = h("div", { class: "danger-zone" },
      h("h4", {}, "Delete this folder"),
      n === 0 ? h("p", { class: "hint" }, "This folder is empty.")
        : h("div", {},
            h("p", { class: "hint" }, `It contains ${n} item${n === 1 ? "" : "s"}, including any in sub-folders. What should happen to ${n === 1 ? "it" : "them"}?`),
            h("label", { class: "check" }, keep, "Move " + (n === 1 ? "it" : "them") + " to"), where,
            h("label", { class: "check" }, drop, `Delete ${n === 1 ? "it" : "all " + n} as well`)),
      h("div", { class: "actions" }, h("button", { class: "btn danger outline", type: "button", onclick: async () => {
        err.textContent = "";
        const wipe = n > 0 && drop.checked;
        if (wipe && !confirm(`Delete the folder ${folderLabel(folder.path)} and the ${n} item${n === 1 ? "" : "s"} in it?`)) return;
        const body = { path: folder.path };
        if (!wipe) body.move_to = n === 0 ? folderOf(folder.path) : where.value;
        try { await api("POST", "/v1/folders/delete", body); finish(wipe ? "Folder and items deleted" : "Folder deleted", ""); }
        catch (ex) { err.textContent = ex.status === 409 ? "The destination already has an item with the same name: " + ex.message : ex.message; }
      } }, "Delete folder")));
  }
  const dlg = dialog(null,
    h("form", { onsubmit: save },
      h("h3", {}, folder ? "Folder " + folderLabel(folder.path) : "New folder"),
      h("div", { class: "two" }, h("div", {}, h("label", {}, "Name"), name), h("div", {}, h("label", {}, "Inside"), parent)),
      folder && h("p", { class: "hint" }, "Renaming or moving a folder changes the address of everything in it."),
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, folder ? "Save" : "Create folder"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel")),
      removal, err));
  dlg.showModal();
}

function driverDialog(d, done) {
  const presets = {
    ssh: { type: "ssh", host: "server-name", user: "root", command: "chpasswd", stdin: "{{username}}:{{new}}\n", timeout_secs: 30 },
    exec: { type: "exec", argv: ["/usr/local/bin/rotate-script"], stdin: "{{new}}", timeout_secs: 30 },
  };
  const text = h("textarea", { spellcheck: "false", class: "code" }, JSON.stringify(d.driver || presets.ssh, null, 2));
  const err = h("div", { class: "error" });
  async function save(driver) {
    err.textContent = "";
    try { await api("POST", "/v1/secrets/driver", { path: d.path, driver }); dlg.close(); toast(driver ? "Rotation set up" : "Rotation removed"); done(); }
    catch (ex) { err.textContent = ex.message; }
  }
  const dlg = dialog(null,
    h("h3", {}, "Rotation for " + itemName(d)),
    h("p", { class: "hint" }, "How the vault pushes a new password to the real system. The password is sent on the command's standard input only. Placeholders: {{new}}, {{old}}, {{username}}."),
    h("div", { class: "row" },
      h("button", { class: "btn small", type: "button", onclick: () => { text.value = JSON.stringify(presets.ssh, null, 2); } }, "Over SSH"),
      h("button", { class: "btn small", type: "button", onclick: () => { text.value = JSON.stringify(presets.exec, null, 2); } }, "Program on the vault host")),
    h("label", {}, "Setup, as JSON"), text, err,
    h("div", { class: "actions" },
      h("button", { class: "btn primary", type: "button", onclick: () => { let j; try { j = JSON.parse(text.value); } catch (ex) { err.textContent = "Not valid JSON: " + ex.message; return; } save(j); } }, "Save rotation setup"),
      d.has_driver && h("button", { class: "btn danger ghost", type: "button", onclick: () => confirm("Remove rotation setup for this item?") && save(null) }, "Remove"),
      h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel")));
  dlg.showModal();
}

// ----------------------------------------------------------------- tokens

const stateLamp = (s) => ({ active: "green", ok: "green", current: "green", pending: "amber", denied: "red", error: "red", failed: "red", revoked: "red", expired: "amber", rejected: "amber" })[s] || "";
const stateCell = (s) => h("span", { class: "st" }, lamp(stateLamp(s)), s);

async function viewTokens(main) {
  const body = h("tbody", {});
  main.replaceChildren(
    h("div", { class: "head" }, h("h2", { class: "grow" }, "Access tokens"), h("button", { class: "btn primary", onclick: () => tokenDialog(load) }, "New token")),
    h("div", { class: "tablewrap" }, h("table", { class: "plain" },
      h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Role"), h("th", {}, "Can do"), h("th", {}, "Last used"), h("th", {}, "Expires"), h("th", {}, "State"), h("th", {}))), body)));
  async function load() {
    let rows;
    try { rows = await api("GET", "/v1/tokens"); } catch (e) { return fail(e); }
    body.replaceChildren(...rows.map((t) => {
      const st = t.revoked_at ? "revoked" : t.expires_at && t.expires_at * 1000 < Date.now() ? "expired" : "active";
      return h("tr", {},
        h("td", {}, t.name, h("div", { class: "hint mono" }, t.id)),
        h("td", {}, t.role),
        h("td", { class: "mono" }, t.role === "admin" ? "everything" : t.rules.length ? t.rules.map((r) => h("div", {}, `${r.path}  ${r.caps.join(", ")}`)) : "nothing"),
        h("td", { class: "nw" }, fmt(t.last_used_at)), h("td", { class: "nw" }, t.expires_at ? fmt(t.expires_at) : "never"),
        h("td", {}, stateCell(st)),
        h("td", {}, st === "active" && t.id !== state.me.id && h("button", { class: "link danger", onclick: async () => {
          if (!confirm(`Revoke the token ${t.name}? Anything using it stops working immediately.`)) return;
          try { await api("POST", "/v1/tokens/revoke", { id: t.id }); toast("Revoked"); load(); } catch (e) { fail(e); }
        } }, "Revoke")));
    }));
  }
  load();
}

function tokenDialog(done) {
  const caps = ["list", "create", "update", "generate", "rotate", "delete", "write", "reveal", "upgrade"];
  const name = h("input", { type: "text", placeholder: "claude-homelab", required: true, pattern: "[A-Za-z0-9._\\-]{1,64}", autocomplete: "off", autofocus: true });
  const role = h("select", {}, [["agent", "Agent (can never read passwords)"], ["human", "Person"], ["admin", "Admin (everything)"]].map(([r, l]) => h("option", { value: r }, l)));
  const path = h("input", { type: "text", class: "mono", value: "infra/**", spellcheck: "false", autocomplete: "off" });
  const ttl = h("input", { type: "number", min: "1", max: "3650", placeholder: "Never" });
  const boxes = caps.map((c) => [c, h("input", { type: "checkbox", checked: ["list", "generate", "rotate"].includes(c) })]);
  const err = h("div", { class: "error" });
  const scope = h("div", {}, h("label", {}, "Where it applies"), path, h("label", {}, "What it may do"),
    h("div", { class: "opts row" }, boxes.map(([c, b]) => h("label", { class: "chip" }, b, h("span", {}, c)))));
  const sync = () => {
    scope.hidden = role.value === "admin";
    const rv = boxes.find(([c]) => c === "reveal");
    rv[1].disabled = role.value === "agent";
    if (role.value === "agent") rv[1].checked = false;
  };
  role.addEventListener("change", sync);
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault(); err.textContent = "";
    const body = { name: name.value.trim(), role: role.value, rules: [], ttl_days: ttl.value ? Number(ttl.value) : null };
    if (role.value !== "admin") body.rules = [{ path: path.value.trim(), caps: boxes.filter(([, b]) => b.checked).map(([c]) => c) }];
    try {
      const r = await api("POST", "/v1/tokens/create", body);
      form.replaceChildren(h("h3", {}, "Token created"), h("p", { class: "hint" }, "Copy it now. It is shown once and cannot be recovered."),
        h("div", { class: "once" }, r.token),
        h("div", { class: "actions" },
          h("button", { class: "btn primary", type: "button", onclick: async () => { try { await navigator.clipboard.writeText(r.token); toast("Copied"); } catch (_) { toast("Copy failed, select it by hand", true); } } }, "Copy token"),
          h("button", { class: "btn ghost", type: "button", onclick: () => { dlg.close(); done(); } }, "Done")));
    } catch (ex) { err.textContent = ex.message; }
  } },
    h("h3", {}, "New access token"),
    h("div", { class: "two" }, h("div", {}, h("label", {}, "Name"), name), h("div", {}, h("label", {}, "Who it is for"), role)),
    scope, h("label", {}, "Expires after this many days"), ttl, err,
    h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Create token"),
      h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel")));
  const dlg = dialog(null, form);
  sync();
  dlg.showModal();
}

// ------------------------------------------------------------------ audit

async function viewAudit(main) {
  const body = h("tbody", {});
  const chain = h("span", { class: "st" }, lamp(""), "Checking the log…");
  const more = h("button", { class: "btn", onclick: () => load(false) }, "Load older entries");
  more.style.marginTop = "14px";
  let oldest = null;
  main.replaceChildren(
    h("div", { class: "head" }, h("h2", {}, "Audit log"), chain, h("div", { class: "grow" }),
      h("button", { class: "btn", onclick: verify }, "Check for tampering"), h("button", { class: "btn", onclick: () => load(true) }, "Refresh")),
    h("div", { class: "tablewrap" }, h("table", { class: "plain" },
      h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "Time"), h("th", {}, "Who"), h("th", {}, "Did"), h("th", {}, "Item"), h("th", {}, "Result"), h("th", {}, "Detail"))), body)),
    more);
  async function verify() {
    try {
      const r = await api("GET", "/v1/audit/verify");
      chain.replaceChildren(lamp(r.intact ? "green" : "red"), r.intact ? `Untampered, ${r.rows} entries` : `Tampered with at entry ${r.first_bad_seq}`);
    } catch (e) { fail(e); }
  }
  async function load(reset) {
    if (reset) { oldest = null; body.replaceChildren(); }
    let rows;
    try { rows = await api("GET", "/v1/audit?limit=100" + (oldest ? "&before=" + oldest : "")); } catch (e) { return fail(e); }
    more.hidden = rows.length < 100;
    if (rows.length) oldest = rows[rows.length - 1].seq;
    body.append(...rows.map((r) => h("tr", {},
      h("td", { class: "num" }, r.seq), h("td", { class: "nw mono" }, fmt(r.ts)), h("td", { class: "mono" }, who(r.actor)), h("td", { class: "mono" }, r.action),
      h("td", { class: "mono" }, r.path), h("td", {}, stateCell(r.outcome)), h("td", {}, r.detail))));
  }
  load(true); verify();
}

// ---------------------------------------------------------------- updates

async function viewUpdates(main) {
  const box = h("div", { class: "panel" });
  main.replaceChildren(h("div", { class: "head" }, h("h2", {}, "Updates")), box);
  let timer;
  const busy = (s) => ["checking", "downloading", "installing"].includes(s);
  async function send(body) {
    try { await api("POST", "/v1/sys/update", body); toast("Requested"); setTimeout(load, 1500); } catch (e) { fail(e); }
  }
  async function load() {
    clearTimeout(timer);
    if (state.view !== "updates" || !box.isConnected) return;
    let s;
    try { s = await api("GET", "/v1/sys/update"); }
    catch (e) { if (e.status) return fail(e); timer = setTimeout(load, 2000); return box.replaceChildren(h("p", { class: "hint" }, "The vault is restarting…")); }
    const hp = (s.enabled && s.helper) || {};
    const latest = hp.latest || "";
    const newer = latest && latest !== s.current;
    box.replaceChildren(
      h("dl", { class: "kv" },
        h("dt", {}, "Installed"), h("dd", { class: "mono" }, s.current),
        h("dt", {}, "Latest"), h("dd", { class: "mono" }, latest || "Not checked yet"),
        h("dt", {}, "Status"), h("dd", {}, hp.state ? h("span", { class: "st" }, lamp(hp.state === "failed" ? "red" : busy(hp.state) ? "amber" : "green"), hp.message || hp.state) : "—"),
        h("dt", {}, "Last run"), h("dd", {}, hp.ts ? fmt(hp.ts) : "—")),
      s.enabled
        ? h("div", { class: "row" },
            h("button", { class: "btn", disabled: busy(hp.state), onclick: () => send({ action: "check" }) }, "Check for updates"),
            newer && h("button", { class: "btn primary", disabled: busy(hp.state), onclick: () => confirm(`Install ${latest}? The vault will restart and stay sealed until you enter the passphrase.`) && send({ action: "apply", version: latest }) }, "Install " + latest))
        : h("p", {}, "Updates are switched off. They turn on once your release signing key is installed on the vault host, so that only releases you signed can ever be installed."),
      h("p", { class: "hint" }, "Only releases signed with your release key are accepted. The signature is checked by a separate root helper, not by the vault itself, and a version that fails to start is rolled back automatically."));
    if (busy(hp.state) || s.pending_request) timer = setTimeout(load, 1500);
  }
  load();
}

boot();
