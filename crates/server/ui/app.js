// jaword web UI. No frameworks and no inline script. Every piece of server
// data reaches the page as a text node, never parsed as markup, so a stored
// value cannot turn into HTML or script. The API token lives in sessionStorage (gone when the tab closes).
"use strict";

const REVEAL_SECONDS = 30;
const IDLE_LOCK_MS = 10 * 60 * 1000;
const state = { token: null, me: null, view: "secrets", secrets: [], selected: null, filter: "" };
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

function fmt(ts) {
  if (!ts) return "never";
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function logout() {
  state.token = null; state.me = null; state.selected = null; state.secrets = [];
  try { sessionStorage.removeItem("jaword.token"); } catch (_) { /* ignore */ }
  boot();
}

let idleTimer;
function armIdle() {
  clearTimeout(idleTimer);
  if (state.token) idleTimer = setTimeout(() => { toast("Locked after inactivity"); logout(); }, IDLE_LOCK_MS);
}
["pointerdown", "keydown"].forEach((e) => document.addEventListener(e, armIdle, { passive: true }));

// ------------------------------------------------------------------ gates

function gate(title, text, ...body) {
  root.replaceChildren(h("div", { class: "gate" }, h("div", { class: "card" },
    h("div", { class: "brand" }, h("div", { class: "mark" }, "j"), h("span", {}, "jaword")),
    h("h1", {}, title), h("p", {}, text), ...body)));
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

async function boot() {
  let st;
  try { st = await api("GET", "/v1/sys/status"); }
  catch (e) { return gate("Vault unreachable", e.message, h("button", { class: "btn", onclick: boot }, "Retry")); }
  if (!st.initialized) {
    return gate("Not initialized", "Create the vault from a terminal so the recovery key never passes through a browser.",
      h("p", {}, h("code", {}, "jaword init")), h("button", { class: "btn", onclick: boot }, "Check again"));
  }
  if (st.sealed) {
    return gate("Vault is sealed", "Encryption keys are not in memory. Enter the unseal passphrase or recovery key.",
      gateForm("Passphrase", "unseal passphrase", "Unseal", async (v) => { await api("POST", "/v1/sys/unseal", { credential: v }); boot(); }));
  }
  if (state.token) {
    try { state.me = await api("GET", "/v1/whoami"); armIdle(); return shell(); }
    catch (e) { state.token = null; try { sessionStorage.removeItem("jaword.token"); } catch (_) { /* ignore */ } }
  }
  gate("Sign in", "Paste your API token. It is kept for this tab only.",
    gateForm("Token", "jw_…", "Sign in", async (v) => {
      state.token = v.trim();
      try { state.me = await api("GET", "/v1/whoami"); }
      catch (e) { state.token = null; throw e; }
      try { sessionStorage.setItem("jaword.token", state.token); } catch (_) { /* ignore */ }
      armIdle(); shell();
    }));
}

// ------------------------------------------------------------------ shell

const isAdmin = () => state.me && state.me.role === "admin";

function shell() {
  const views = [["secrets", "Secrets"]];
  if (isAdmin()) views.push(["tokens", "Tokens"], ["audit", "Audit log"]);
  const main = h("main", { class: "main" });
  const nav = views.map(([id, label]) => h("button", { class: "nav" + (state.view === id ? " on" : ""), onclick: () => { state.view = id; shell(); } }, label));
  root.replaceChildren(h("div", { class: "shell" },
    h("aside", { class: "side" },
      h("div", { class: "brand" }, h("div", { class: "mark" }, "j"), h("span", {}, "jaword")),
      ...nav,
      h("div", { class: "foot" },
        h("b", {}, state.me.name), h("small", {}, state.me.role), h("div", { class: "row", style: null },
          h("button", { class: "btn small ghost", onclick: logout }, "Sign out"),
          isAdmin() && h("button", { class: "btn small ghost danger", onclick: sealVault }, "Seal")))),
    main));
  ({ secrets: viewSecrets, tokens: viewTokens, audit: viewAudit })[state.view](main);
}

async function sealVault() {
  if (!confirm("Seal the vault? Nothing can be read or rotated until someone unseals it with the passphrase.")) return;
  try { await api("POST", "/v1/sys/seal", {}); logout(); } catch (e) { toast(e.message, true); }
}

function fail(e) {
  if (e.status === 401) { toast("Session ended", true); return logout(); }
  if (e.code === "sealed") return boot();
  toast(e.message, true);
}

// ---------------------------------------------------------------- secrets

async function viewSecrets(main) {
  const listEl = h("div", { class: "list" });
  const detailEl = h("div", {});
  const search = h("input", { type: "search", placeholder: "Filter by path, user or tag", value: state.filter, "aria-label": "Filter secrets",
    oninput: (e) => { state.filter = e.target.value; renderList(); } });
  main.replaceChildren(
    h("div", { class: "head" }, h("h2", {}, "Secrets"), h("div", { class: "grow" }, search),
      h("button", { class: "btn primary", onclick: () => secretDialog(null, reload) }, "New secret")),
    h("div", { class: "split" }, listEl, detailEl));

  function renderList() {
    const q = state.filter.trim().toLowerCase();
    const rows = state.secrets.filter((s) => !q || s.path.includes(q) || s.meta.username.toLowerCase().includes(q) || s.meta.tags.some((t) => t.toLowerCase().includes(q)));
    if (!rows.length) return listEl.replaceChildren(h("div", { class: "empty" }, state.secrets.length ? "Nothing matches." : "No secrets yet."));
    listEl.replaceChildren(...rows.map((s) => {
      const i = s.path.lastIndexOf("/");
      return h("button", { class: "item" + (state.selected === s.path ? " on" : ""), onclick: () => { state.selected = s.path; renderList(); renderDetail(); } },
        h("div", { class: "p" }, h("span", { class: "dir" }, s.path.slice(0, i + 1)), s.path.slice(i + 1)),
        h("div", { class: "m" }, h("span", {}, s.kind), h("span", {}, "v" + s.current_version), s.meta.username && h("span", {}, s.meta.username),
          s.has_driver && h("span", { class: "pill" }, "auto-rotate"), s.pending_rotation && h("span", { class: "pill pending" }, "pending")));
    }));
  }

  async function renderDetail() {
    if (!state.selected) return detailEl.replaceChildren(h("div", { class: "panel empty" }, "Select a secret to see its history."));
    let d;
    try { d = await api("GET", "/v1/secrets/get?path=" + encodeURIComponent(state.selected)); }
    catch (e) { state.selected = null; return fail(e); }
    detailEl.replaceChildren(secretPanel(d, reload));
  }

  async function reload() {
    try { state.secrets = await api("GET", "/v1/secrets"); } catch (e) { return fail(e); }
    if (state.selected && !state.secrets.some((s) => s.path === state.selected)) state.selected = null;
    renderList(); renderDetail();
  }
  reload();
}

function secretPanel(d, reload) {
  const val = h("div", { class: "val" }, "•••••••••••••••••••••");
  const note = h("div", { class: "hint" }, "Reveals are written to the audit log.");
  let hideTimer, tick;
  const hide = () => { clearTimeout(hideTimer); clearInterval(tick); val.textContent = "•••••••••••••••••••••"; val.className = "val"; note.textContent = "Reveals are written to the audit log."; };
  async function fetchValue(version) { return (await api("POST", "/v1/secrets/reveal", { path: d.path, version: version || null })).value; }
  async function reveal(version) {
    try {
      const v = await fetchValue(version);
      val.textContent = v; val.className = "val shown";
      let left = REVEAL_SECONDS;
      const label = version ? `Version ${version}. ` : "";
      note.textContent = `${label}Hides in ${left}s.`;
      clearTimeout(hideTimer); clearInterval(tick);
      tick = setInterval(() => { left -= 1; note.textContent = `${label}Hides in ${left}s.`; }, 1000);
      hideTimer = setTimeout(hide, REVEAL_SECONDS * 1000);
    } catch (e) { fail(e); }
  }
  async function copy() {
    try {
      const v = await fetchValue();
      await navigator.clipboard.writeText(v);
      toast("Copied. Clipboard clears in 30s.");
      setTimeout(async () => { try { if (await navigator.clipboard.readText() === v) await navigator.clipboard.writeText(""); } catch (_) { /* tab not focused */ } }, 30000);
    } catch (e) { fail(e); }
  }
  async function act(label, path, body, okMsg) {
    try {
      const r = await api("POST", path, body);
      if (r && r.rotated === false) toast("Rotation failed, old value kept: " + r.error, true); else toast(okMsg);
      reload();
    } catch (e) { fail(e); }
  }
  const m = d.meta;
  return h("div", { class: "panel" },
    h("h3", {}, d.path),
    h("div", { class: "row" }, h("span", { class: "pill" }, d.kind), h("span", { class: "pill current" }, "v" + d.current_version),
      d.has_driver && h("span", { class: "pill" }, "auto-rotate"), d.pending_rotation && h("span", { class: "pill pending" }, "rotation pending")),
    h("div", { class: "secretbox" }, val,
      h("button", { class: "btn small", onclick: () => (val.className.includes("shown") ? hide() : reveal()) }, "Reveal"),
      h("button", { class: "btn small", onclick: copy }, "Copy")),
    note,
    h("dl", { class: "kv" },
      h("dt", {}, "Username"), h("dd", {}, m.username || "—"),
      h("dt", {}, "URL"), h("dd", {}, m.url || "—"),
      h("dt", {}, "Tags"), h("dd", {}, m.tags.length ? m.tags.map((t) => h("span", { class: "pill" }, t)) : "—"),
      h("dt", {}, "Notes"), h("dd", {}, m.notes || "—"),
      h("dt", {}, "Updated"), h("dd", {}, fmt(d.updated_at)),
      d.driver && h("dt", {}, "Driver"), d.driver && h("dd", { class: "mono" }, d.driver.type === "ssh" ? `ssh ${d.driver.user}@${d.driver.host}: ${d.driver.command}` : d.driver.argv.join(" "))),
    h("div", { class: "row" },
      d.has_driver && h("button", { class: "btn primary", onclick: () => confirm(`Rotate ${d.path} on the live system now?`) && act("rotate", "/v1/secrets/rotate", { path: d.path }, "Rotated") }, "Rotate now"),
      h("button", { class: "btn", onclick: () => confirm("Generate a new value in the vault only? The live system is not changed.") && act("gen", "/v1/secrets/generate", { path: d.path }, "New version generated") }, "Generate new version"),
      h("button", { class: "btn", onclick: () => secretDialog(d, reload) }, "Edit"),
      d.pending_rotation && isAdmin() && h("button", { class: "btn", onclick: () => confirm("Promote the pending version to current?") && act("res", "/v1/secrets/resolve", { path: d.path, promote: true }, "Promoted") }, "Promote pending"),
      d.pending_rotation && isAdmin() && h("button", { class: "btn", onclick: () => confirm("Discard the pending version?") && act("res", "/v1/secrets/resolve", { path: d.path, promote: false }, "Discarded") }, "Discard pending"),
      h("button", { class: "btn danger ghost", onclick: () => confirm(`Delete ${d.path}?`) && act("del", "/v1/secrets/delete", { path: d.path }, "Deleted") }, "Delete")),
    h("h4", {}, "History"),
    h("div", { class: "tablewrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Ver"), h("th", {}, "State"), h("th", {}, "Created"), h("th", {}, "By"), h("th", {}))),
      h("tbody", {}, d.versions.map((v) => h("tr", {},
        h("td", { class: "num" }, v.version), h("td", {}, h("span", { class: "pill " + v.state }, v.state)),
        h("td", { class: "nw" }, fmt(v.created_at)), h("td", { class: "mono" }, v.created_by),
        h("td", {}, h("button", { class: "btn small ghost", onclick: () => reveal(v.version) }, "Reveal"))))))));
}

function secretDialog(existing, done) {
  const m = existing ? existing.meta : { username: "", url: "", notes: "", tags: [] };
  const f = {
    path: h("input", { type: "text", placeholder: "infra/pve/root", value: existing ? existing.path : "", disabled: !!existing, required: true, spellcheck: "false", autocomplete: "off" }),
    kind: h("select", { disabled: !!existing }, ["password", "api_key", "ssh_key", "config", "note"].map((k) => h("option", { value: k, selected: existing && existing.kind === k }, k))),
    username: h("input", { type: "text", value: m.username, autocomplete: "off" }),
    url: h("input", { type: "text", value: m.url, autocomplete: "off" }),
    tags: h("input", { type: "text", value: m.tags.join(", "), placeholder: "comma separated", autocomplete: "off" }),
    notes: h("textarea", {}, m.notes),
    own: h("input", { type: "checkbox" }),
    value: h("input", { type: "password", autocomplete: "new-password", placeholder: existing ? "leave empty to keep current value" : "your value" }),
    length: h("input", { type: "number", min: "12", max: "256", value: "32" }),
    symbols: h("input", { type: "checkbox", checked: true }),
  };
  const err = h("div", { class: "error" });
  const valueRow = h("div", { hidden: !existing }, h("label", {}, existing ? "New value (optional)" : "Value"), f.value);
  const genRow = h("div", { class: "two", hidden: !!existing },
    h("div", {}, h("label", {}, "Length"), f.length), h("label", { class: "check" }, f.symbols, "Include symbols"));
  f.own.addEventListener("change", () => { valueRow.hidden = !f.own.checked; genRow.hidden = f.own.checked; });
  const dlg = h("dialog", {},
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const meta = { username: f.username.value, url: f.url.value, notes: f.notes.value, tags: f.tags.value.split(",").map((t) => t.trim()).filter(Boolean) };
      if (existing && existing.meta.policy) meta.policy = existing.meta.policy;
      try {
        if (existing) {
          const body = { path: existing.path, meta };
          if (f.value.value) body.value = f.value.value;
          await api("POST", "/v1/secrets/update", body);
        } else {
          const body = { path: f.path.value.trim(), kind: f.kind.value, meta };
          if (f.own.checked) body.value = f.value.value;
          else body.policy = { type: "password", length: Number(f.length.value), symbols: f.symbols.checked ? null : "" };
          await api("POST", "/v1/secrets/create", body);
          state.selected = body.path;
        }
        dlg.close(); dlg.remove(); toast(existing ? "Saved" : "Created"); done();
      } catch (ex) { err.textContent = ex.message; }
    } },
      h("h3", {}, existing ? "Edit secret" : "New secret"),
      h("div", { class: "two" }, h("div", {}, h("label", {}, "Path"), f.path), h("div", {}, h("label", {}, "Kind"), f.kind)),
      h("div", { class: "two" }, h("div", {}, h("label", {}, "Username"), f.username), h("div", {}, h("label", {}, "URL"), f.url)),
      h("label", {}, "Tags"), f.tags, h("label", {}, "Notes"), f.notes,
      !existing && h("label", { class: "check" }, f.own, "I'll provide the value (otherwise the vault generates it)"),
      genRow, valueRow, err,
      h("div", { class: "row", style: null }, h("button", { class: "btn primary", type: "submit" }, existing ? "Save" : "Create"),
        h("button", { class: "btn ghost", type: "button", onclick: () => { dlg.close(); dlg.remove(); } }, "Cancel"))));
  document.body.append(dlg);
  dlg.showModal();
}

// ----------------------------------------------------------------- tokens

async function viewTokens(main) {
  const body = h("tbody", {});
  main.replaceChildren(
    h("div", { class: "head" }, h("h2", { class: "grow" }, "Tokens"), h("button", { class: "btn primary", onclick: () => tokenDialog(load) }, "New token")),
    h("div", { class: "tablewrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Role"), h("th", {}, "Access"), h("th", {}, "Last used"), h("th", {}, "Expires"), h("th", {}, "State"), h("th", {}))), body)));
  async function load() {
    let rows;
    try { rows = await api("GET", "/v1/tokens"); } catch (e) { return fail(e); }
    body.replaceChildren(...rows.map((t) => {
      const live = !t.revoked_at && !(t.expires_at && t.expires_at * 1000 < Date.now());
      return h("tr", {},
        h("td", {}, t.name, h("div", { class: "hint mono" }, t.id)),
        h("td", {}, h("span", { class: "pill " + t.role }, t.role)),
        h("td", { class: "mono" }, t.role === "admin" ? "everything" : t.rules.length ? t.rules.map((r) => h("div", {}, `${r.path} → ${r.caps.join(", ")}`)) : "nothing"),
        h("td", { class: "nw" }, fmt(t.last_used_at)), h("td", {}, t.expires_at ? fmt(t.expires_at) : "never"),
        h("td", {}, h("span", { class: "pill " + (live ? "active" : "revoked") }, live ? "active" : t.revoked_at ? "revoked" : "expired")),
        h("td", {}, live && t.id !== state.me.id && h("button", { class: "btn small danger ghost", onclick: async () => {
          if (!confirm(`Revoke token "${t.name}"? Anything using it stops working immediately.`)) return;
          try { await api("POST", "/v1/tokens/revoke", { id: t.id }); toast("Revoked"); load(); } catch (e) { fail(e); }
        } }, "Revoke")));
    }));
  }
  load();
}

function tokenDialog(done) {
  const caps = ["list", "create", "update", "generate", "rotate", "delete", "write", "reveal"];
  const name = h("input", { type: "text", placeholder: "claude-homelab", required: true, pattern: "[A-Za-z0-9._\\-]{1,64}", autocomplete: "off" });
  const role = h("select", {}, ["agent", "human", "admin"].map((r) => h("option", { value: r }, r)));
  const path = h("input", { type: "text", value: "infra/**", spellcheck: "false", autocomplete: "off" });
  const ttl = h("input", { type: "number", min: "1", max: "3650", placeholder: "no expiry" });
  const boxes = caps.map((c) => [c, h("input", { type: "checkbox", checked: ["list", "generate", "rotate"].includes(c) })]);
  const err = h("div", { class: "error" });
  const scope = h("div", {}, h("label", {}, "Path pattern"), path, h("label", {}, "Capabilities"),
    h("div", { class: "row" }, boxes.map(([c, b]) => h("label", { class: "check", "data-cap": c }, b, c))));
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
        h("div", { class: "row" },
          h("button", { class: "btn primary", type: "button", onclick: async () => { try { await navigator.clipboard.writeText(r.token); toast("Copied"); } catch (_) { toast("Copy failed, select it manually", true); } } }, "Copy"),
          h("button", { class: "btn ghost", type: "button", onclick: () => { dlg.close(); dlg.remove(); done(); } }, "Done")));
    } catch (ex) { err.textContent = ex.message; }
  } },
    h("h3", {}, "New token"),
    h("div", { class: "two" }, h("div", {}, h("label", {}, "Name"), name), h("div", {}, h("label", {}, "Role"), role)),
    scope, h("label", {}, "Expires after (days)"), ttl,
    h("p", { class: "hint" }, "Agent tokens can never reveal values, whatever is ticked here."), err,
    h("div", { class: "row" }, h("button", { class: "btn primary", type: "submit" }, "Create"),
      h("button", { class: "btn ghost", type: "button", onclick: () => { dlg.close(); dlg.remove(); } }, "Cancel")));
  const dlg = h("dialog", {}, form);
  document.body.append(dlg);
  sync();
  dlg.showModal();
}

// ------------------------------------------------------------------ audit

async function viewAudit(main) {
  const body = h("tbody", {});
  const chain = h("span", { class: "pill" }, "chain not checked");
  const more = h("button", { class: "btn", onclick: () => load(false) }, "Load older");
  let oldest = null;
  main.replaceChildren(
    h("div", { class: "head" }, h("h2", {}, "Audit log"), chain, h("div", { class: "grow" }),
      h("button", { class: "btn", onclick: verify }, "Verify chain"), h("button", { class: "btn", onclick: () => load(true) }, "Refresh")),
    h("div", { class: "tablewrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "Time"), h("th", {}, "Actor"), h("th", {}, "Action"), h("th", {}, "Path"), h("th", {}, "Result"), h("th", {}, "Detail"))), body)),
    h("div", { class: "row", style: null }, more));
  more.style.marginTop = "12px";
  async function verify() {
    try {
      const r = await api("GET", "/v1/audit/verify");
      chain.textContent = r.intact ? `chain intact · ${r.rows} rows` : `TAMPERED at #${r.first_bad_seq}`;
      chain.className = "pill " + (r.intact ? "ok" : "failed");
    } catch (e) { fail(e); }
  }
  async function load(reset) {
    if (reset) { oldest = null; body.replaceChildren(); }
    let rows;
    try { rows = await api("GET", "/v1/audit?limit=100" + (oldest ? "&before=" + oldest : "")); } catch (e) { return fail(e); }
    more.hidden = rows.length < 100;
    if (rows.length) oldest = rows[rows.length - 1].seq;
    body.append(...rows.map((r) => h("tr", {},
      h("td", { class: "num" }, r.seq), h("td", { class: "nw" }, fmt(r.ts)), h("td", { class: "mono" }, r.actor), h("td", { class: "mono" }, r.action),
      h("td", { class: "mono" }, r.path), h("td", {}, h("span", { class: "pill " + r.outcome }, r.outcome)), h("td", {}, r.detail))));
  }
  load(true); verify();
}

boot();
