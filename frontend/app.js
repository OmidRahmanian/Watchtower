// WatchTower dashboard. Plain DOM, no dependencies, no build step.
//
// Everything from the API is data, including content captured from scanned
// hosts (titles, headers, evidence excerpts). It is only ever inserted with
// textContent or as attribute values set through the DOM, never as HTML.
"use strict";

const API = "/api/v1";
const TOKEN_KEY = "watchtower.token";
const PROJECT_KEY = "watchtower.project";
const REFRESH_MS = 10000;

const state = { token: null, projects: [], project: null, view: "overview", timer: null, cursor: {} };

// ---- small DOM helpers -------------------------------------------------

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function text(value) {
  return value === undefined || value === null || value === "" ? "-" : String(value);
}

function when(iso) {
  if (!iso) return "-";
  const moment = new Date(iso);
  return isNaN(moment) ? String(iso) : moment.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function badge(label, kind) {
  return el("span", { class: `badge ${kind}` }, label);
}

// Failed and cancelled runs never share the colour of success.
const RUN_KIND = { succeeded: "ok", partial: "warn", failed: "bad", cancelled: "muted", queued: "info", running: "info" };
const REMEDIATION = {
  verified_fixed: ["Fixed, verified by retest", "ok"],
  retest_failed: ["Retest failed: not verified", "bad"],
  retest_inconclusive: ["Retest inconclusive: not verified", "warn"],
  retest_pending: ["Retest pending", "info"],
  still_present: ["Still present after retest", "bad"],
  not_retested: ["Not retested", "muted"],
};
const SEVERITY = { critical: "bad", high: "bad", medium: "warn", low: "info", info: "muted" };

function runBadge(status) {
  return badge(status.toUpperCase(), RUN_KIND[status] || "muted");
}

function remediationBadge(state) {
  const [label, kind] = REMEDIATION[state] || [state, "muted"];
  return badge(label, kind);
}

function notice(message, kind) {
  const box = document.getElementById("status");
  box.textContent = message || "";
  box.className = `status ${kind || ""}`;
}

// ---- API ---------------------------------------------------------------

class ApiError extends Error {
  constructor(status, body) {
    super((body && body.detail) || `request failed (${status})`);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const response = await fetch(API + path, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${state.token}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: "omit",
    cache: "no-store",
  });
  if (response.status === 401) {
    signOut("Your token was rejected. Sign in again.");
    throw new ApiError(401, null);
  }
  if (options.raw) {
    if (!response.ok) throw new ApiError(response.status, null);
    return response;
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(response.status, body);
  return body;
}

function projectPath(suffix) {
  return `/projects/${encodeURIComponent(state.project.id)}${suffix}`;
}

function can(permission) {
  return state.project && state.project.permissions.includes(permission);
}

// ---- session -----------------------------------------------------------

function storage(action, key, value) {
  try {
    if (action === "get") return sessionStorage.getItem(key);
    if (action === "set") sessionStorage.setItem(key, value);
    if (action === "remove") sessionStorage.removeItem(key);
  } catch (_) {
    return null;
  }
  return null;
}

async function signIn(token) {
  state.token = token;
  try {
    state.projects = await api("/projects");
  } catch (error) {
    state.token = null;
    notice(error.status === 401 ? "That token was not accepted." : error.message, "bad");
    return;
  }
  storage("set", TOKEN_KEY, token);
  if (!state.projects.length) {
    notice("This token has no projects.", "warn");
    return;
  }
  const remembered = storage("get", PROJECT_KEY);
  state.project = state.projects.find((p) => p.id === remembered) || state.projects[0];
  const select = document.getElementById("project");
  select.replaceChildren(...state.projects.map((p) =>
    el("option", { value: p.id, selected: p.id === state.project.id }, `${p.name} (${p.role})`)));
  document.getElementById("signin").hidden = true;
  document.getElementById("nav").hidden = false;
  document.getElementById("view").hidden = false;
  notice("");
  show("overview");
}

function signOut(message) {
  storage("remove", TOKEN_KEY);
  state.token = null;
  state.project = null;
  clearInterval(state.timer);
  document.getElementById("signin").hidden = false;
  document.getElementById("nav").hidden = true;
  document.getElementById("view").hidden = true;
  document.getElementById("view").replaceChildren();
  notice(message || "", message ? "warn" : "");
}

// ---- views -------------------------------------------------------------

const views = {};

async function show(view, arg) {
  state.view = view;
  clearInterval(state.timer);
  for (const button of document.querySelectorAll("#nav button[data-view]")) {
    button.classList.toggle("active", button.dataset.view === view);
  }
  const root = document.getElementById("view");
  try {
    await views[view](root, arg);
  } catch (error) {
    if (error.status !== 401) notice(error.message, "bad");
  }
  if (["overview", "runs", "alerts"].includes(view)) {
    // The monitoring views follow live state.
    state.timer = setInterval(() => views[view](root, arg).catch(() => {}), REFRESH_MS);
  }
}

function heading(title, ...extra) {
  return el("div", { class: "heading" }, el("h1", {}, title), ...extra);
}

function tableOf(headers, rows, empty) {
  if (!rows.length) return el("p", { class: "empty" }, empty);
  return el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows)));
}

function runRow(run) {
  return el("tr", { class: run.status === "failed" ? "row-bad" : "" },
    el("td", { class: "mono" }, run.run_id.slice(0, 8)),
    el("td", {}, run.kind),
    el("td", {}, runBadge(run.status)),
    el("td", {}, when(run.created_at)),
    el("td", {}, run.phases.map((p) => el("span", { class: "chip" }, `${p.phase}: ${p.comparison}`))),
    el("td", { class: "error" }, run.last_error || ""));
}

views.overview = async (root) => {
  const data = await api(projectPath("/overview"));
  const counts = data.counts;
  const open = counts.findings_by_status.open + counts.findings_by_status.triaged;
  const pending = data.rules.filter((r) => !r.approved);
  root.replaceChildren(
    heading(data.project.name),
    data.scope
      ? el("div", { class: "panel" },
        el("h2", {}, `Authorized scope: revision ${data.scope.number}`),
        el("p", {}, data.scope.rules.filter((r) => r.effect === "include").map((r) => r.pattern).join(", ")),
        el("p", { class: "hint" }, `Authorized by ${data.scope.authorization.granted_by} `
          + `(${data.scope.authorization.kind}: ${data.scope.authorization.reference})`))
      : el("div", { class: "panel warn" }, el("h2", {}, "No authorized scope"),
        el("p", {}, "Nothing is scanned until an owner publishes a scope revision with its authorization.")),
    el("div", { class: "tiles" },
      tile("Assets", Object.values(counts.assets).reduce((a, b) => a + b, 0)),
      tile("Open findings", open, open ? "bad" : "ok"),
      tile("Resolved (verified)", counts.findings_by_status.resolved, "ok"),
      tile("Critical / high open", counts.open_findings_by_severity.critical + counts.open_findings_by_severity.high,
        counts.open_findings_by_severity.critical + counts.open_findings_by_severity.high ? "bad" : "")),
    pending.length
      ? el("div", { class: "panel warn" }, el("h2", {}, "Detection rules pending maintainer approval"),
        el("p", {}, "These rules are listed but never run, so they cannot open or resolve findings: "
          + pending.map((r) => r.id).join(", ")))
      : null,
    el("h2", {}, "Latest runs"),
    data.runs_available
      ? tableOf(["Run", "Kind", "Status", "Created", "Phases", "Error"], data.latest_runs.map(runRow), "No runs yet.")
      : el("p", { class: "empty" }, "The monitoring runtime is not installed on this server."));
};

function tile(label, value, kind) {
  return el("div", { class: `tile ${kind || ""}` }, el("div", { class: "value" }, String(value)),
    el("div", { class: "label" }, label));
}

views.runs = async (root) => {
  const page = await api(projectPath("/runs?limit=50"));
  const start = can("operate")
    ? el("button", {
      onclick: async () => {
        try {
          const run = await api(projectPath("/runs"), { method: "POST", body: { reason: "started from dashboard" } });
          notice(`Queued run ${run.run_id.slice(0, 8)}.`, "ok");
          show("runs");
        } catch (error) { notice(error.message, "bad"); }
      },
    }, "Start run")
    : null;
  root.replaceChildren(heading("Runs", start),
    tableOf(["Run", "Kind", "Status", "Created", "Phases", "Error"], page.items.map(runRow), "No runs yet."));
};

function describeChange(change) {
  const parts = [change.type || "change", change.target || ""];
  if (change.key) parts.push(change.key);
  if (change.before !== undefined || change.after !== undefined) {
    parts.push(`${JSON.stringify(change.before ?? null)} -> ${JSON.stringify(change.after ?? null)}`);
  }
  return parts.join(" ");
}

views.alerts = async (root) => {
  const page = await api(projectPath("/alerts?limit=50"));
  root.replaceChildren(heading("Alerts"), page.items.length
    ? el("ul", { class: "feed" }, page.items.map((alert) => el("li", {},
      el("div", {}, badge(alert.event_type, alert.event_type === "monitor.run_failed" ? "bad" : "warn"), " ",
        when(alert.created_at), ` to ${alert.channel} (${alert.status})`,
        alert.last_error ? el("span", { class: "error" }, ` ${alert.last_error}`) : null),
      el("ul", {}, (alert.payload.changes || []).slice(0, 50).map((c) => el("li", { class: "mono" }, describeChange(c)))))))
    : el("p", { class: "empty" }, "No alerts yet."));
};

async function paged(root, title, path, render, headers, empty) {
  const key = `${state.project.id}:${path}`;
  const cursors = state.cursor[key] || (state.cursor[key] = [null]);
  const cursor = cursors[cursors.length - 1];
  const separator = path.includes("?") ? "&" : "?";
  const page = await api(projectPath(path + separator + "limit=50" + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "")));
  const prev = el("button", { disabled: cursors.length < 2, onclick: () => { cursors.pop(); paged(root, title, path, render, headers, empty); } }, "Previous");
  const next = el("button", { disabled: !page.next_cursor, onclick: () => { cursors.push(page.next_cursor); paged(root, title, path, render, headers, empty); } }, "Next");
  root.replaceChildren(heading(title), tableOf(headers, page.items.map(render), empty), el("div", { class: "pager" }, prev, next));
}

views.assets = (root) => paged(root, "Inventory", "/assets", (asset) => {
  const http = asset.last_http || {};
  return el("tr", {},
    el("td", { class: "mono" }, asset.value),
    el("td", {}, asset.kind),
    el("td", {}, badge(asset.authorization, asset.authorization === "authorized" ? "ok" : "warn")),
    el("td", { class: "mono" }, asset.addresses.join(", ") || "-"),
    el("td", {}, text(http.status_code || http.outcome)),
    el("td", {}, text(http.title)),
    el("td", {}, when(asset.last_seen_at)));
}, ["Asset", "Kind", "Authorization", "Addresses", "HTTP", "Title", "Last seen"], "No assets yet.");

views.findings = (root) => paged(root, "Findings", "/findings", (finding) => el("tr", {
  class: "link", tabindex: 0,
  onclick: () => show("finding", finding.id),
  onkeydown: (event) => { if (event.key === "Enter") show("finding", finding.id); },
},
el("td", {}, badge(finding.severity, SEVERITY[finding.severity])),
el("td", {}, finding.status),
el("td", {}, remediationBadge(finding.remediation)),
el("td", {}, finding.title),
el("td", { class: "mono" }, finding.target + finding.location),
el("td", {}, when(finding.last_seen_at))),
["Severity", "Status", "Remediation", "Title", "Where", "Last seen"], "No findings.");

views.finding = async (root, findingId) => {
  const f = await api(projectPath(`/findings/${encodeURIComponent(findingId)}`));
  const actions = el("div", { class: "actions" });
  if (can("operate")) {
    actions.append(el("button", {
      onclick: async () => {
        try {
          const run = await api(projectPath(`/findings/${encodeURIComponent(f.id)}/retest`), { method: "POST", body: {} });
          notice(`Retest queued as run ${run.run_id.slice(0, 8)}. Watch it under Runs.`, "ok");
        } catch (error) { notice(error.message, "bad"); }
      },
    }, "Request retest"));
    const choices = { open: ["triaged", "accepted_risk", "false_positive"], triaged: ["open", "accepted_risk", "false_positive"],
      accepted_risk: ["triaged"], false_positive: ["triaged"], resolved: [] }[f.status] || [];
    for (const status of choices) {
      actions.append(el("button", {
        class: "quiet",
        onclick: async () => {
          let reason = "";
          if (status === "accepted_risk" || status === "false_positive") {
            reason = window.prompt(`Reason for ${status.replace("_", " ")}:`) || "";
            if (!reason.trim()) return;
          }
          try {
            await api(projectPath(`/findings/${encodeURIComponent(f.id)}/status`), { method: "POST", body: { status, reason } });
            show("finding", f.id);
          } catch (error) { notice(error.message, "bad"); }
        },
      }, `Mark ${status.replace("_", " ")}`));
    }
  }
  const evidence = el("div", { class: "evidence" });
  root.replaceChildren(
    el("p", {}, el("button", { class: "quiet", onclick: () => show("findings") }, "Back to findings")),
    heading(f.title, badge(f.severity, SEVERITY[f.severity])),
    el("div", { class: "panel" },
      el("dl", { class: "facts" },
        fact("Where", f.target + f.location), fact("Check", `${f.check_id} v${f.rule_version} (${f.confidence})`),
        fact("Workflow status", f.status), fact("Remediation", remediationBadge(f.remediation)),
        fact("Detection", `${f.detection.state}, last outcome ${f.detection.last_outcome} at ${when(f.detection.last_outcome_at)}`),
        fact("First / last seen", `${when(f.first_seen_at)} / ${when(f.last_seen_at)}`),
        fact("Seen / recurred", `${f.occurrences} / ${f.recurrences}`),
        f.cves.length ? fact("CVEs", f.cves.join(", ")) : null),
      actions),
    el("h2", {}, "History"),
    tableOf(["When", "Event", "Details"], f.history.slice().reverse().map((event) => {
      const details = Object.entries(event).filter(([k, v]) => !["at", "event"].includes(k) && v !== null && v !== "");
      return el("tr", { class: /failed|inconclusive/.test(event.event) ? "row-bad" : "" },
        el("td", {}, when(event.at)), el("td", {}, event.event),
        el("td", { class: "mono" }, details.map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("  ")));
    }), "No history."),
    el("h2", {}, "Evidence"),
    f.evidence.length
      ? el("ul", { class: "feed" }, f.evidence.map((item) => el("li", {},
        `${when(item.created_at)}  ${item.size_bytes} bytes  ${item.description} `,
        el("button", { class: "quiet", onclick: () => viewEvidence(item, evidence) }, "View"),
        el("button", { class: "quiet", onclick: () => downloadEvidence(item) }, "Download"))))
      : el("p", { class: "empty" }, "No evidence stored."),
    evidence);
};

function fact(label, value) {
  return [el("dt", {}, label), el("dd", {}, value)];
}

async function viewEvidence(item, target) {
  try {
    const data = await api(projectPath(`/evidence/${encodeURIComponent(item.id)}`));
    // Redacted content captured from the target, shown as inert text.
    target.replaceChildren(el("h3", {}, `Evidence ${item.id}`),
      el("pre", { class: "captured" }, JSON.stringify(data.content, null, 2)));
  } catch (error) { notice(error.message, "bad"); }
}

async function downloadEvidence(item) {
  try {
    const response = await api(projectPath(`/evidence/${encodeURIComponent(item.id)}/download`), { raw: true });
    const blob = new Blob([await response.arrayBuffer()], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: `evidence-${item.id}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { notice(error.message, "bad"); }
}

views.scope = async (root) => {
  const scope = await api(projectPath("/scope"));
  const parts = [heading("Scope")];
  if (!scope.history.length) parts.push(el("p", { class: "empty" }, "No scope revisions published."));
  for (const revision of scope.history) {
    parts.push(el("div", { class: `panel ${revision.revocation ? "muted" : ""}` },
      el("h2", {}, `Revision ${revision.number} `, revision.revocation ? badge("REVOKED", "bad") : badge("in force", "ok")),
      el("p", { class: "hint" }, `${when(revision.created_at)}, ports ${revision.permitted_ports}, authorized by `
        + `${revision.authorization.granted_by} (${revision.authorization.kind}: ${revision.authorization.reference})`),
      el("ul", {}, revision.rules.map((r) => el("li", { class: "mono" }, `${r.effect} ${r.pattern}${r.ports ? " ports " + r.ports : ""}`))),
      revision.revocation ? el("p", { class: "error" }, `Revoked ${when(revision.revocation.revoked_at)}: ${revision.revocation.reason}`) : null));
  }
  if (can("manage_scope")) parts.push(publishForm());
  root.replaceChildren(...parts);
};

function publishForm() {
  const field = (id, label, attrs) => [el("label", { for: id }, label), el("input", { id, ...attrs })];
  const form = el("form", { class: "panel" },
    el("h2", {}, "Publish a new revision"),
    field("includes", "Include (comma-separated: example.com, *.example.com, 10.0.0.0/24)", { required: true }),
    field("excludes", "Exclude (optional)", {}),
    field("ports", "Permitted ports (optional, e.g. 80,443)", {}),
    el("label", { for: "auth-kind" }, "Authorization"),
    el("select", { id: "auth-kind" }, ["asset_owner", "contract", "internal_approval", "bug_bounty_program",
      "vulnerability_disclosure_program"].map((k) => el("option", { value: k }, k))),
    field("auth-ref", "Reference (program URL, contract id, approval ticket)", { required: true }),
    field("auth-by", "Granted by", { required: true }),
    el("label", { class: "check" }, el("input", { id: "attest", type: "checkbox", required: true }),
      " I am authorized to test every included target under this authorization."),
    el("button", { type: "submit" }, "Publish"));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const list = (id) => form.querySelector(`#${id}`).value.split(",").map((v) => v.trim()).filter(Boolean);
    try {
      await api(projectPath("/scope"), {
        method: "POST",
        body: {
          includes: list("includes"), excludes: list("excludes"),
          permitted_ports: form.querySelector("#ports").value.trim() || null,
          authorization: { kind: form.querySelector("#auth-kind").value, reference: form.querySelector("#auth-ref").value,
            granted_by: form.querySelector("#auth-by").value },
          attest_authorized: form.querySelector("#attest").checked,
        },
      });
      notice("Scope revision published.", "ok");
      show("scope");
    } catch (error) { notice(error.message, "bad"); }
  });
  return form;
}

// ---- start -------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("signin-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = document.getElementById("token");
    signIn(input.value.trim());
    input.value = "";
  });
  document.getElementById("signout").addEventListener("click", () => signOut());
  document.getElementById("project").addEventListener("change", (event) => {
    state.project = state.projects.find((p) => p.id === event.target.value);
    storage("set", PROJECT_KEY, state.project.id);
    state.cursor = {};
    show("overview");
  });
  for (const button of document.querySelectorAll("#nav button[data-view]")) {
    button.addEventListener("click", () => show(button.dataset.view));
  }
  const saved = storage("get", TOKEN_KEY);
  if (saved) signIn(saved);
});
