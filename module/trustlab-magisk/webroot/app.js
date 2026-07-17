import { call, supported } from "./bridge.js";
import { formatTime, messageFor, newestFirst, validCollectionId } from "./state.js";

const byId = (id) => document.getElementById(id);
const ui = { application: byId("application"), unsupported: byId("unsupported"), version: byId("version"), status: byId("status-text"), detail: byId("status-detail"), list: byId("collections"), empty: byId("empty"), details: byId("detail"), detailBody: byId("detail-body"), collect: byId("collect"), refresh: byId("refresh"), dialog: byId("confirm"), confirmTitle: byId("confirm-title"), confirmMessage: byId("confirm-message"), confirmation: byId("confirmation"), confirmLabel: byId("confirmation-label"), confirmSubmit: byId("confirm-submit") };
let busy = false;

function text(tag, value) { const node = document.createElement(tag); node.textContent = value; return node; }
function setBusy(value) { busy = value; ui.collect.disabled = value; ui.refresh.disabled = value; }
function status(message, detail = "") { ui.status.textContent = message; ui.detail.textContent = detail; }
function button(label, action, disabled = false) { const node = document.createElement("button"); node.type = "button"; node.textContent = label; node.disabled = disabled || busy; node.addEventListener("click", action); return node; }
function error(error) { status("Operation failed", messageFor(error)); }

async function refresh() {
  if (busy) return;
  setBusy(true); status("Refreshing collector status…");
  try {
    const [current, listed] = await Promise.all([call("status"), call("list")]);
    status(current.state, current.currentCollectionId ? `Current collection: ${current.currentCollectionId}; ${current.stage}` : current.stage);
    renderList(newestFirst(Array.isArray(listed.collections) ? listed.collections : []));
  } catch (exception) { error(exception); } finally { setBusy(false); }
}
function renderList(collections) {
  ui.list.replaceChildren(); ui.empty.hidden = collections.length !== 0;
  for (const collection of collections) {
    const card = document.createElement("article"); card.className = "collection";
    const heading = text("h3", collection.collectionId || "Unknown collection");
    const meta = text("p", `${collection.status || "unknown"} · ${collection.source || "unknown"} · ${formatTime(collection.startedAt)}`); meta.className = "muted";
    const facts = text("p", `${collection.artifactCount || 0} artifacts · ${collection.totalSize || 0} bytes · ${collection.verified ? "verified" : "unverified"}`); facts.className = "muted";
    const actions = document.createElement("div"); actions.className = "actions";
    const id = collection.collectionId;
    const valid = validCollectionId(id);
    actions.append(button("Details", () => inspect(id), !valid));
    actions.append(button("Verify", () => verify(id), !valid || collection.status !== "complete"));
    actions.append(button("Export", () => confirmExport(id), !valid || !collection.verified));
    actions.append(button("Delete", () => confirmDelete(id), !valid));
    card.append(heading, meta, facts, actions); ui.list.append(card);
  }
}
async function inspect(id) {
  if (busy || !validCollectionId(id)) return;
  setBusy(true); status("Loading sanitized metadata…");
  try {
    const data = await call("inspect", [id]);
    ui.detailBody.replaceChildren();
    ui.details.hidden = false;
    const overview = text("p", `${data.completion || "unknown"} collection from ${data.source || "unknown"}; started ${formatTime(data.startedAt)}.`);
    const list = document.createElement("ul");
    for (const artifact of Array.isArray(data.artifacts) ? data.artifacts : []) list.append(text("li", `${artifact.name}: ${artifact.status}; ${artifact.size} bytes; ${artifact.sha256 || "no hash"}`));
    ui.detailBody.append(overview, text("h3", "Sanitized artifacts"), list, text("h3", "Limitations"));
    const limits = document.createElement("ul"); for (const limitation of Array.isArray(data.limitations) ? data.limitations : []) limits.append(text("li", limitation)); ui.detailBody.append(limits);
  } catch (exception) { error(exception); } finally { setBusy(false); }
}
async function verify(id) { if (!validCollectionId(id) || busy) return; setBusy(true); status("Verifying collection integrity…"); try { const data = await call("verify", [id]); status("Verification passed", `${data.artifactCount} declared artifacts verified.`); } catch (exception) { error(exception); } finally { setBusy(false); } await refresh(); }
function confirm(title, message, id, callback) {
  ui.confirmTitle.textContent = title; ui.confirmMessage.textContent = message; ui.confirmLabel.textContent = `Type ${id} to continue`; ui.confirmation.value = ""; ui.dialog.showModal();
  const handler = () => { if (ui.dialog.returnValue === "confirm" && ui.confirmation.value === id) callback(); ui.dialog.removeEventListener("close", handler); };
  ui.dialog.addEventListener("close", handler);
}
function confirmExport(id) { if (validCollectionId(id)) confirm("Export verified collection", "Export copies redacted evidence to shared storage. Other apps may be able to access it.", id, () => exportCollection(id)); }
function confirmDelete(id) { if (validCollectionId(id)) confirm("Delete private collection", "This permanently deletes only the selected private collection. Shared-storage exports are not changed.", id, () => deleteCollection(id)); }
async function exportCollection(id) { if (busy) return; setBusy(true); status("Exporting verified collection…"); try { const data = await call("export", [id]); status("Export complete", data.path || "Fixed shared-storage destination."); await refresh(); } catch (exception) { error(exception); } finally { setBusy(false); } }
async function deleteCollection(id) { if (busy) return; setBusy(true); status("Deleting selected private collection…"); try { await call("delete", [id, `DELETE:${id}`]); ui.details.hidden = true; status("Private collection deleted"); await refresh(); } catch (exception) { error(exception); } finally { setBusy(false); } }
async function collect() { if (busy) return; setBusy(true); status("Collecting…", "The page will refresh after the shared collector finishes."); try { await call("collect"); status("Collection complete"); } catch (exception) { error(exception); } finally { setBusy(false); await refresh(); } }
async function initialize() {
  if (!supported()) { ui.unsupported.hidden = false; return; }
  ui.application.hidden = false;
  try { const info = await call("info"); ui.version.textContent = `Version ${info.moduleVersion || "unavailable"} · ${info.observerType || "root collector"}`; } catch (exception) { ui.version.textContent = messageFor(exception); }
  await refresh();
}
ui.collect.addEventListener("click", collect); ui.refresh.addEventListener("click", refresh); byId("close-detail").addEventListener("click", () => { ui.details.hidden = true; });
initialize();
