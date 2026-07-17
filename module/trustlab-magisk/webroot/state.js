export const idPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/;
export function validCollectionId(value) { return typeof value === "string" && value !== "." && value !== ".." && idPattern.test(value); }
export function newestFirst(items) { return [...items].sort((a, b) => String(b.startedAt || "").localeCompare(String(a.startedAt || "")) || String(b.collectionId).localeCompare(String(a.collectionId))); }
export function formatTime(value) { const time = Date.parse(value); return Number.isNaN(time) ? "Unavailable" : new Date(time).toLocaleString(); }
export function messageFor(error) { return error && error.message ? String(error.message) : "The requested operation could not be completed."; }
