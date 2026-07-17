import { spawn } from "./vendor/kernelsu.js";

const backend = "/data/adb/modules/androidtrustlab/scripts/webui_api.sh";
const maxBytes = 65536;
const allowed = new Set(["info", "status", "list", "inspect", "verify", "collect", "export", "delete"]);

export function supported() { return typeof globalThis.ksu === "object" && typeof globalThis.ksu.spawn === "function"; }
export function call(operation, args = []) {
  if (!supported()) return Promise.reject(new Error("The KernelSU spawn bridge is unavailable."));
  if (!allowed.has(operation) || !Array.isArray(args) || args.some((item) => typeof item !== "string" || item.length > 128)) return Promise.reject(new Error("Invalid management operation."));
  return new Promise((resolve, reject) => {
    let stdout = ""; let stderr = ""; let settled = false;
    const finish = (callback, value) => { if (!settled) { settled = true; callback(value); } };
    const child = spawn(backend, [operation, ...args], {});
    child.stdout.on("data", (chunk) => { stdout += String(chunk); if (stdout.length > maxBytes) finish(reject, new Error("Backend response exceeded the safety limit.")); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); if (stderr.length > maxBytes) stderr = stderr.slice(0, maxBytes); });
    child.on("error", () => finish(reject, new Error("KernelSU could not start the management backend.")));
    child.on("exit", () => {
      if (settled) return;
      if (stdout.length > maxBytes) return finish(reject, new Error("Backend response exceeded the safety limit."));
      let response;
      try { response = JSON.parse(stdout); } catch (error) { return finish(reject, new Error("The management backend returned an invalid response.")); }
      if (!response || response.apiVersion !== 1 || typeof response.ok !== "boolean") return finish(reject, new Error("The management backend returned an invalid response."));
      if (!response.ok) return finish(reject, new Error(response.error && response.error.message ? response.error.message : "The operation was refused."));
      return finish(resolve, response.data);
    });
  });
}
