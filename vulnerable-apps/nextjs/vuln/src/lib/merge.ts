// VULN PROTO-001 (CWE-1321): recursive deep-merge that walks attacker-controlled
// keys (including "__proto__") straight onto the target, polluting
// Object.prototype. Used by the settings/import endpoint.
export function deepMerge(target: any, source: any): any {
  for (const key in source) {
    if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
      if (!target[key] || typeof target[key] !== "object") target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// NM-MERGE (near-miss, safe): copies only an explicit allow-list of keys. Present
// in BOTH variants; a scanner that flags this is producing a false positive.
const ALLOWED = ["theme", "timezone", "notifications"];
export function safeApplySettings(target: any, source: any): any {
  for (const key of ALLOWED) {
    if (Object.prototype.hasOwnProperty.call(source, key)) target[key] = source[key];
  }
  return target;
}
