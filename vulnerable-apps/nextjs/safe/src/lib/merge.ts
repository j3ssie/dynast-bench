// FIXED PROTO-001: the deep-merge skips dangerous keys (__proto__, constructor,
// prototype), so a malicious body can no longer reach Object.prototype.
const DANGEROUS = new Set(["__proto__", "constructor", "prototype"]);

export function deepMerge(target: any, source: any): any {
  for (const key in source) {
    if (DANGEROUS.has(key) || !Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
      if (!target[key] || typeof target[key] !== "object") target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// NM-MERGE (near-miss, safe): allow-list copy. Present in both variants.
const ALLOWED = ["theme", "timezone", "notifications"];
export function safeApplySettings(target: any, source: any): any {
  for (const key of ALLOWED) {
    if (Object.prototype.hasOwnProperty.call(source, key)) target[key] = source[key];
  }
  return target;
}
