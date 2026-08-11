/**
 * Adapters: raw scanner output -> findings/v1.
 *
 * Each adapter is deliberately dumb - it moves fields across and guesses a CWE
 * when the tool did not provide one. Nothing here knows about the answer key; if
 * an adapter needed to know, that would be the benchmark grading itself.
 */

import { coerceConfidence, coerceSeverity } from "../schema/findings.ts";
import { str } from "../schema/coerce.ts";
import type { Finding, FindingLocation, Severity } from "../schema/types.ts";
import {
  allCwes,
  clip,
  cweFromAny,
  guessCwe,
  markersIn,
  unxml,
  xmlAttr,
  xmlBlocks,
  xmlValue,
} from "./guess.ts";

export interface AdapterResult {
  tool: { name: string; version?: string; mode?: "dast" | "sast" | "hybrid" | "agent" };
  findings: Finding[];
  notes: string[];
}

// One spelling table for both paths: the adapters and the validator used to have
// their own, and disagreed (a scanner "warning" scored medium here, low there).
const sev = coerceSeverity;
const conf = coerceConfidence;

/**
 * SARIF's `security-severity` is a CVSS-style 0.0-10.0 string (the GitHub code
 * scanning convention, emitted by CodeQL, Semgrep and Snyk). It cannot go
 * through the shared alias table, where "3" means ZAP's high rather than CVSS's
 * low - which is why every real SARIF report used to arrive with no severity.
 */
function cvssSeverity(raw: unknown): Severity | undefined {
  const n = Number(str(raw));
  if (!Number.isFinite(n) || n < 0 || n > 10) return undefined;
  if (n >= 9) return "critical";
  if (n >= 7) return "high";
  if (n >= 4) return "medium";
  if (n > 0) return "low";
  return "info";
}

/**
 * Per-app proof markers from the answer key, so a marker in a scanner's evidence
 * becomes `evidence.markers` and reaches the matcher's `proof` tier. Without it
 * only the one shared seed marker is ever recognised.
 */
export interface AdapterOpts {
  markers?: readonly string[];
}

const httpLoc = (url: string | undefined, method?: string, param?: string): FindingLocation =>
  url ? { http: { url, method, param } } : {};

// ---------------------------------------------------------------- OWASP ZAP ---

/** ZAP's JSON report: { site: [ { alerts: [ { instances: [...] } ] } ] }. */
export function fromZap(doc: any, opts: AdapterOpts = {}): AdapterResult {
  const vocab = opts.markers ?? [];
  const findings: Finding[] = [];
  const notes: string[] = [];
  const sites = Array.isArray(doc?.site) ? doc.site : doc?.site ? [doc.site] : [];
  let n = 0;

  for (const site of sites) {
    for (const alert of site?.alerts ?? []) {
      const cwe =
        cweFromAny(alert.cweid, alert.cweId) ??
        guessCwe(alert.name, alert.alert, alert.desc, alert.solution);
      const instances = Array.isArray(alert.instances) && alert.instances.length
        ? alert.instances
        : [{ uri: site["@name"], method: undefined, param: undefined }];
      // ZAP repeats an alert per instance; each becomes its own finding, and the
      // scorer collapses the ones that land on the same bug.
      for (const inst of instances) {
        const evidenceText = [inst.evidence, inst.attack, inst.otherinfo].filter(Boolean).join("\n");
        findings.push({
          id: `zap-${alert.pluginid ?? alert.alertRef ?? "x"}-${++n}`,
          title: clip(alert.name ?? alert.alert, 160),
          cwe: cwe ?? undefined,
          severity: sev(alert.riskcode ?? alert.riskdesc ?? alert.risk),
          confidence: conf(alert.confidence),
          location: httpLoc(inst.uri, inst.method, inst.param || undefined),
          evidence: {
            markers: markersIn(vocab, evidenceText, inst.uri),
            request: clip(inst.attack),
            response_excerpt: clip(inst.evidence),
            note: clip(inst.otherinfo ?? alert.desc),
          },
          exploited: undefined,
        });
      }
    }
  }
  if (!findings.length) notes.push("no alerts found in the ZAP report");
  return { tool: { name: "zap", version: clip(doc?.["@version"], 40), mode: "dast" }, findings, notes };
}

// --------------------------------------------------------------------- SARIF --

/** SARIF 2.1.0 - Semgrep, CodeQL, Snyk, gitleaks, trivy and friends. */
export function fromSarif(doc: any, opts: AdapterOpts = {}): AdapterResult {
  const vocab = opts.markers ?? [];
  const findings: Finding[] = [];
  const notes: string[] = [];
  const runs = Array.isArray(doc?.runs) ? doc.runs : [];
  let toolName = "sarif";
  let toolVersion: string | undefined;
  let n = 0;

  for (const run of runs) {
    const driver = run?.tool?.driver ?? {};
    toolName = String(driver.name ?? toolName).toLowerCase();
    toolVersion = clip(driver.semanticVersion ?? driver.version, 40);

    const rules = new Map<string, any>();
    for (const r of driver.rules ?? []) if (r?.id) rules.set(String(r.id), r);

    for (const result of run?.results ?? []) {
      const rule = rules.get(String(result.ruleId ?? "")) ?? {};
      const tags = rule?.properties?.tags ?? [];
      const cwes = allCwes(
        rule?.properties?.cwe,
        tags,
        result?.properties?.cwe,
        rule?.id,
        result.ruleId,
      );
      const message = clip(result?.message?.text, 300);
      const cwe = cwes[0] ?? guessCwe(rule?.shortDescription?.text, message, String(result.ruleId ?? ""));

      const loc = result?.locations?.[0]?.physicalLocation ?? {};
      const uri = loc?.artifactLocation?.uri;
      const region = loc?.region ?? {};
      const location: FindingLocation = {};
      if (uri) {
        location.file = {
          path: String(uri).replace(/^file:\/\//, ""),
          line: region.startLine,
          end_line: region.endLine,
          snippet: clip(region?.snippet?.text, 200),
        };
      }
      // some SARIF producers put a URL in properties or in a webRequest
      const url = result?.webRequest?.target ?? result?.properties?.url ?? result?.properties?.uri;
      if (url) {
        location.http = { url: String(url), method: result?.webRequest?.method };
      }
      if (!location.file && !location.http) {
        notes.push(`skipped ${result.ruleId ?? "result"} - no location`);
        continue;
      }

      findings.push({
        id: `${toolName}-${result.ruleId ?? "rule"}-${++n}`.replace(/[^\w.@-]+/g, "_"),
        title: clip(rule?.shortDescription?.text ?? message, 160),
        cwe: cwe ?? undefined,
        cwes: cwes.length > 1 ? cwes.slice(1) : undefined,
        severity:
          cvssSeverity(
            result?.properties?.["security-severity"] ?? rule?.properties?.["security-severity"],
          ) ?? sev(result.level ?? rule?.defaultConfiguration?.level),
        confidence: conf(result?.properties?.confidence ?? rule?.properties?.confidence),
        location,
        evidence: { markers: markersIn(vocab, message, region?.snippet?.text), note: message },
      });
    }
  }
  if (!findings.length) notes.push("no results found in the SARIF document");
  return { tool: { name: toolName, version: toolVersion, mode: "sast" }, findings, notes };
}

// -------------------------------------------------------------------- nuclei --

/** nuclei -jsonl (one object per line) or -json (an array). */
export function fromNuclei(docs: any[], opts: AdapterOpts = {}): AdapterResult {
  const vocab = opts.markers ?? [];
  const findings: Finding[] = [];
  let n = 0;
  for (const d of docs) {
    const info = d?.info ?? {};
    const cwes = allCwes(info?.classification?.["cwe-id"], info?.tags, d?.["template-id"]);
    const cwe = cwes[0] ?? guessCwe(info.name, d?.["template-id"], info.description);
    const matched = String(d?.["matched-at"] ?? d?.host ?? "");
    const evidenceText = [d?.["extracted-results"]?.join?.(" "), d?.response].filter(Boolean).join("\n");

    // network templates match on host:port rather than a URL
    const location: FindingLocation = /^[a-z]+:\/\//i.test(matched)
      ? { http: { url: matched } }
      : (() => {
          const m = matched.match(/^([^:]+):(\d{1,5})$/);
          return m
            ? { net: { host: m[1], port: Number(m[2]), proto: String(d?.type ?? "tcp").toLowerCase(), state: "open" } }
            : matched
              ? { http: { url: matched } }
              : {};
        })();
    if (!location.http && !location.net) continue;

    findings.push({
      id: `nuclei-${d?.["template-id"] ?? "t"}-${++n}`.replace(/[^\w.@-]+/g, "_"),
      title: clip(info.name, 160),
      cwe: cwe ?? undefined,
      cwes: cwes.length > 1 ? cwes.slice(1) : undefined,
      severity: sev(info.severity),
      confidence: "firm",
      location,
      evidence: {
        markers: markersIn(vocab, evidenceText, matched),
        request: clip(d?.request),
        response_excerpt: clip(d?.response),
        note: clip(info.description),
      },
      exploited: Array.isArray(d?.["extracted-results"]) && d["extracted-results"].length > 0,
    });
  }
  return { tool: { name: "nuclei", mode: "dast" }, findings, notes: [] };
}

// ---------------------------------------------------------------------- Burp --

const PARAM_STOPWORDS = new Set([
  "is", "the", "a", "an", "of", "value", "this", "that", "each", "any", "request", "response",
  "url", "name", "same",
]);

/**
 * Which parameter did Burp mean? The request's own query string is the most
 * reliable source; the prose is a fallback and reads in both orders ("the q
 * parameter" and "parameter q").
 */
function burpParam(req: string | undefined, detail: string | undefined): string | undefined {
  const qs = req?.match(/^[A-Z]{3,7}\s+\S*?\?(\S*)/)?.[1];
  if (qs) {
    const names = [...new Set(qs.split("&").map((p) => p.split("=")[0]!).filter(Boolean))];
    if (names.length === 1) return names[0];
  }
  for (const re of [
    /\b([\w.\[\]-]+)\s+(?:request\s+)?parameter\b/i,
    /\b(?:parameter|param)\s+['"]?([\w.\[\]-]+)/i,
  ]) {
    const hit = detail?.match(re)?.[1];
    if (hit && !PARAM_STOPWORDS.has(hit.toLowerCase())) return hit;
  }
  return undefined;
}

/** Burp Suite's XML issue export. Parsed with regex - no XML dependency. */
export function fromBurp(text: string, opts: AdapterOpts = {}): AdapterResult {
  const vocab = opts.markers ?? [];
  const findings: Finding[] = [];
  let n = 0;
  for (const block of xmlBlocks(text, "issue")) {
    const name = xmlValue(block, "name");
    // <host ip="...">http://127.0.0.1:13311</host> - the body carries the port
    const host = xmlValue(block, "host") ?? xmlAttr(block, "host", "ip");
    const path = xmlValue(block, "path") ?? "/";
    const detail = xmlValue(block, "issueDetail") ?? xmlValue(block, "issueBackground");
    const req = unxml(xmlValue(block, "request"));
    const res = unxml(xmlValue(block, "response"));
    const cwe = cweFromAny(xmlValue(block, "vulnerabilityClassifications")) ?? guessCwe(name, detail);
    const method = req?.match(/^([A-Z]{3,7})\s+\S/)?.[1];
    const param = burpParam(req, detail);

    findings.push({
      id: `burp-${xmlValue(block, "serialNumber") ?? ++n}`,
      title: clip(name, 160),
      cwe: cwe ?? undefined,
      severity: sev(xmlValue(block, "severity")),
      confidence: conf(xmlValue(block, "confidence")),
      location: { http: { url: `${host ?? ""}${path}`, method, param } },
      evidence: {
        markers: markersIn(vocab, res, detail),
        request: clip(req),
        response_excerpt: clip(res),
        note: clip(detail),
      },
    });
  }
  return { tool: { name: "burp", mode: "dast" }, findings, notes: [] };
}

// ---------------------------------------------------------------------- nmap --

/** nmap -oX. Feeds the discovery track. */
export function fromNmap(text: string): AdapterResult {
  const findings: Finding[] = [];
  let n = 0;
  for (const hostBlock of xmlBlocks(text, "host")) {
    const addr = xmlAttr(hostBlock, "address", "addr");
    const name = hostBlock.match(/<hostname\b[^>]*\bname="([^"]*)"/i)?.[1];
    const host = name ?? addr;
    for (const m of hostBlock.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/gi)) {
      const attrs = m[1]!;
      const body = m[2]!;
      const proto = attrs.match(/protocol="([^"]*)"/i)?.[1] ?? "tcp";
      const port = Number(attrs.match(/portid="(\d+)"/i)?.[1] ?? 0);
      const state = body.match(/<state\b[^>]*\bstate="([^"]*)"/i)?.[1] ?? "unknown";
      const service = body.match(/<service\b[^>]*\bname="([^"]*)"/i)?.[1];
      const product = body.match(/<service\b[^>]*\bproduct="([^"]*)"/i)?.[1];
      const version = body.match(/<service\b[^>]*\bversion="([^"]*)"/i)?.[1];
      if (!port) continue;
      findings.push({
        id: `nmap-${host ?? "h"}-${port}-${proto}-${++n}`,
        title: `${state} ${proto}/${port}${service ? " " + service : ""}`,
        severity: "info",
        confidence: state === "open" ? "certain" : "tentative",
        location: {
          net: {
            host: host ?? undefined,
            port,
            proto,
            service,
            version: [product, version].filter(Boolean).join(" ") || undefined,
            state,
          },
        },
      });
    }
  }
  return { tool: { name: "nmap", mode: "dast" }, findings, notes: [] };
}
