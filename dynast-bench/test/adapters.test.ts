/**
 * Native scanner formats -> findings/v1.
 *
 * `dynast-bench score` reads ZAP, SARIF, nuclei, Burp and nmap output directly,
 * so a regression in an adapter silently mis-scores every tool that emits that
 * format - and unlike a scorer bug it would not show up in any answer-key test.
 * Each case below is a hand-written excerpt of what the real tool writes.
 */

import { describe, expect, test } from "bun:test";

import { detectFormat, normalizeText } from "../src/normalize/index.ts";

const MARKER = "GLOBEX-CONFIDENTIAL-MARKER-7f3a";
const norm = (text: string, format?: any) =>
  normalizeText(text, { format, markers: [MARKER] });

describe("zap", () => {
  const report = JSON.stringify({
    "@version": "2.15.0",
    site: [
      {
        "@name": "http://127.0.0.1:13311",
        alerts: [
          {
            pluginid: "40018",
            name: "SQL Injection",
            riskcode: "3",
            confidence: "2",
            cweid: "89",
            desc: "SQL injection may be possible.",
            instances: [
              {
                uri: "http://127.0.0.1:13311/api/posts/search?q=x",
                method: "GET",
                param: "q",
                attack: "' OR '1'='1",
                evidence: `title: ${MARKER}`,
              },
              { uri: "http://127.0.0.1:13311/api/posts/search?q=y", method: "GET", param: "q" },
            ],
          },
        ],
      },
    ],
  });

  test("one finding per instance, with cwe, param and risk", () => {
    const r = norm(report);
    expect(r.file.findings).toHaveLength(2);
    const f = r.file.findings[0]!;
    expect(f.cwe).toBe("CWE-89");
    expect(f.severity).toBe("high"); // riskcode 3
    expect(f.location.http?.param).toBe("q");
    expect(f.location.http?.method).toBe("GET");
  });

  test("a proof marker in the evidence reaches the matcher", () => {
    expect(norm(report).file.findings[0]!.evidence?.markers).toContain(MARKER);
  });

  test("detected without being told the format", () => {
    expect(detectFormat(report).format).toBe("zap");
  });
});

describe("sarif", () => {
  const report = JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Semgrep",
            semanticVersion: "1.2.3",
            rules: [
              {
                id: "javascript.express.sqli",
                shortDescription: { text: "SQL string concatenation" },
                properties: { tags: ["CWE-89"], "security-severity": "8.8" },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "javascript.express.sqli",
            message: { text: "User input flows into a raw query" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "vuln/src/app/api/posts/search/route.ts" },
                  region: { startLine: 21, endLine: 24, snippet: { text: "db.query(`...${q}`)" } },
                },
              },
            ],
          },
          { ruleId: "no.location.rule", message: { text: "nowhere" } },
        ],
      },
    ],
  });

  test("file, line range and cwe survive", () => {
    const f = norm(report).file.findings[0]!;
    expect(f.location.file?.path).toBe("vuln/src/app/api/posts/search/route.ts");
    expect(f.location.file?.line).toBe(21);
    expect(f.location.file?.end_line).toBe(24);
    expect(f.cwe).toBe("CWE-89");
    expect(f.severity).toBe("high"); // security-severity 8.8
  });

  test("a result with no location is dropped, not guessed at", () => {
    const r = norm(report);
    expect(r.file.findings).toHaveLength(1);
    expect([...r.warnings.map((w) => w.msg), ...r.notes].some((m) => m.includes("no location"))).toBe(true);
  });

  test("the driver names the tool", () => {
    expect(norm(report).file.tool.name).toBe("semgrep");
    expect(norm(report).file.tool.mode).toBe("sast");
  });

  test("detected without being told the format", () => {
    expect(detectFormat(report).format).toBe("sarif");
  });
});

describe("nuclei", () => {
  const jsonl = [
    JSON.stringify({
      "template-id": "exposed-env",
      info: { name: "Exposed .env", severity: "high", classification: { "cwe-id": ["CWE-200"] } },
      "matched-at": "http://127.0.0.1:13311/.env",
      "extracted-results": [MARKER],
    }),
    JSON.stringify({
      "template-id": "open-redis",
      type: "tcp",
      info: { name: "Open Redis", severity: "medium" },
      "matched-at": "cache-1:6379",
    }),
  ].join("\n");

  test("a URL match becomes an http anchor", () => {
    const f = norm(jsonl).file.findings[0]!;
    expect(f.location.http?.url).toBe("http://127.0.0.1:13311/.env");
    expect(f.cwe).toBe("CWE-200");
    expect(f.severity).toBe("high");
  });

  test("a host:port match becomes a net anchor, not a bogus URL", () => {
    const f = norm(jsonl).file.findings[1]!;
    expect(f.location.net).toEqual({ host: "cache-1", port: 6379, proto: "tcp", state: "open" });
    expect(f.location.http).toBeUndefined();
  });

  test("extracted results count as proof of exploitation", () => {
    const f = norm(jsonl).file.findings[0]!;
    expect(f.exploited).toBe(true);
    expect(f.evidence?.markers).toContain(MARKER);
  });

  test("detected without being told the format", () => {
    expect(detectFormat(jsonl).format).toBe("nuclei");
  });
});

describe("burp", () => {
  const xml = `<?xml version="1.0"?>
<issues burpVersion="2024.1">
  <issue>
    <serialNumber>123456</serialNumber>
    <name><![CDATA[SQL injection]]></name>
    <host ip="127.0.0.1">http://127.0.0.1:13311</host>
    <path><![CDATA[/api/posts/search]]></path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueDetail><![CDATA[The q parameter appears to be vulnerable.]]></issueDetail>
    <request base64="false"><![CDATA[GET /api/posts/search?q=%27 HTTP/1.1]]></request>
    <response base64="false"><![CDATA[HTTP/1.1 200 OK

${MARKER}]]></response>
  </issue>
</issues>`;

  test("host, path, method and severity are recovered", () => {
    const f = norm(xml).file.findings[0]!;
    expect(f.location.http?.url).toBe("http://127.0.0.1:13311/api/posts/search");
    expect(f.location.http?.method).toBe("GET");
    expect(f.severity).toBe("high");
    expect(f.confidence).toBe("certain");
  });

  test("the injected parameter is read off the request, not the prose", () => {
    expect(norm(xml).file.findings[0]!.location.http?.param).toBe("q");
  });

  test("a marker in the response body is picked up", () => {
    expect(norm(xml).file.findings[0]!.evidence?.markers).toContain(MARKER);
  });

  test("detected without being told the format", () => {
    expect(detectFormat(xml).format).toBe("burp");
  });
});

describe("nmap", () => {
  const xml = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="edge-proxy"/></hostnames>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis key-value store" version="7.2.4"/>
      </port>
      <port protocol="tcp" portid="9000">
        <state state="closed"/>
        <service name="cslistener"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

  test("each port becomes a net finding with service and version", () => {
    const fs = norm(xml).file.findings;
    expect(fs).toHaveLength(2);
    expect(fs[0]!.location.net).toEqual({
      host: "edge-proxy",
      port: 6379,
      proto: "tcp",
      service: "redis",
      version: "Redis key-value store 7.2.4",
      state: "open",
    });
  });

  test("a closed port is reported but not as certain", () => {
    const fs = norm(xml).file.findings;
    expect(fs[1]!.location.net?.state).toBe("closed");
    expect(fs[1]!.confidence).toBe("tentative");
    expect(fs[0]!.confidence).toBe("certain");
  });

  test("detected without being told the format", () => {
    expect(detectFormat(xml).format).toBe("nmap");
  });
});

describe("malformed input fails loudly", () => {
  test("truncated JSON is an error, not an empty clean run", () => {
    const r = norm(`{"site": [{"alerts": [`, "zap");
    expect(r.errors.length).toBeGreaterThan(0);
  });

  test("XML with no issues yields no findings rather than throwing", () => {
    const r = norm(`<issues></issues>`, "burp");
    expect(r.file.findings).toHaveLength(0);
  });

  test("an unrecognisable document is reported as such", () => {
    expect(detectFormat("hello, i am not a scan report").format).toBe("unknown");
  });
});
