#!/usr/bin/env node

// ../lib/checks/providers/domain.ts
import { connect as tlsConnect } from "node:tls";

// ../lib/checks/types.ts
var pass = (observed, evidence) => ({
  status: "pass",
  observed,
  evidence
});
var fail = (observed, evidence) => ({
  status: "fail",
  observed,
  evidence
});
var unknown = (errorScope, observed = {}) => ({
  status: "unknown",
  observed,
  evidence: null,
  errorScope
});
async function guarded(scope, body) {
  try {
    return await body();
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    if (message === "edge.challenge") return unknown("edge.challenge");
    if (message.startsWith("scope:")) return unknown(message.slice("scope:".length));
    return unknown(scope);
  }
}
function shapeMismatch(items, pick) {
  return items.length > 0 && items.every((item) => pick(item).every((v) => v === void 0));
}

// ../lib/checks/http.ts
var READ_ONLY_POST = [
  // Token exchanges: a refresh token or a client credential for a short-lived access token.
  /^https:\/\/oauth2\.googleapis\.com\/token$/,
  /^https:\/\/login\.microsoftonline\.com\/[^/]+\/oauth2\/v2\.0\/token$/,
  /^https:\/\/api\.supabase\.com\/v1\/oauth\/token$/,
  // Auth0 machine-to-machine application: client credentials for a Management API token.
  /^https:\/\/[a-z0-9-]+(\.(us|eu|au|jp|uk|ca))?\.auth0\.com\/oauth\/token$/,
  // MongoDB Atlas service account: client credentials for a one-hour token.
  /^https:\/\/cloud\.mongodb\.com\/api\/oauth\/token$/,
  // Supabase's read-only SQL endpoint: the server refuses anything but a read.
  /^https:\/\/api\.supabase\.com\/v1\/projects\/[^/]+\/database\/query\/read-only$/,
  // Google names two reads as POST because the request carries options in a
  // body. `:getIamPolicy` returns a policy and cannot set one — that is
  // `:setIamPolicy`, which no pattern here admits.
  /^https:\/\/cloudresourcemanager\.googleapis\.com\/v1\/projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]:getIamPolicy$/,
  // `:testIamPermissions` answers "which of these permissions does this caller
  // hold", and holds nothing itself. It is how the connector proves its own
  // credential cannot write, so refusing it here would refuse the proof.
  /^https:\/\/cloudresourcemanager\.googleapis\.com\/v1\/projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]:testIamPermissions$/,
  // Notion names search a POST because the request carries its options in a
  // body. It reads pages and cannot create one, which is /v1/pages.
  /^https:\/\/api\.notion\.com\/v1\/search$/,
  // Jamf Pro API client credentials for a short-lived token.
  /^https:\/\/[a-z0-9][a-z0-9-]{1,60}\.jamfcloud\.com\/api\/oauth\/token$/,
  // 1Password's Events API reads a log through POST, because the body carries
  // a cursor: a log is read forwards. There is no endpoint that writes one.
  /^https:\/\/events\.(1password\.(com|ca|eu)|ent\.1password\.com)\/api\/v2\/(signinattempts|auditevents)$/,
  // Bitwarden organisation API key for a bearer token.
  /^https:\/\/identity\.bitwarden\.(com|eu)\/connect\/token$/,
  // Aikido OAuth client credentials for a short-lived token.
  /^https:\/\/app\.aikido\.dev\/api\/oauth\/token$/,
  // UptimeRobot's API is POST-only; these two methods read.
  /^https:\/\/api\.uptimerobot\.com\/v2\/(getMonitors|getAccountDetails)$/
];
var GRAPHQL_READ = [/^https:\/\/api\.fly\.io\/graphql$/, /^https:\/\/backboard\.railway\.com\/graphql\/v2$/, /^https:\/\/api\.linear\.app\/graphql$/];
function isReadQueryBody(body) {
  if (typeof body !== "string") return false;
  try {
    const parsed = JSON.parse(body);
    const q = parsed.query;
    if (typeof q !== "string" || !/^\s*(query\b|\{)/.test(q)) return false;
    if (/\b(mutation|subscription)\b/i.test(q)) return false;
    if (parsed.operationName != null) return false;
    return true;
  } catch {
    return false;
  }
}
var AWS_QUERY_HOST = /^https:\/\/(iam|sts)\.amazonaws\.com\/$|^https:\/\/(ec2|rds)\.[a-z0-9-]+\.amazonaws\.com\/$/;
var AWS_READ_ACTIONS = /* @__PURE__ */ new Set([
  // STS: who are we, under what role.
  "GetCallerIdentity",
  // IAM: the account's own posture, its users, and their credentials.
  "GetAccountSummary",
  "GetAccountPasswordPolicy",
  "ListUsers",
  "ListMFADevices",
  "ListAccessKeys",
  "ListAccountAliases",
  "ListAttachedUserPolicies",
  "GetAccessKeyLastUsed",
  // EC2: the network and the disks.
  "DescribeSecurityGroups",
  "DescribeVpcs",
  "DescribeFlowLogs",
  "DescribeInstances",
  "DescribeVolumes",
  "DescribeRegions",
  "DescribeAddresses",
  "DescribeSnapshots",
  "DescribeImages",
  "GetEbsEncryptionByDefault",
  // RDS: the databases.
  "DescribeDBInstances",
  "DescribeDBSnapshots"
]);
var AWS_JSON_HOST = /^https:\/\/(cloudtrail|kms|guardduty|config)\.[a-z0-9-]+\.amazonaws\.com\//;
var AWS_READ_TARGETS = /* @__PURE__ */ new Set([
  "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails",
  "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetTrailStatus",
  "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetEventSelectors",
  "TrentService.ListKeys",
  "TrentService.DescribeKey",
  "TrentService.GetKeyRotationStatus",
  "StarlingDoveService.DescribeConfigurationRecorders",
  "StarlingDoveService.DescribeConfigurationRecorderStatus"
]);
function awsAction(body) {
  if (typeof body !== "string") return null;
  const action = new URLSearchParams(body).get("Action");
  return action && /^[A-Za-z]{1,64}$/.test(action) ? action : null;
}
function headerValue(headers, name) {
  if (!headers) return null;
  const wanted = name.toLowerCase();
  if (headers instanceof Headers) return headers.get(wanted);
  if (Array.isArray(headers)) {
    for (const [k, v] of headers) if (k.toLowerCase() === wanted) return v;
    return null;
  }
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === wanted) return String(v);
  return null;
}
var WriteRefused = class extends Error {
  constructor(method, url) {
    super(`read-only: ${method} ${url} refused`);
    this.name = "WriteRefused";
  }
};
function isReadOnlyRequest(url, method, body, headers) {
  const m = method.toUpperCase();
  if (m === "GET" || m === "HEAD") return true;
  if (m !== "POST") return false;
  if (READ_ONLY_POST.some((re) => re.test(url))) return true;
  if (GRAPHQL_READ.some((re) => re.test(url)) && isReadQueryBody(body)) return true;
  if (AWS_QUERY_HOST.test(url)) {
    const action = awsAction(body);
    return action !== null && AWS_READ_ACTIONS.has(action);
  }
  if (AWS_JSON_HOST.test(url)) {
    const target = headerValue(headers, "x-amz-target");
    return target !== null && AWS_READ_TARGETS.has(target);
  }
  return false;
}
var readOnlyFetch = (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const method = init?.method ?? (typeof input === "object" && !(input instanceof URL) ? input.method : "GET") ?? "GET";
  if (!isReadOnlyRequest(url, method, init?.body, init?.headers)) {
    return Promise.reject(new WriteRefused(method.toUpperCase(), url));
  }
  return fetch(input, init);
};

// ../lib/checks/dns-tags.ts
function dnsTag(record, tag) {
  if (!record) return null;
  const re = new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;]*)`, "i");
  const raw = re.exec(record)?.[1];
  return raw === void 0 ? null : raw.trim();
}
function dmarcPolicy(record) {
  const v = dnsTag(record, "p")?.toLowerCase();
  return v === "none" || v === "quarantine" || v === "reject" ? v : null;
}
function dmarcRua(record) {
  const v = dnsTag(record, "rua");
  if (!v) return null;
  const first = v.split(",")[0]?.trim() ?? "";
  const m = /^mailto:(.+)$/i.exec(first);
  return m ? m[1].trim() : null;
}

// ../lib/checks/providers/domain.ts
var TIMEOUT_MS = 1e4;
var UA = "snoopios-check/1 (+https://snoopios.com)";
var EdgeChallenge = class extends Error {
  constructor() {
    super("edge.challenge");
  }
};
function challenged(res) {
  return res.headers.get("cf-mitigated") === "challenge" || res.status === 403 && /challenge-platform|cf-chl/i.test(res.headers.get("cf-chl-bypass") ?? "");
}
var REFUSED_STATUS = /* @__PURE__ */ new Set([401, 403, 407, 429, 451]);
var EdgeRefused = class extends Error {
  constructor(status) {
    super(`scope:edge.refused.${status}`);
  }
};
function rejectChallenge(res) {
  if (challenged(res)) throw new EdgeChallenge();
  if (REFUSED_STATUS.has(res.status)) throw new EdgeRefused(res.status);
  return res;
}
async function head(ctx, url, redirect = "manual") {
  const f = ctx.fetch ?? readOnlyFetch;
  const res = rejectChallenge(
    await f(url, {
      method: "GET",
      redirect,
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "user-agent": UA }
    })
  );
  const headers = {};
  res.headers.forEach((v, k) => {
    headers[k] = v;
  });
  return { status: res.status, headers, url: res.url };
}
async function dohTxt(ctx, name, type = "TXT") {
  const f = ctx.fetch ?? readOnlyFetch;
  const res = await f(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  const json = await res.json();
  return json;
}
function realTls(host) {
  return new Promise((resolve2, reject) => {
    const socket = tlsConnect(
      // Deliberate: this connection exists to READ the certificate and judge
      // it (expiry, issuer, protocol). Verifying it first would make an expired
      // or self-signed certificate unreadable, which is the finding. Nothing is
      // sent over this socket. (Semgrep bypass-tls-verification, triaged
      // 12 Oct 2026 as by design.)
      // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
      { host, port: 443, servername: host, rejectUnauthorized: false, timeout: TIMEOUT_MS },
      () => {
        const cert = socket.getPeerCertificate();
        resolve2({
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          validTo: cert?.valid_to ?? null,
          issuer: cert?.issuer ? Object.values(cert.issuer).join(", ") : null
        });
        socket.end();
      }
    );
    socket.on("error", reject);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("timeout"));
    });
  });
}
var headersCsp = {
  code: "domain.headers.csp",
  provider: "domain",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.6", "ce:secure-config", "iso:8.26", "iso:8.9"],
  run: (ctx) => guarded("http.get", async () => {
    const r = await head(ctx, `https://${ctx.host}/`, "follow");
    const csp = r.headers["content-security-policy"] ?? null;
    const scriptSrc = /script-src\s+([^;]+)/i.exec(csp ?? "")?.[1] ?? /default-src\s+([^;]+)/i.exec(csp ?? "")?.[1] ?? "";
    const nonceOrHash = /'nonce-|'sha(256|384|512)-|'strict-dynamic'/i.test(scriptSrc);
    const observed = {
      present: Boolean(csp),
      objectSrcNone: /object-src\s+'none'/i.test(csp ?? ""),
      baseUriSelf: /base-uri\s+'self'/i.test(csp ?? ""),
      frameAncestors: /frame-ancestors/i.test(csp ?? ""),
      // Inline script and eval are only excused by a nonce, a hash or strict-dynamic.
      scriptUnsafeInline: /'unsafe-inline'/i.test(scriptSrc) && !nonceOrHash,
      scriptUnsafeEval: /'unsafe-eval'/i.test(scriptSrc),
      scriptWildcard: /(^|\s)\*(\s|$)/.test(scriptSrc)
    };
    const ok = observed.present && observed.objectSrcNone && observed.baseUriSelf && observed.frameAncestors && !observed.scriptUnsafeInline && !observed.scriptUnsafeEval && !observed.scriptWildcard;
    return ok ? pass(observed, r) : fail(observed, r);
  })
};
var headersHsts = {
  code: "domain.headers.hsts",
  provider: "domain",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("http.get", async () => {
    const r = await head(ctx, `https://${ctx.host}/`, "follow");
    const hsts = r.headers["strict-transport-security"] ?? null;
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts ?? "")?.[1] ?? 0);
    const observed = {
      present: Boolean(hsts),
      maxAge,
      includeSubDomains: /includeSubDomains/i.test(hsts ?? ""),
      preload: /preload/i.test(hsts ?? "")
    };
    const ok = observed.present && maxAge >= 31536e3 && observed.includeSubDomains;
    return ok ? pass(observed, r) : fail(observed, r);
  })
};
var headersBasics = {
  code: "domain.headers.basics",
  provider: "domain",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.6", "ce:secure-config", "iso:8.9"],
  run: (ctx) => guarded("http.get", async () => {
    const r = await head(ctx, `https://${ctx.host}/`, "follow");
    const h = r.headers;
    const csp = h["content-security-policy"] ?? "";
    const observed = {
      nosniff: (h["x-content-type-options"] ?? "").toLowerCase() === "nosniff",
      framing: /frame-ancestors/i.test(csp) || Boolean(h["x-frame-options"]),
      referrerPolicy: Boolean(h["referrer-policy"]),
      serverHeaderLeaks: /\d/.test(h["server"] ?? "") || Boolean(h["x-powered-by"])
    };
    const ok = observed.nosniff && observed.framing && observed.referrerPolicy && !observed.serverHeaderLeaks;
    return ok ? pass(observed, r) : fail(observed, r);
  })
};
var httpsRedirect = {
  code: "domain.https.redirect",
  provider: "domain",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24", "iso:8.20"],
  run: (ctx) => guarded("http.get", async () => {
    const r = await head(ctx, `http://${ctx.host}/`, "manual");
    const location = r.headers["location"] ?? "";
    const observed = {
      status: r.status,
      redirectsToHttps: r.status >= 300 && r.status < 400 && location.startsWith("https://")
    };
    return observed.redirectsToHttps ? pass(observed, r) : fail(observed, r);
  })
};
var hstsPreload = {
  code: "domain.hsts.preload",
  provider: "domain",
  version: 1,
  severity: "low",
  maps: ["ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("hstspreload.api", async () => {
    const f = ctx.fetch ?? readOnlyFetch;
    const res = await f(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(ctx.host)}`, {
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    const json = await res.json();
    const observed = { status: json.status, preloadedDomain: json.preloadedDomain ?? null };
    if (json.status === "preloaded") return pass(observed, json);
    return fail(observed, json);
  })
};
function txtRecords(answer) {
  return (answer ?? []).map((a) => a.data.replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
}
var dnsSpf = {
  code: "domain.dns.spf",
  provider: "domain",
  version: 1,
  severity: "medium",
  maps: ["ce:secure-config", "iso:8.20", "soc2:CC6.6"],
  run: (ctx) => guarded("doh.txt", async () => {
    const json = await dohTxt(ctx, ctx.host);
    const spf = txtRecords(json.Answer).filter((t) => t.toLowerCase().startsWith("v=spf1"));
    const observed = { count: spf.length, record: spf[0] ?? null, hardOrSoftFail: /[-~]all\b/.test(spf[0] ?? "") };
    return spf.length === 1 && observed.hardOrSoftFail ? pass(observed, json) : fail(observed, json);
  })
};
var dnsDmarc = {
  code: "domain.dns.dmarc",
  provider: "domain",
  version: 1,
  severity: "medium",
  maps: ["ce:secure-config", "iso:8.20", "soc2:CC6.6"],
  run: (ctx) => guarded("doh.txt", async () => {
    const json = await dohTxt(ctx, `_dmarc.${ctx.host}`);
    const rec = txtRecords(json.Answer).find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
    const policy = dmarcPolicy(rec);
    const observed = { present: Boolean(rec), policy };
    return policy === "quarantine" || policy === "reject" ? pass(observed, json) : fail(observed, json);
  })
};
var dnsCaa = {
  code: "domain.dns.caa",
  provider: "domain",
  version: 1,
  severity: "low",
  maps: ["ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("doh.caa", async () => {
    const labels = ctx.host.split(".");
    let json = null;
    let found = [];
    for (let i = 0; i < labels.length - 1; i++) {
      json = await dohTxt(ctx, labels.slice(i).join("."), "CAA");
      found = (json.Answer ?? []).filter((a) => a.type === 257).map((a) => a.data);
      if (found.length) break;
    }
    const observed = { count: found.length, records: found };
    return found.length > 0 ? pass(observed, json) : fail(observed, json);
  })
};
var tlsModern = {
  code: "domain.tls.modern",
  provider: "domain",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("tls.handshake", async () => {
    const facts = await (ctx.tls ?? realTls)(ctx.host);
    const validTo = facts.validTo ? new Date(facts.validTo) : null;
    const daysLeft = validTo ? Math.floor((validTo.getTime() - Date.now()) / 864e5) : null;
    const observed = {
      protocol: facts.protocol,
      cipher: facts.cipher,
      certDaysLeft: daysLeft,
      issuer: facts.issuer
    };
    const modern = facts.protocol === "TLSv1.3" || facts.protocol === "TLSv1.2";
    const ok = modern && daysLeft !== null && daysLeft > 14;
    return ok ? pass(observed, facts) : fail(observed, facts);
  })
};
var securityTxt = {
  code: "domain.securitytxt",
  provider: "domain",
  version: 1,
  severity: "low",
  maps: ["iso:5.24", "iso:8.8", "soc2:CC7.3"],
  run: (ctx) => guarded("http.get", async () => {
    const f = ctx.fetch ?? readOnlyFetch;
    const res = rejectChallenge(
      await f(`https://${ctx.host}/.well-known/security.txt`, {
        redirect: "follow",
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { "user-agent": UA }
      })
    );
    const text2 = res.ok ? await res.text() : "";
    const contact = /^Contact:/im.test(text2);
    const expires = /^Expires:\s*(.+)$/im.exec(text2)?.[1] ?? null;
    const expired = expires ? new Date(expires).getTime() < Date.now() : true;
    const observed = { status: res.status, contact, expires, expired };
    const ok = res.ok && contact && !expired;
    return ok ? pass(observed, { status: res.status, body: text2.slice(0, 2e3) }) : fail(observed, { status: res.status, body: text2.slice(0, 2e3) });
  })
};
var privacyPage = {
  code: "domain.privacy.page",
  provider: "domain",
  version: 1,
  severity: "medium",
  maps: ["gdpr:art13", "iso:5.34", "soc2:CC2.3"],
  run: (ctx) => guarded("http.get", async () => {
    const f = ctx.fetch ?? readOnlyFetch;
    const candidates = ["/privacy", "/privacy-policy", "/legal/privacy"];
    let found = null;
    for (const p of candidates) {
      const res = rejectChallenge(await f(`https://${ctx.host}${p}`, { redirect: "follow", signal: AbortSignal.timeout(TIMEOUT_MS), headers: { "user-agent": UA } }));
      if (res.ok) {
        found = { path: p, status: res.status, body: (await res.text()).slice(0, 2e5) };
        break;
      }
    }
    if (!found) return fail({ found: false }, null);
    const text2 = found.body.replace(/<[^>]+>/g, " ");
    const observed = {
      found: true,
      path: found.path,
      namesController: /\b(controller|Ltd|Limited|LLC|Inc\.?|GmbH|company)\b/i.test(text2),
      hasDate: /\b(20\d\d)\b/.test(text2) && /(updated|effective|last revised)/i.test(text2),
      pendingMarker: /\[(DATE PENDING|PENDING|TODO)[^\]]*\]/i.test(text2)
    };
    const ok = observed.namesController && observed.hasDate && !observed.pendingMarker;
    return ok ? pass(observed, { path: found.path, status: found.status }) : fail(observed, { path: found.path, status: found.status });
  })
};
var DOMAIN_CHECKS = [
  httpsRedirect,
  headersHsts,
  headersCsp,
  headersBasics,
  tlsModern,
  hstsPreload,
  dnsSpf,
  dnsDmarc,
  dnsCaa,
  securityTxt,
  privacyPage
];
async function runDomainChecks(ctx) {
  const out = [];
  for (const c of DOMAIN_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/email.ts
var ESP_DEFAULTS = {
  resend: { selector: "resend", returnPath: "send", spfInclude: "amazonses.com" },
  postmark: { selector: "pm", returnPath: "pm-bounces", spfInclude: "spf.mtasv.net" },
  mailgun: { selector: "smtp", returnPath: "mg", spfInclude: "mailgun.org" },
  ses: { spfInclude: "amazonses.com" },
  other: {}
};
var TIMEOUT_MS2 = 1e4;
async function doh(ctx, name, type = "TXT") {
  const f = ctx.fetch ?? readOnlyFetch;
  const res = await f(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(TIMEOUT_MS2)
  });
  return await res.json();
}
function txt(answer) {
  return (answer ?? []).filter((a) => a.type === 16).map((a) => a.data.replace(/"\s+"/g, "").replace(/^"|"$/g, ""));
}
function mxHosts(answer) {
  return (answer ?? []).filter((a) => a.type === 15).map((a) => (a.data.trim().split(/\s+/).pop() ?? "").replace(/\.$/, "").toLowerCase()).filter(Boolean);
}
function parseStsPolicy(text2) {
  let version = null;
  let mode = null;
  let maxAge = null;
  const mx = [];
  for (const line of text2.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9_-]+)\s*:\s*(.*?)\s*$/.exec(line);
    if (!m) continue;
    const [, rawKey, value] = m;
    const key = rawKey.toLowerCase();
    if (key === "version") version ??= value;
    else if (key === "mode") mode ??= value.toLowerCase();
    else if (key === "mx") mx.push(value.replace(/\.$/, "").toLowerCase());
    else if (key === "max_age" && /^\d+$/.test(value)) maxAge ??= Number(value);
  }
  return { version, mode, mx, maxAge };
}
function mxCoveredBy(host, pattern) {
  const h = host.replace(/\.$/, "").toLowerCase();
  const p = pattern.replace(/\.$/, "").toLowerCase();
  if (!p.startsWith("*.")) return h === p;
  const suffix = p.slice(1);
  if (!h.endsWith(suffix)) return false;
  const label4 = h.slice(0, h.length - suffix.length);
  return label4.length > 0 && !label4.includes(".");
}
function selectorFor(ctx) {
  return ctx.selector?.trim() || ESP_DEFAULTS[ctx.esp].selector || null;
}
function returnPathHost(ctx) {
  const sub = ctx.returnPath?.trim() || ESP_DEFAULTS[ctx.esp].returnPath;
  return sub ? `${sub}.${ctx.domain}` : ctx.domain;
}
var dkimPresent = {
  code: "email.dkim.present",
  provider: "email",
  version: 1,
  severity: "high",
  maps: ["ce:secure-config", "iso:8.24", "soc2:CC6.6"],
  run: (ctx) => guarded("doh.dkim", async () => {
    const selector = selectorFor(ctx);
    if (!selector) return unknown("dkim.selector", { selector: null });
    const json = await doh(ctx, `${selector}._domainkey.${ctx.domain}`);
    const rec = txt(json.Answer).find((t) => dnsTag(t, "p") !== null) ?? null;
    const key = (dnsTag(rec, "p") ?? "").replace(/\s+/g, "");
    let bits = null;
    if (key) {
      const bytes = Buffer.from(key, "base64").length;
      bits = bytes >= 290 ? 2048 : bytes >= 155 ? 1024 : bytes > 0 ? 512 : null;
    }
    const observed = { selector, present: Boolean(rec), revoked: Boolean(rec) && key === "", keyBits: bits };
    return rec && key && (bits ?? 0) >= 1024 ? pass(observed, json) : fail(observed, json);
  })
};
var spfReturnPath = {
  code: "email.spf.returnpath",
  provider: "email",
  version: 1,
  severity: "high",
  maps: ["ce:secure-config", "iso:8.20", "soc2:CC6.6"],
  run: (ctx) => guarded("doh.spf", async () => {
    const host = returnPathHost(ctx);
    const json = await doh(ctx, host);
    const spf = txt(json.Answer).filter((t) => t.toLowerCase().startsWith("v=spf1"));
    const include = ESP_DEFAULTS[ctx.esp].spfInclude;
    const rec = spf[0] ?? "";
    const observed = {
      host,
      count: spf.length,
      record: rec || null,
      includesProvider: include ? rec.toLowerCase().includes(`include:${include}`) : /include:/.test(rec),
      hardOrSoftFail: /[-~]all\b/.test(rec)
    };
    return spf.length === 1 && observed.includesProvider && observed.hardOrSoftFail ? pass(observed, json) : fail(observed, json);
  })
};
async function dmarc(ctx) {
  const json = await doh(ctx, `_dmarc.${ctx.domain}`);
  const rec = txt(json.Answer).find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
  const policy = dmarcPolicy(rec);
  const rua = dmarcRua(rec);
  return { json, rec, policy, rua };
}
var dmarcEnforced = {
  code: "email.dmarc.enforced",
  provider: "email",
  version: 1,
  severity: "high",
  maps: ["ce:secure-config", "iso:8.20", "soc2:CC6.6"],
  run: (ctx) => guarded("doh.dmarc", async () => {
    const d = await dmarc(ctx);
    const observed = { present: Boolean(d.rec), policy: d.policy };
    return d.policy === "quarantine" || d.policy === "reject" ? pass(observed, d.json) : fail(observed, d.json);
  })
};
var dmarcReporting = {
  code: "email.dmarc.reporting",
  provider: "email",
  version: 1,
  severity: "low",
  maps: ["iso:8.16"],
  run: (ctx) => guarded("doh.dmarc", async () => {
    const d = await dmarc(ctx);
    const observed = { present: Boolean(d.rec), reportsTo: d.rua ? d.rua.replace(/^[^@]+@/, "\u2026@") : null };
    return d.rua ? pass(observed, d.json) : fail(observed, d.json);
  })
};
var MIN_MAX_AGE = 86400;
var MAX_MAX_AGE = 31557600;
async function stsPolicy(ctx) {
  const json = await doh(ctx, `_mta-sts.${ctx.domain}`);
  const rec = txt(json.Answer).find((t) => t.toLowerCase().startsWith("v=stsv1")) ?? null;
  if (!rec) return { json, rec, status: null, contentType: null, policy: null };
  const f = ctx.fetch ?? readOnlyFetch;
  const res = await f(`https://mta-sts.${ctx.domain}/.well-known/mta-sts.txt`, {
    redirect: "manual",
    signal: AbortSignal.timeout(TIMEOUT_MS2)
  });
  const contentType = (res.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase() || null;
  const readable = res.ok && res.status < 300 && contentType === "text/plain";
  return { json, rec, status: res.status, contentType, policy: readable ? parseStsPolicy(await res.text()) : null };
}
function enforcing(policy) {
  return Boolean(
    policy && policy.version === "STSv1" && policy.mode === "enforce" && policy.maxAge !== null && policy.maxAge >= MIN_MAX_AGE && policy.maxAge <= MAX_MAX_AGE && policy.mx.length > 0
  );
}
var mtaSts = {
  code: "email.mta_sts",
  provider: "email",
  version: 2,
  severity: "low",
  maps: ["iso:8.24", "iso:8.20"],
  // "Is inbound mail protected from downgrade?" Absence is a missing hardening
  // control on a domain that is working fine, which is what `low` is for. The
  // separate question — "is this domain's mail about to bounce?" — is
  // email.mta_sts.mx_match below, and it is `high`, because those two failures
  // have nothing in common but a config file.
  //
  // This one still fails on a mismatched mx: list, and deliberately, even
  // though the check below covers it: `check.email.mta_sts.pass` says the
  // policy's exchangers cover the domain's MX records, and a green tick under
  // a sentence that is not true is worse than the same fault counted twice.
  //
  // v2, 16 Sep 2026. v1 asked one question — does the file say `mode: enforce`
  // — and passed four kinds of policy that a conforming sender rejects or
  // ignores: reached through a redirect, served as something other than
  // text/plain, carrying a max_age too short to matter, and the one that
  // matters, listing exchangers that are not the domain's. Found by verifying
  // snoopios.com's own policy by hand (docs/pilot-readiness.md, 16 Sep 2026).
  run: (ctx) => guarded("doh.mta-sts", async () => {
    const { json, rec, status, contentType, policy } = await stsPolicy(ctx);
    const observed = {
      dnsRecord: Boolean(rec),
      policyStatus: status,
      redirected: status !== null && status >= 300 && status < 400,
      contentType,
      mode: policy?.mode ?? null,
      maxAge: policy?.maxAge ?? null,
      mxPolicy: policy?.mx ?? []
    };
    const evidence = { dns: json, policyStatus: status, contentType, policy };
    if (!enforcing(policy)) return fail(observed, evidence);
    const hosts = mxHosts((await doh(ctx, ctx.domain, "MX")).Answer);
    if (hosts.length === 0) return unknown("dns.mx.none", { ...observed, mxActual: [] });
    const mxUnmatched = hosts.filter((h) => !policy.mx.some((m) => mxCoveredBy(h, m)));
    const final = { ...observed, mxActual: hosts, mxUnmatched };
    const full = { ...evidence, mx: { policy: policy.mx, actual: hosts, unmatched: mxUnmatched } };
    return mxUnmatched.length === 0 ? pass(final, full) : fail(final, full);
  })
};
var mtaStsMxMatch = {
  code: "email.mta_sts.mx_match",
  provider: "email",
  version: 1,
  severity: "high",
  maps: ["iso:8.24", "iso:8.20"],
  // The one MTA-STS failure that is an incident rather than a gap. A policy in
  // enforce mode whose mx: lines do not cover the zone's exchangers makes a
  // conforming sender REJECT mail rather than deliver it: the domain is not
  // less protected, it is not receiving email. That is why this is `high` and
  // email.mta_sts is `low`, and why it exists as its own check at all —
  // severity lives on the definition, not the result, so one check cannot say
  // "absent, and that is a nice-to-have" and "misconfigured, and your mail is
  // bouncing" with the right weight for each.
  //
  // It PASSES when no policy is in force, and records the zero it counted.
  // Nothing is enforcing, so nothing is being rejected, and the hazard this
  // check exists to find is genuinely absent — the same shape as
  // vercel.projects.fork_protection, which holds only linked projects to the
  // rule. `enforcing: false` with `mxChecked: 0` is exactly what the
  // pass-that-counted-nothing detector in scripts/evidence-ledger.mjs is meant
  // to surface for a human to dismiss, and it is right to surface it.
  run: (ctx) => guarded("doh.mta-sts", async () => {
    const { json, status, contentType, policy } = await stsPolicy(ctx);
    const evidence = { dns: json, policyStatus: status, contentType, policy };
    if (!enforcing(policy)) return pass({ enforcing: false, mxChecked: 0, mxUnmatched: [] }, evidence);
    const hosts = mxHosts((await doh(ctx, ctx.domain, "MX")).Answer);
    if (hosts.length === 0) return unknown("dns.mx.none", { enforcing: true, mxChecked: 0 });
    const mxUnmatched = hosts.filter((h) => !policy.mx.some((m) => mxCoveredBy(h, m)));
    const observed = { enforcing: true, mxChecked: hosts.length, mxPolicy: policy.mx, mxActual: hosts, mxUnmatched };
    const full = { ...evidence, mx: { policy: policy.mx, actual: hosts, unmatched: mxUnmatched } };
    return mxUnmatched.length === 0 ? pass(observed, full) : fail(observed, full);
  })
};
var tlsRpt = {
  code: "email.tlsrpt",
  provider: "email",
  version: 1,
  severity: "low",
  maps: ["iso:8.16"],
  run: (ctx) => guarded("doh.tlsrpt", async () => {
    const json = await doh(ctx, `_smtp._tls.${ctx.domain}`);
    const rec = txt(json.Answer).find((t) => t.toLowerCase().startsWith("v=tlsrptv1")) ?? null;
    const rua = /rua=(mailto:|https:)/i.test(rec ?? "");
    const observed = { present: Boolean(rec), reportsConfigured: rua };
    return rec && rua ? pass(observed, json) : fail(observed, json);
  })
};
var EMAIL_CHECKS = [dkimPresent, spfReturnPath, dmarcEnforced, dmarcReporting, mtaSts, mtaStsMxMatch, tlsRpt];
async function runEmailChecks(ctx) {
  const out = [];
  for (const c of EMAIL_CHECKS) out.push({ code: c.code, version: c.version, result: await c.run(ctx) });
  return out;
}

// ../lib/checks/providers/netlify.ts
function netlifyApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.netlify.com/api/v1${path}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
async function sites(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxSites ?? 30;
  const r = await ctx.api.get("/sites?per_page=100");
  if (r.status === 403) throw new Error("scope:sites.read");
  if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.sites");
  let list4 = r.json.filter((s) => s && s.id && s.name);
  if (ctx.sites?.length) list4 = list4.filter((s) => ctx.sites.includes(s.name));
  return list4.slice(0, max);
}
async function publishedSites(ctx) {
  return (await sites(ctx)).filter((s) => Boolean(s.published_deploy));
}
var SECRET_KEY = /(SECRET|TOKEN|PASSWORD|PRIVATE|API_KEY|_KEY$|^KEY_)/i;
var PUBLIC_KEY = /^(NEXT_PUBLIC_|PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|GATSBY_)|_PUBLIC_KEY$|PUBLISHABLE/i;
var REDIRECTS = /* @__PURE__ */ new Set([301, 302, 307, 308]);
var forceHttps = {
  code: "netlify.site.force_https",
  provider: "netlify",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("site.force_https", async () => {
    if ((await sites(ctx)).length === 0) return unknown("api.no_sites");
    const list4 = await publishedSites(ctx);
    if (list4.length === 0) return unknown("api.no_published_sites");
    const f = ctx.fetch ?? readOnlyFetch;
    const serving = [];
    const evidence = {};
    for (const s of list4) {
      const host = s.custom_domain || s.default_domain || `${s.name}.netlify.app`;
      const res = await f(`http://${host}/`, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(1e4) });
      const location = res.headers.get("location") ?? "";
      const redirected = REDIRECTS.has(res.status) && /^https:\/\//i.test(location);
      evidence[s.name] = {
        host,
        status: res.status,
        redirectsToHttps: redirected,
        aliases: s.domain_aliases ?? [],
        // Kept because an auditor will ask, and because version 1 believed them.
        apiSsl: s.ssl ?? null,
        apiForceSsl: s.force_ssl ?? null
      };
      if (!redirected) serving.push(s.name);
    }
    const observed = { sites: list4.length, notForced: serving };
    return serving.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var siteProtected = {
  code: "netlify.site.protected",
  provider: "netlify",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.3"],
  run: (ctx) => guarded("api.sites", async () => {
    const list4 = await sites(ctx);
    if (list4.length === 0) return unknown("api.no_sites");
    const password = (s) => s.password !== void 0 ? Boolean(s.password) : s.has_password;
    const locked = (s) => {
      const p = password(s);
      const sso = s.sso_login;
      if (p === void 0 && sso === void 0) return void 0;
      return p === true || sso === true;
    };
    if (list4.every((s) => locked(s) === void 0)) return unknown("api.protection_hidden", { sites: list4.length });
    const open = list4.filter((s) => locked(s) !== true).map((s) => s.name);
    const observed = { sites: list4.length, unprotected: open };
    const evidence = list4.map((s) => ({
      name: s.name,
      protected: locked(s) ?? null,
      passwordSet: password(s) ?? null,
      teamLoginRequired: s.sso_login ?? null,
      context: s.sso_login === true ? s.sso_login_context ?? null : s.password_context ?? null
    }));
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var envSecretsMarked = {
  code: "netlify.env.secrets_marked",
  provider: "netlify",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.env", async () => {
    const list4 = await sites(ctx);
    if (list4.length === 0) return unknown("api.no_sites");
    const accounts = [...new Set(list4.map((s) => s.account_slug).filter((a) => Boolean(a)))];
    if (accounts.length === 0) return unknown("api.no_account");
    const unmarked = {};
    const evidence = {};
    let total = 0;
    for (const account of accounts) {
      const r = await ctx.api.get(`/accounts/${encodeURIComponent(account)}/env`);
      if (r.status === 403) throw new Error("scope:env.read");
      if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.env");
      const vars = r.json;
      total += vars.length;
      const bad = vars.filter((v) => SECRET_KEY.test(v.key) && !PUBLIC_KEY.test(v.key) && v.is_secret !== true).map((v) => v.key);
      evidence[account] = vars.map((v) => ({ key: v.key, is_secret: v.is_secret ?? false, scopes: v.scopes ?? [] }));
      if (bad.length) unmarked[account] = bad;
    }
    const observed = { accounts: accounts.length, variables: total, secretLikeNotMarkedSecret: unmarked };
    if (total === 0) return unknown("api.no_env_vars", observed);
    return Object.keys(unmarked).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var liveHeaders = {
  code: "netlify.site.headers",
  provider: "netlify",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("site.headers", async () => {
    if ((await sites(ctx)).length === 0) return unknown("api.no_sites");
    const list4 = await publishedSites(ctx);
    if (list4.length === 0) return unknown("api.no_published_sites");
    const f = ctx.fetch ?? readOnlyFetch;
    const missing = {};
    const evidence = {};
    const behindLogin = [];
    let judged = 0;
    for (const s of list4) {
      const url = s.ssl_url ?? s.url;
      if (!url) continue;
      const res = await f(url, { method: "HEAD", redirect: "follow", signal: AbortSignal.timeout(1e4) });
      const h = (n) => res.headers.get(n);
      if (res.status === 401 || res.status === 403) {
        behindLogin.push(s.name);
        evidence[s.name] = { url, status: res.status, judged: false, reason: "behind site protection" };
        continue;
      }
      judged++;
      const csp = h("content-security-policy") ?? "";
      const gaps = [];
      if (!h("x-frame-options") && !/frame-ancestors/i.test(csp)) gaps.push("framing");
      if ((h("x-content-type-options") ?? "").toLowerCase() !== "nosniff") gaps.push("nosniff");
      if (!h("referrer-policy")) gaps.push("referrer-policy");
      evidence[s.name] = { url, status: res.status, judged: true, xFrameOptions: h("x-frame-options"), nosniff: h("x-content-type-options"), referrerPolicy: h("referrer-policy"), cspFrameAncestors: /frame-ancestors/i.test(csp) };
      if (gaps.length) missing[s.name] = gaps;
    }
    const observed = { sites: judged, behindLogin, missing };
    if (judged === 0) return unknown("api.sites_behind_login", observed);
    return Object.keys(missing).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var NETLIFY_CHECKS = [forceHttps, siteProtected, envSecretsMarked, liveHeaders];
async function runNetlifyChecks(ctx) {
  const out = [];
  for (const c of NETLIFY_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/neon.ts
function neonApi(key, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://console.neon.tech/api/v2${path}`, {
        headers: { authorization: `Bearer ${key}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
var WEEK = 7 * 24 * 3600;
var STALE_DAYS = 30;
async function listProjectIds(api) {
  const orgs = await api.get("/users/me/organizations");
  const orgIds = orgs.status === 200 ? (orgs.json?.organizations ?? []).map((o) => o.id) : [];
  const queries = orgIds.length > 0 ? orgIds.map((id) => `/projects?org_id=${encodeURIComponent(id)}&limit=100`) : ["/projects?limit=100"];
  const ids = [];
  for (const q of queries) {
    const r = await api.get(q);
    if (r.status === 403) throw new Error("scope:projects.read");
    if (r.status !== 200) throw new Error("scope:api.projects");
    for (const p of r.json?.projects ?? []) ids.push(p.id);
  }
  return ids;
}
async function projects(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxProjects ?? 20;
  let ids = ctx.projects ?? [];
  if (ids.length === 0) ids = await listProjectIds(ctx.api);
  const out = [];
  for (const id of ids.slice(0, max)) {
    const r = await ctx.api.get(`/projects/${encodeURIComponent(id)}`);
    if (r.status !== 200) throw new Error("scope:api.project");
    const p = r.json?.project;
    if (p && p.id) out.push(p);
  }
  return out;
}
async function branches(ctx, projectId) {
  const r = await ctx.api.get(`/projects/${encodeURIComponent(projectId)}/branches`);
  if (r.status !== 200) throw new Error("scope:api.branches");
  return r.json?.branches ?? [];
}
var ipAllowlist = {
  code: "neon.project.ip_allowlist",
  provider: "neon",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.20", "ce:firewalls"],
  run: (ctx) => guarded("api.projects", async () => {
    const list4 = await projects(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const open = list4.filter((p) => !p.settings?.allowed_ips?.ips?.length && p.settings?.block_public_connections !== true).map((p) => p.name);
    const observed = { projects: list4.length, openToAnyAddress: open };
    const evidence = list4.map((p) => ({ name: p.name, allowedIps: p.settings?.allowed_ips?.ips?.length ?? 0, protectedBranchesOnly: p.settings?.allowed_ips?.protected_branches_only ?? null, blockPublic: p.settings?.block_public_connections ?? null }));
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var defaultProtected = {
  code: "neon.branch.default_protected",
  provider: "neon",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "soc2:A1.2", "iso:8.13"],
  run: (ctx) => guarded("api.branches", async () => {
    const list4 = await projects(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const unprotected = [];
    const evidence = {};
    for (const p of list4) {
      const bs = await branches(ctx, p.id);
      const main2 = bs.find((b) => b.default);
      evidence[p.name] = main2 ? { branch: main2.name, protected: main2.protected ?? false } : null;
      if (!main2 || main2.protected !== true) unprotected.push(p.name);
    }
    const observed = { projects: list4.length, defaultUnprotected: unprotected };
    return unprotected.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var historyRetention = {
  code: "neon.project.history_retention",
  provider: "neon",
  version: 1,
  severity: "high",
  maps: ["soc2:A1.2", "iso:8.13", "gdpr:art32"],
  run: (ctx) => guarded("api.projects", async () => {
    const list4 = await projects(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const short = list4.filter((p) => (p.history_retention_seconds ?? 0) < WEEK).map((p) => p.name);
    const observed = { projects: list4.length, underSevenDays: short, requiredSeconds: WEEK };
    const evidence = list4.map((p) => ({ name: p.name, historyRetentionSeconds: p.history_retention_seconds ?? null }));
    return short.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var stalePreviews = {
  code: "neon.branch.stale_previews",
  provider: "neon",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.5", "gdpr:art5", "iso:8.10"],
  run: (ctx) => guarded("api.branches", async () => {
    const list4 = await projects(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    const stale = {};
    const evidence = {};
    for (const p of list4) {
      const bs = await branches(ctx, p.id);
      const old = bs.filter((b) => !b.default && b.parent_id && b.created_at && now - Date.parse(b.created_at) > STALE_DAYS * 24 * 3600 * 1e3).map((b) => b.name);
      evidence[p.name] = bs.map((b) => ({ name: b.name, default: b.default ?? false, parent: b.parent_id ?? null, createdAt: b.created_at ?? null }));
      if (old.length) stale[p.name] = old;
    }
    const observed = { projects: list4.length, staleDays: STALE_DAYS, stale };
    return Object.keys(stale).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var NEON_CHECKS = [ipAllowlist, defaultProtected, historyRetention, stalePreviews];
async function runNeonChecks(ctx) {
  const out = [];
  for (const c of NEON_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/render.ts
function renderApi(key, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.render.com/v1${path}`, {
        headers: { authorization: `Bearer ${key}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
var WEB = /* @__PURE__ */ new Set(["web_service", "static_site"]);
async function services(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxServices ?? 50;
  const out = [];
  let cursor = "";
  for (let page2 = 0; page2 < 5; page2++) {
    const r = await ctx.api.get(`/services?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
    if (r.status === 403) throw new Error("scope:services.read");
    if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.services");
    const items = r.json;
    for (const it of items) if (it.service && it.service.id) out.push(it.service);
    if (items.length < 100) break;
    cursor = items[items.length - 1]?.cursor ?? "";
    if (!cursor) break;
  }
  const list4 = ctx.services?.length ? out.filter((s) => ctx.services.includes(s.name)) : out;
  return list4.slice(0, max);
}
var healthCheck = {
  code: "render.service.health_check",
  provider: "render",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.1", "iso:8.16"],
  run: (ctx) => guarded("api.services", async () => {
    const list4 = (await services(ctx)).filter((s) => s.type === "web_service" && s.suspended !== "suspended");
    if (list4.length === 0) return unknown("api.no_web_services");
    const without = list4.filter((s) => !s.serviceDetails?.healthCheckPath).map((s) => s.name);
    const observed = { webServices: list4.length, withoutHealthCheck: without };
    const evidence = list4.map((s) => ({ name: s.name, healthCheckPath: s.serviceDetails?.healthCheckPath ?? null, region: s.serviceDetails?.region ?? null }));
    return without.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var customDomainsVerified = {
  code: "render.service.custom_domains_verified",
  provider: "render",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.24"],
  run: (ctx) => guarded("api.domains", async () => {
    const list4 = (await services(ctx)).filter((s) => WEB.has(s.type) && s.suspended !== "suspended");
    if (list4.length === 0) return unknown("api.no_web_services");
    const pending = {};
    const evidence = {};
    let domains = 0;
    for (const s of list4) {
      const r = await ctx.api.get(`/services/${encodeURIComponent(s.id)}/custom-domains?limit=100`);
      if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.domains");
      const items = r.json.map((i) => i.customDomain).filter((d) => Boolean(d));
      domains += items.length;
      const bad = items.filter((d) => d.verificationStatus !== "verified").map((d) => d.name ?? "?");
      evidence[s.name] = items.map((d) => ({ name: d.name ?? null, verificationStatus: d.verificationStatus ?? null }));
      if (bad.length) pending[s.name] = bad;
    }
    if (domains === 0) return unknown("api.no_custom_domains");
    const observed = { services: list4.length, customDomains: domains, unverified: pending };
    return Object.keys(pending).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var notifyOnFail = {
  code: "render.service.notify_on_fail",
  provider: "render",
  version: 2,
  severity: "low",
  maps: ["soc2:A1.1", "soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.services", async () => {
    const list4 = (await services(ctx)).filter((s) => s.suspended !== "suspended");
    if (list4.length === 0) return unknown("api.no_services");
    const owners = [...new Set(list4.filter((s) => (s.notifyOnFail ?? "default") === "default").map((s) => s.ownerId ?? ""))];
    const quiet = /* @__PURE__ */ new Set();
    const workspace = {};
    for (const owner of owners) {
      if (!owner) throw new Error("scope:api.shape.ownerId");
      const r = await ctx.api.get(`/notification-settings/owners/${encodeURIComponent(owner)}`);
      if (r.status !== 200 || !r.json) throw new Error("scope:api.notification_settings");
      const n = r.json;
      workspace[owner] = { notificationsToSend: n.notificationsToSend ?? null, emailEnabled: n.emailEnabled ?? null, slackEnabled: n.slackEnabled ?? null };
      if (n.notificationsToSend === "none" || !n.emailEnabled && !n.slackEnabled) quiet.add(owner);
    }
    const silent = list4.filter((s) => s.notifyOnFail === "ignore" || (s.notifyOnFail ?? "default") === "default" && quiet.has(s.ownerId ?? "")).map((s) => s.name);
    const observed = { services: list4.length, deployFailuresIgnored: silent };
    const evidence = { services: list4.map((s) => ({ name: s.name, type: s.type, notifyOnFail: s.notifyOnFail ?? null })), workspace };
    return silent.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var RENDER_CHECKS = [healthCheck, customDomainsVerified, notifyOnFail];
async function runRenderChecks(ctx) {
  const out = [];
  for (const c of RENDER_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/heroku.ts
function herokuApi(key, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.heroku.com${path}`, {
        headers: { authorization: `Bearer ${key}`, accept: "application/vnd.heroku+json; version=3", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
var SUPPORTED_STACKS = /* @__PURE__ */ new Set(["heroku-22", "heroku-24", "container"]);
async function apps(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxApps ?? 30;
  const r = await ctx.api.get("/apps");
  if (r.status === 403) throw new Error("scope:apps.read");
  if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.apps");
  let list4 = r.json.filter((a) => a && a.id && a.name);
  if (ctx.apps?.length) list4 = list4.filter((a) => ctx.apps.includes(a.name));
  return list4.slice(0, max);
}
var managedCerts = {
  code: "heroku.app.managed_certs",
  provider: "heroku",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("api.domains", async () => {
    const list4 = await apps(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    const bad = {};
    const evidence = {};
    let custom = 0;
    for (const a of list4) {
      const r = await ctx.api.get(`/apps/${encodeURIComponent(a.id)}/domains`);
      if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.domains");
      const domains = r.json.filter((d) => d.kind === "custom");
      custom += domains.length;
      const without = domains.filter((d) => !d.sni_endpoint || d.status && d.status !== "succeeded").map((d) => d.hostname ?? "?");
      evidence[a.name] = { acm: a.acm ?? null, customDomains: domains.map((d) => ({ hostname: d.hostname ?? null, status: d.status ?? null, cert: Boolean(d.sni_endpoint) })) };
      if (without.length) bad[a.name] = without;
    }
    const observed = { apps: list4.length, customDomains: custom, withoutCertificate: bad };
    return Object.keys(bad).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var maintenanceOff = {
  code: "heroku.app.maintenance_off",
  provider: "heroku",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.1", "iso:8.16"],
  run: (ctx) => guarded("api.apps", async () => {
    const list4 = await apps(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    if (shapeMismatch(list4, (a) => [a.maintenance])) return unknown("api.shape.maintenance");
    const on = list4.filter((a) => a.maintenance === true).map((a) => a.name);
    const observed = { apps: list4.length, inMaintenance: on };
    return on.length === 0 ? pass(observed, list4.map((a) => ({ name: a.name, maintenance: a.maintenance ?? false }))) : fail(observed, list4.map((a) => ({ name: a.name, maintenance: a.maintenance ?? false })));
  })
};
var stackSupported = {
  code: "heroku.app.stack_supported",
  provider: "heroku",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.1", "iso:8.8", "ce:patching"],
  run: (ctx) => guarded("api.apps", async () => {
    const list4 = await apps(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    if (shapeMismatch(list4, (a) => [a.stack])) return unknown("api.shape.stack");
    const old = list4.filter((a) => !SUPPORTED_STACKS.has(a.stack?.name ?? "")).map((a) => `${a.name} (${a.stack?.name ?? "unknown"})`);
    const observed = { apps: list4.length, unsupportedStack: old, supported: [...SUPPORTED_STACKS] };
    const evidence = list4.map((a) => ({ name: a.name, stack: a.stack?.name ?? null, buildStack: a.build_stack?.name ?? null }));
    return old.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var webRedundancy = {
  code: "heroku.formation.web_redundant",
  provider: "heroku",
  version: 1,
  severity: "low",
  maps: ["soc2:A1.2", "iso:8.14"],
  run: (ctx) => guarded("api.formation", async () => {
    const list4 = await apps(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    const single = [];
    const evidence = {};
    let withWeb = 0;
    for (const a of list4) {
      const r = await ctx.api.get(`/apps/${encodeURIComponent(a.id)}/formation`);
      if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.formation");
      const web = r.json.find((f) => f.type === "web");
      evidence[a.name] = web ? { quantity: web.quantity ?? 0, size: web.size ?? null } : null;
      if (!web || (web.quantity ?? 0) === 0) continue;
      withWeb++;
      if ((web.quantity ?? 0) < 2) single.push(a.name);
    }
    if (withWeb === 0) return unknown("api.no_web_dynos", { apps: list4.length });
    const observed = { appsWithWeb: withWeb, singleWebDyno: single };
    return single.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var HEROKU_CHECKS = [managedCerts, maintenanceOff, stackSupported, webRedundancy];
async function runHerokuChecks(ctx) {
  const out = [];
  for (const c of HEROKU_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/clerk.ts
function clerkApi(key, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.clerk.com/v1${path}`, {
        headers: { authorization: `Bearer ${key}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
var DORMANT_DAYS = 90;
var NEW_DAYS = 30;
var USER_CAP = 500;
var MAX_JWT_LIFETIME = 3600;
var DAY = 24 * 3600 * 1e3;
var redirectUrlsHttps = {
  code: "clerk.redirect_urls.https_only",
  provider: "clerk",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.redirect_urls", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get("/redirect_urls");
    if (r.status === 403) throw new Error("scope:redirect_urls.read");
    if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.redirect_urls");
    const urls = r.json.map((u) => u.url ?? "").filter(Boolean);
    if (urls.length === 0) return unknown("api.no_redirect_urls");
    const bad = urls.filter((u) => !/^https:\/\//i.test(u) || /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:|\/|$)/i.test(u) || /^https:\/\/[^/]*\.(local|test|localhost)(:|\/|$)/i.test(u));
    const observed = { redirectUrls: urls.length, insecureOrLocal: bad };
    return bad.length === 0 ? pass(observed, { urls }) : fail(observed, { urls });
  })
};
var jwtLifetime = {
  code: "clerk.jwt_templates.short_lifetime",
  provider: "clerk",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.5"],
  run: (ctx) => guarded("api.jwt_templates", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get("/jwt_templates");
    if (r.status === 403) throw new Error("scope:jwt_templates.read");
    if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.jwt_templates");
    const templates = r.json;
    if (templates.length === 0) return pass({ templates: 0, longLived: [], maxSeconds: MAX_JWT_LIFETIME }, []);
    if (shapeMismatch(templates, (t) => [t.lifetime])) return unknown("api.shape.lifetime");
    const long = templates.filter((t) => (t.lifetime ?? 0) > MAX_JWT_LIFETIME).map((t) => `${t.name ?? "?"} (${t.lifetime}s)`);
    const observed = { templates: templates.length, longLived: long, maxSeconds: MAX_JWT_LIFETIME };
    const evidence = templates.map((t) => ({ name: t.name ?? null, lifetime: t.lifetime ?? null }));
    return long.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var dormantUsers = {
  code: "clerk.users.dormant",
  provider: "clerk",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.2", "soc2:CC6.3", "iso:5.18", "ce:user-access"],
  run: (ctx) => guarded("api.users", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get(`/users?limit=${USER_CAP}&order_by=-last_active_at`);
    if (r.status === 403) throw new Error("scope:users.read");
    if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.users");
    const users = r.json.filter((u) => u && u.id && !u.banned && !u.locked);
    if (r.json.length >= USER_CAP) return unknown("api.users.too_many", { users: r.json.length, cap: USER_CAP });
    if (users.length === 0) return unknown("api.no_users");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    if (shapeMismatch(users, (u) => [u.last_active_at, u.last_sign_in_at, u.created_at])) return unknown("api.shape.last_active_at");
    const dormant = users.filter((u) => {
      const last = u.last_active_at ?? u.last_sign_in_at ?? null;
      if (last) return now - last > DORMANT_DAYS * DAY;
      return (u.created_at ?? now) < now - NEW_DAYS * DAY;
    });
    const observed = { users: users.length, dormant: dormant.length, dormantDays: DORMANT_DAYS };
    const evidence = { dormantUserIds: dormant.map((u) => u.id) };
    return dormant.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var CLERK_CHECKS = [redirectUrlsHttps, jwtLifetime, dormantUsers];
async function runClerkChecks(ctx) {
  const out = [];
  for (const c of CLERK_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/upstash.ts
function upstashApi(email, apiKey, fetchImpl = readOnlyFetch) {
  const basic = Buffer.from(`${email}:${apiKey}`).toString("base64");
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.upstash.com/v2${path}`, {
        headers: { authorization: `Basic ${basic}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401 || res.status === 403) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
function slim(d) {
  return { database_id: d.database_id, database_name: d.database_name, region: d.region, state: d.state, tls: d.tls, type: d.type, daily_backup_enabled: d.daily_backup_enabled };
}
async function databases(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get("/redis/databases?credentials=hide");
  if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.databases");
  return r.json.map(slim);
}
var tlsEverywhere = {
  code: "upstash.redis.tls",
  provider: "upstash",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "iso:8.24", "gdpr:art32"],
  run: (ctx) => guarded("api.databases", async () => {
    const dbs = await databases(ctx);
    if (dbs.length === 0) return unknown("api.no_databases");
    if (shapeMismatch(dbs, (d) => [d.tls])) return unknown("api.shape.tls");
    const plain = dbs.filter((d) => d.tls !== true).map((d) => d.database_name ?? d.database_id ?? "?");
    const observed = { databases: dbs.length, withoutTls: plain };
    const evidence = dbs.map((d) => ({ name: d.database_name ?? null, region: d.region ?? null, tls: d.tls ?? null }));
    return plain.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var dailyBackup = {
  code: "upstash.redis.daily_backup",
  provider: "upstash",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.2", "iso:8.13", "gdpr:art32"],
  run: (ctx) => guarded("api.databases", async () => {
    const dbs = await databases(ctx);
    if (dbs.length === 0) return unknown("api.no_databases");
    const paid = dbs.filter((d) => (d.type ?? "free") !== "free");
    if (paid.length === 0) return unknown("api.free_only", { databases: dbs.length });
    if (shapeMismatch(paid, (d) => [d.daily_backup_enabled])) return unknown("api.shape.daily_backup_enabled");
    const off = paid.filter((d) => d.daily_backup_enabled !== true).map((d) => d.database_name ?? d.database_id ?? "?");
    const observed = { databases: dbs.length, paid: paid.length, withoutBackup: off };
    const evidence = paid.map((d) => ({ name: d.database_name ?? null, type: d.type ?? null, dailyBackup: d.daily_backup_enabled ?? null }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var noneSuspended = {
  code: "upstash.redis.none_suspended",
  provider: "upstash",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.1", "soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.databases", async () => {
    const dbs = await databases(ctx);
    if (dbs.length === 0) return unknown("api.no_databases");
    if (shapeMismatch(dbs, (d) => [d.state])) return unknown("api.shape.state");
    const suspended = dbs.filter((d) => d.state === "suspended").map((d) => d.database_name ?? d.database_id ?? "?");
    const observed = { databases: dbs.length, suspended };
    const evidence = dbs.map((d) => ({ name: d.database_name ?? null, state: d.state ?? null }));
    return suspended.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var UPSTASH_CHECKS = [tlsEverywhere, dailyBackup, noneSuspended];
async function runUpstashChecks(ctx) {
  const out = [];
  for (const c of UPSTASH_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/betterstack.ts
function betterStackApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://uptime.betterstack.com/api/v2${path}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401 || res.status === 403) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
var MAX_PAGES = 10;
var MAX_FREQUENCY_SECONDS = 300;
var HTTP_TYPES = /* @__PURE__ */ new Set(["status", "expected_status_code", "keyword", "keyword_absence", "playwright"]);
async function monitors(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  for (let page2 = 1; page2 <= MAX_PAGES; page2++) {
    const r = await ctx.api.get(`/monitors?per_page=250&page=${page2}`);
    if (r.status !== 200) throw new Error("scope:api.monitors");
    const body = r.json;
    for (const m of body?.data ?? []) out.push({ id: m.id, ...m.attributes ?? {} });
    if (!body?.pagination?.next) break;
  }
  return out;
}
var label = (m) => m.pronounceable_name || m.url || m.id;
var active = (m) => !m.paused_at;
var monitorsActive = {
  code: "betterstack.monitors.active",
  provider: "betterstack",
  version: 1,
  severity: "high",
  maps: ["soc2:A1.1", "soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.monitors", async () => {
    const all = await monitors(ctx);
    if (shapeMismatch(all, (m) => [m.paused_at, m.url])) return unknown("api.shape.paused_at");
    const paused = all.filter((m) => !active(m)).map(label);
    const observed = { monitors: all.length, paused };
    const evidence = all.map((m) => ({ name: label(m), type: m.monitor_type ?? null, status: m.status ?? null, pausedAt: m.paused_at ?? null }));
    return all.length > 0 && paused.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var sslVerified = {
  code: "betterstack.monitors.ssl_verified",
  provider: "betterstack",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.monitors", async () => {
    const https = (await monitors(ctx)).filter((m) => active(m) && HTTP_TYPES.has(m.monitor_type ?? "") && (m.url ?? "").toLowerCase().startsWith("https://"));
    if (https.length === 0) return unknown("api.no_https_monitors");
    if (shapeMismatch(https, (m) => [m.verify_ssl, m.ssl_expiration])) return unknown("api.shape.verify_ssl");
    const weak = https.filter((m) => m.verify_ssl !== true || !(typeof m.ssl_expiration === "number" && m.ssl_expiration > 0)).map(label);
    const observed = { httpsMonitors: https.length, withoutSslChecks: weak };
    const evidence = https.map((m) => ({ name: label(m), verifySsl: m.verify_ssl ?? null, sslExpirationDays: m.ssl_expiration ?? null }));
    return weak.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var checkFrequency = {
  code: "betterstack.monitors.frequency",
  provider: "betterstack",
  version: 1,
  severity: "low",
  maps: ["soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.monitors", async () => {
    const live = (await monitors(ctx)).filter(active);
    if (live.length === 0) return unknown("api.no_active_monitors");
    if (shapeMismatch(live, (m) => [m.check_frequency])) return unknown("api.shape.check_frequency");
    const slow = live.filter((m) => !(typeof m.check_frequency === "number" && m.check_frequency <= MAX_FREQUENCY_SECONDS)).map(label);
    const observed = { monitors: live.length, slowerThanSeconds: MAX_FREQUENCY_SECONDS, slow };
    const evidence = live.map((m) => ({ name: label(m), checkFrequencySeconds: m.check_frequency ?? null }));
    return slow.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var alerting = {
  code: "betterstack.monitors.alerting",
  provider: "betterstack",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.3", "soc2:A1.1", "iso:8.16"],
  run: (ctx) => guarded("api.monitors", async () => {
    const live = (await monitors(ctx)).filter(active);
    if (live.length === 0) return unknown("api.no_active_monitors");
    if (shapeMismatch(live, (m) => [m.policy_id, m.call, m.sms, m.email, m.push])) return unknown("api.shape.policy_id");
    const silent = live.filter((m) => !(m.policy_id || m.call || m.sms || m.email || m.push)).map(label);
    const observed = { monitors: live.length, withoutAlerts: silent };
    const evidence = live.map((m) => ({ name: label(m), policy: Boolean(m.policy_id), call: m.call ?? false, sms: m.sms ?? false, email: m.email ?? false, push: m.push ?? false }));
    return silent.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var BETTERSTACK_CHECKS = [monitorsActive, sslVerified, checkFrequency, alerting];
async function runBetterStackChecks(ctx) {
  const out = [];
  for (const c of BETTERSTACK_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/railway.ts
function railwayApi(projectToken, fetchImpl = readOnlyFetch) {
  return {
    async query(query, variables = {}) {
      const res = await fetchImpl("https://backboard.railway.com/graphql/v2", {
        method: "POST",
        headers: { "project-access-token": projectToken, "content-type": "application/json", accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        body: JSON.stringify({ query, variables }),
        signal: AbortSignal.timeout(2e4)
      });
      if (res.status === 401 || res.status === 403) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
async function gql(api, query, variables, scope) {
  const r = await api.query(query, variables);
  const body = r.json;
  if (body?.errors?.some((e) => /unauthori[sz]ed|not authorized|forbidden/i.test(e.message ?? "") || e.extensions?.code === "UNAUTHENTICATED")) throw new Error("scope:auth");
  if (r.status !== 200 || !body?.data || body.errors?.length) throw new Error(`scope:${scope}`);
  return body.data;
}
var Q_TOKEN = "query snoopiosToken { projectToken { projectId environmentId } }";
var Q_PROJECT = "query snoopiosProject($id: String!) { project(id: $id) { id name services { edges { node { id name } } } } }";
var Q_INSTANCE = "query snoopiosInstance($serviceId: String!, $environmentId: String!) { serviceInstance(serviceId: $serviceId, environmentId: $environmentId) { healthcheckPath numReplicas restartPolicyType } }";
var Q_DOMAINS = "query snoopiosDomains($projectId: String!, $environmentId: String!, $serviceId: String!) { domains(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId) { serviceDomains { domain } customDomains { domain status { dnsRecords { hostlabel requiredValue currentValue status } } } } }";
var MAX_SERVICES = 50;
async function load(api) {
  const tok = await gql(api, Q_TOKEN, {}, "api.project_token");
  const projectId = tok.projectToken?.projectId ?? "";
  const environmentId = tok.projectToken?.environmentId ?? "";
  if (!projectId || !environmentId) throw new Error("scope:api.project_token");
  const proj = await gql(api, Q_PROJECT, { id: projectId }, "api.project");
  const nodes = (proj.project?.services?.edges ?? []).map((e) => e.node).filter((n) => Boolean(n?.id)).slice(0, MAX_SERVICES);
  const services2 = [];
  for (const n of nodes) {
    const inst = await gql(api, Q_INSTANCE, { serviceId: n.id, environmentId }, "api.service_instance");
    const dom = await gql(api, Q_DOMAINS, { projectId, environmentId, serviceId: n.id }, "api.domains");
    services2.push({
      id: n.id,
      name: n.name ?? n.id,
      healthcheckPath: inst.serviceInstance?.healthcheckPath ?? null,
      numReplicas: inst.serviceInstance?.numReplicas ?? null,
      restartPolicyType: inst.serviceInstance?.restartPolicyType ?? null,
      serviceDomains: (dom.domains?.serviceDomains ?? []).map((d) => d.domain ?? "").filter(Boolean),
      customDomains: (dom.domains?.customDomains ?? []).filter((d) => d.domain).map((d) => ({ domain: d.domain, records: d.status?.dnsRecords ?? [] }))
    });
  }
  return { projectId, environmentId, services: services2 };
}
function inventory(ctx) {
  if (!ctx.api) return Promise.reject(new Error("scope:api.not_connected"));
  ctx.inventory ??= load(ctx.api);
  return ctx.inventory;
}
var isPublic = (s) => s.serviceDomains.length + s.customDomains.length > 0;
var norm = (v) => (v ?? "").trim().toLowerCase().replace(/\.$/, "");
var healthcheck = {
  code: "railway.service.healthcheck",
  provider: "railway",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.1", "soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.services", async () => {
    const pub = (await inventory(ctx)).services.filter(isPublic);
    if (pub.length === 0) return unknown("api.no_public_services");
    const none = pub.filter((s) => !(s.healthcheckPath ?? "").trim()).map((s) => s.name);
    const observed = { publicServices: pub.length, withoutHealthcheck: none };
    const evidence = pub.map((s) => ({ name: s.name, healthcheckPath: s.healthcheckPath ?? null, domains: [...s.serviceDomains, ...s.customDomains.map((d) => d.domain)] }));
    return none.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var restartPolicy = {
  code: "railway.service.restart_policy",
  provider: "railway",
  version: 1,
  severity: "low",
  maps: ["soc2:A1.1", "iso:8.14"],
  run: (ctx) => guarded("api.services", async () => {
    const all = (await inventory(ctx)).services;
    if (all.length === 0) return unknown("api.no_services");
    const never = all.filter((s) => (s.restartPolicyType ?? "").toUpperCase() === "NEVER").map((s) => s.name);
    const observed = { services: all.length, neverRestart: never };
    const evidence = all.map((s) => ({ name: s.name, restartPolicy: s.restartPolicyType ?? null }));
    return never.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var replicas = {
  code: "railway.service.replicas",
  provider: "railway",
  version: 1,
  severity: "low",
  maps: ["soc2:A1.1", "iso:8.14"],
  run: (ctx) => guarded("api.services", async () => {
    const pub = (await inventory(ctx)).services.filter(isPublic);
    if (pub.length === 0) return unknown("api.no_public_services");
    const single = pub.filter((s) => (s.numReplicas ?? 1) < 2).map((s) => s.name);
    const observed = { publicServices: pub.length, singleReplica: single };
    const evidence = pub.map((s) => ({ name: s.name, replicas: s.numReplicas ?? null }));
    return single.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var customDomainsValid = {
  code: "railway.domain.dns_valid",
  provider: "railway",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.20", "ce:secure-config"],
  run: (ctx) => guarded("api.domains", async () => {
    const domains = (await inventory(ctx)).services.flatMap((s) => s.customDomains.map((d) => ({ service: s.name, ...d })));
    if (domains.length === 0) return unknown("api.no_custom_domains");
    const stale = domains.filter((d) => d.records.length === 0 || d.records.some((r) => norm(r.currentValue) !== norm(r.requiredValue))).map((d) => d.domain);
    const observed = { customDomains: domains.length, notPointingAtRailway: stale };
    const evidence = domains.map((d) => ({ domain: d.domain, service: d.service, records: d.records.map((r) => ({ host: r.hostlabel ?? null, status: r.status ?? null, matches: norm(r.currentValue) === norm(r.requiredValue) })) }));
    return stale.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var RAILWAY_CHECKS = [healthcheck, restartPolicy, replicas, customDomainsValid];
async function runRailwayChecks(ctx) {
  const out = [];
  for (const c of RAILWAY_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/circleci.ts
var CIRCLECI_PROJECT = /^(gh|bb|github|bitbucket|circleci)\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
function circleCiApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://circleci.com/api/v2${path}`, {
        headers: { "circle-token": token, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
async function settings(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const [vcs, org, repo2] = ctx.project.split("/");
  const r = await ctx.api.get(`/project/${encodeURIComponent(vcs)}/${encodeURIComponent(org)}/${encodeURIComponent(repo2)}/settings`);
  if (r.status === 403) {
    const p = await ctx.api.get(`/project/${ctx.project.split("/").map(encodeURIComponent).join("/")}`);
    const provider = p.json?.vcs_info?.provider;
    if (p.status === 200 && provider === "CircleCI") throw new Error("scope:api.github_app_project");
    throw new Error("scope:scope.settings");
  }
  if (r.status === 404) throw new Error("scope:api.project_not_found");
  if (r.status !== 200) throw new Error("scope:api.settings");
  return r.json?.advanced ?? {};
}
var buildsPrivate = {
  code: "circleci.project.builds_private",
  provider: "circleci",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.3"],
  run: (ctx) => guarded("api.settings", async () => {
    const s = await settings(ctx);
    if (s.oss === void 0) return unknown("api.shape.oss");
    const observed = { project: ctx.project, oss: s.oss ?? null };
    return s.oss === false ? pass(observed, observed) : fail(observed, observed);
  })
};
var settingsAdminOnly = {
  code: "circleci.project.settings_admin_only",
  provider: "circleci",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC8.1", "iso:8.32"],
  run: (ctx) => guarded("api.settings", async () => {
    const s = await settings(ctx);
    if (s.write_settings_requires_admin === void 0) return unknown("api.shape.write_settings_requires_admin");
    const observed = { project: ctx.project, writeSettingsRequiresAdmin: s.write_settings_requires_admin ?? null };
    return s.write_settings_requires_admin === true ? pass(observed, observed) : fail(observed, observed);
  })
};
var forksNoSecrets = {
  code: "circleci.project.forks_no_secrets",
  provider: "circleci",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.12", "iso:8.28"],
  run: (ctx) => guarded("api.settings", async () => {
    const s = await settings(ctx);
    if (s.forks_receive_secret_env_vars === void 0) return unknown("api.shape.forks_receive_secret_env_vars");
    const observed = { project: ctx.project, buildForkPrs: s.build_fork_prs ?? null, forksReceiveSecrets: s.forks_receive_secret_env_vars ?? null };
    const ok = s.forks_receive_secret_env_vars !== true;
    return ok ? pass(observed, observed) : fail(observed, observed);
  })
};
var CIRCLECI_CHECKS = [buildsPrivate, settingsAdminOnly, forksNoSecrets];
async function runCircleCiChecks(ctx) {
  const out = [];
  for (const c of CIRCLECI_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/checkly.ts
function checklyApi(apiKey, accountId, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.checklyhq.com${path}`, {
        headers: { authorization: `Bearer ${apiKey}`, "x-checkly-account": accountId, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401 || res.status === 403) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
var LIMIT = 100;
async function list(ctx, path, scope) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  for (let page2 = 1; page2 <= 10; page2++) {
    const sep = path.includes("?") ? "&" : "?";
    const r = await ctx.api.get(`${path}${sep}limit=${LIMIT}&page=${page2}`);
    if (r.status !== 200 || !Array.isArray(r.json)) throw new Error(`scope:api.${scope}`);
    out.push(...r.json);
    if (r.json.length < LIMIT) break;
  }
  return out;
}
var label2 = (c) => c.name ?? c.id ?? "?";
var checksActive = {
  code: "checkly.checks.active",
  provider: "checkly",
  version: 1,
  severity: "high",
  maps: ["soc2:A1.1", "soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.checks", async () => {
    const all = await list(ctx, "/v1/checks?applyGroupSettings=true", "checks");
    if (shapeMismatch(all, (c) => [c.activated, c.muted])) return unknown("api.shape.activated");
    const off = all.filter((c) => c.activated === false || c.muted === true).map(label2);
    const observed = { checks: all.length, deactivatedOrMuted: off };
    const evidence = all.map((c) => ({ check: label2(c), type: c.checkType ?? null, activated: c.activated ?? null, muted: c.muted ?? null }));
    return all.length > 0 && off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var checksAlert = {
  code: "checkly.checks.alerting",
  provider: "checkly",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.3", "soc2:A1.1", "iso:8.16"],
  run: (ctx) => guarded("api.checks", async () => {
    const live = (await list(ctx, "/v1/checks?applyGroupSettings=true", "checks")).filter((c) => c.activated !== false);
    if (live.length === 0) return unknown("api.no_active_checks");
    if (shapeMismatch(live, (c) => [c.alertChannelSubscriptions])) return unknown("api.shape.alertChannelSubscriptions");
    const silent = live.filter((c) => !(c.alertChannelSubscriptions ?? []).some((s) => s.activated !== false)).map(label2);
    const observed = { activeChecks: live.length, withoutAlertChannel: silent };
    const evidence = live.map((c) => ({ check: label2(c), channels: (c.alertChannelSubscriptions ?? []).filter((s) => s.activated !== false).length }));
    return silent.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var sslExpiryWatched = {
  code: "checkly.alert_channels.ssl_expiry",
  provider: "checkly",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.alert_channels", async () => {
    const channels = await list(ctx, "/v1/alert-channels", "alert_channels");
    if (channels.length === 0) return fail({ alertChannels: 0, sslExpiryChannels: [] }, []);
    if (shapeMismatch(channels, (c) => [c.sslExpiry])) return unknown("api.shape.sslExpiry");
    const ssl = channels.filter((c) => c.sslExpiry === true).map((c) => `${c.type ?? "?"} (${c.sslExpiryThreshold ?? "?"} days)`);
    const observed = { alertChannels: channels.length, sslExpiryChannels: ssl };
    const evidence = channels.map((c) => ({ type: c.type ?? null, sslExpiry: c.sslExpiry ?? null, thresholdDays: c.sslExpiryThreshold ?? null }));
    return ssl.length > 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var multiLocation = {
  code: "checkly.checks.multi_location",
  provider: "checkly",
  version: 1,
  severity: "low",
  maps: ["soc2:A1.1", "iso:8.16"],
  run: (ctx) => guarded("api.checks", async () => {
    const live = (await list(ctx, "/v1/checks?applyGroupSettings=true", "checks")).filter((c) => c.activated !== false);
    if (live.length === 0) return unknown("api.no_active_checks");
    if (shapeMismatch(live, (c) => [c.locations])) return unknown("api.shape.locations");
    const single = live.filter((c) => (c.locations ?? []).length < 2).map(label2);
    const observed = { activeChecks: live.length, singleLocation: single };
    const evidence = live.map((c) => ({ check: label2(c), locations: c.locations ?? [] }));
    return single.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var CHECKLY_CHECKS = [checksActive, checksAlert, sslExpiryWatched, multiLocation];
async function runChecklyChecks(ctx) {
  const out = [];
  for (const c of CHECKLY_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/turso.ts
var TURSO_ORG = /^[a-z0-9][a-z0-9-]{0,63}$/;
function tursoApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.turso.tech/v1${path}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401 || res.status === 403) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
async function get(ctx, path, key, scope) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(`/organizations/${encodeURIComponent(ctx.org)}${path}`);
  if (r.status !== 200) throw new Error(`scope:api.${scope}`);
  const items = r.json?.[key];
  if (!Array.isArray(items)) throw new Error(`scope:api.${scope}`);
  return items;
}
var dbName = (d) => d.Name ?? d.name ?? "?";
var databasesProtected = {
  code: "turso.databases.delete_protection",
  provider: "turso",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.2", "soc2:CC6.1", "iso:8.13"],
  run: (ctx) => guarded("api.databases", async () => {
    const dbs = await get(ctx, "/databases", "databases", "databases");
    if (dbs.length === 0) return unknown("api.no_databases");
    if (shapeMismatch(dbs, (d) => [d.delete_protection])) return unknown("api.shape.delete_protection");
    const off = dbs.filter((d) => d.delete_protection !== true).map(dbName);
    const observed = { databases: dbs.length, deletable: off };
    const evidence = dbs.map((d) => ({ database: dbName(d), group: d.group ?? null, deleteProtection: d.delete_protection ?? null, blocked: Boolean(d.block_reads || d.block_writes) }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var groupsProtected = {
  code: "turso.groups.delete_protection",
  provider: "turso",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.2", "iso:8.13"],
  run: (ctx) => guarded("api.groups", async () => {
    const groups = await get(ctx, "/groups", "groups", "groups");
    if (groups.length === 0) return unknown("api.no_groups");
    if (shapeMismatch(groups, (g) => [g.delete_protection])) return unknown("api.shape.delete_protection");
    const off = groups.filter((g) => g.delete_protection !== true).map((g) => g.name ?? "?");
    const observed = { groups: groups.length, deletable: off };
    const evidence = groups.map((g) => ({ group: g.name ?? null, primary: g.primary ?? null, deleteProtection: g.delete_protection ?? null }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var MAX_OWNERS = 3;
var ownersLimited = {
  code: "turso.members.owners_limited",
  provider: "turso",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.3", "iso:5.15", "iso:8.2", "ce:user-access"],
  run: (ctx) => guarded("api.members", async () => {
    const members = await get(ctx, "/members", "members", "members");
    if (members.length === 0) return unknown("api.no_members");
    if (shapeMismatch(members, (m) => [m.role])) return unknown("api.shape.role");
    const owners = members.filter((m) => m.role === "owner").length;
    const admins = members.filter((m) => m.role === "admin").length;
    const observed = { members: members.length, owners, admins, max: MAX_OWNERS };
    const evidence = { roles: members.reduce((acc, m) => ({ ...acc, [m.role ?? "?"]: (acc[m.role ?? "?"] ?? 0) + 1 }), {}) };
    return owners > 0 && owners <= MAX_OWNERS ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var TURSO_CHECKS = [databasesProtected, groupsProtected, ownersLimited];
async function runTursoChecks(ctx) {
  const out = [];
  for (const c of TURSO_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/workos.ts
function workOsApi(key, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`https://api.workos.com${path}`, {
        headers: { authorization: `Bearer ${key}`, accept: "application/json", "user-agent": "snoopios-cli (+https://snoopios.com)" },
        signal: AbortSignal.timeout(15e3)
      });
      if (res.status === 401) throw new Error("scope:auth");
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    }
  };
}
var LIMIT2 = 100;
var MAX_PAGES2 = 5;
async function list2(ctx, path, scope) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  let after = null;
  for (let i = 0; i < MAX_PAGES2; i++) {
    const sep = path.includes("?") ? "&" : "?";
    const r = await ctx.api.get(`${path}${sep}limit=${LIMIT2}${after ? `&after=${encodeURIComponent(after)}` : ""}`);
    if (r.status === 403) throw new Error(`scope:scope.${scope}`);
    if (r.status !== 200) throw new Error(`scope:api.${scope}`);
    const body = r.json;
    out.push(...body?.data ?? []);
    after = body?.list_metadata?.after ?? null;
    if (!after) return { items: out, truncated: false };
  }
  return { items: out, truncated: true };
}
var connectionsActive = {
  code: "workos.connections.active",
  provider: "workos",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:5.16", "iso:8.5"],
  run: (ctx) => guarded("api.connections", async () => {
    const { items } = await list2(ctx, "/connections", "connections");
    if (items.length === 0) return unknown("api.no_connections");
    if (shapeMismatch(items, (c) => [c.state])) return unknown("api.shape.state");
    const inactive = items.filter((c) => c.state !== "active").map((c) => `${c.name ?? c.id} (${c.state ?? "?"})`);
    const observed = { connections: items.length, notActive: inactive };
    const evidence = items.map((c) => ({ connection: c.name ?? c.id, type: c.connection_type ?? null, state: c.state ?? null }));
    return inactive.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var directoriesLinked = {
  code: "workos.directories.linked",
  provider: "workos",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.2", "soc2:CC6.3", "iso:5.18"],
  run: (ctx) => guarded("api.directories", async () => {
    const { items } = await list2(ctx, "/directories", "directories");
    if (items.length === 0) return unknown("api.no_directories");
    if (shapeMismatch(items, (d) => [d.state])) return unknown("api.shape.state");
    const broken = items.filter((d) => d.state !== "linked").map((d) => `${d.name ?? d.id} (${d.state ?? "?"})`);
    const observed = { directories: items.length, notLinked: broken };
    const evidence = items.map((d) => ({ directory: d.name ?? d.id, type: d.type ?? null, state: d.state ?? null }));
    return broken.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var domainsVerified = {
  code: "workos.organizations.domains_verified",
  provider: "workos",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:5.16"],
  run: (ctx) => guarded("api.organizations", async () => {
    const { items } = await list2(ctx, "/organizations", "organizations");
    const withDomains = items.filter((o) => (o.domains ?? []).length > 0);
    if (withDomains.length === 0) return unknown("api.no_organization_domains");
    if (shapeMismatch(withDomains.flatMap((o) => o.domains ?? []), (d) => [d.state])) return unknown("api.shape.domain_state");
    const unverified = withDomains.flatMap((o) => (o.domains ?? []).filter((d) => d.state !== "verified").map((d) => `${o.name ?? o.id}: ${d.domain ?? "?"} (${d.state ?? "?"})`));
    const observed = { organizations: withDomains.length, unverifiedDomains: unverified };
    const evidence = withDomains.map((o) => ({ organization: o.name ?? o.id, domains: (o.domains ?? []).map((d) => ({ domain: d.domain ?? null, state: d.state ?? null })) }));
    return unverified.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
function mask(email) {
  if (!email) return "?";
  const [local, domain] = email.split("@");
  return domain ? `${local.slice(0, 1)}\u2026@${domain}` : `${local.slice(0, 1)}\u2026`;
}
var usersVerified = {
  code: "workos.users.email_verified",
  provider: "workos",
  version: 1,
  severity: "low",
  maps: ["soc2:CC6.1", "iso:5.16"],
  run: (ctx) => guarded("api.users", async () => {
    const { items, truncated } = await list2(ctx, "/user_management/users", "users");
    if (truncated) return unknown("api.users.too_many");
    if (items.length === 0) return unknown("api.no_users");
    if (shapeMismatch(items, (u) => [u.email_verified])) return unknown("api.shape.email_verified");
    const unverified = items.filter((u) => u.email_verified !== true).map((u) => mask(u.email));
    const observed = { users: items.length, unverifiedEmails: unverified };
    const evidence = { unverified };
    return unverified.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var WORKOS_CHECKS = [connectionsActive, directoriesLinked, domainsVerified, usersVerified];
async function runWorkOsChecks(ctx) {
  const out = [];
  for (const c of WORKOS_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/findings.ts
var REMEDIATION_DAYS = 30;
var LONG_STOP_DAYS = 90;
var SCAN_DAYS = 14;
var URGENT = ["critical", "high"];
var olderThan = (f, cutoff) => !f.openedAt || Date.parse(f.openedAt) < cutoff;
var describe = (f) => `${f.ref} (${f.severity}, opened ${(f.openedAt ?? "date unknown").slice(0, 10)})`;
function judgeNoCritical(findings4) {
  if (findings4.length > 0 && shapeMismatch(findings4, (f) => [f.severity === "unknown" ? void 0 : f.severity])) {
    return unknown("api.shape.severity");
  }
  const critical = findings4.filter((f) => f.severity === "critical").map(describe);
  const observed = { openFindings: findings4.length, critical: critical.length, findings: critical.slice(0, 10) };
  return critical.length === 0 ? pass(observed, findings4.length) : fail(observed, findings4.length);
}
function judgeWithinWindow(findings4, now) {
  const urgent = findings4.filter((f) => URGENT.includes(f.severity));
  if (urgent.length === 0) {
    const observed2 = { openFindings: findings4.length, urgent: 0, withinDays: REMEDIATION_DAYS, overdue: 0, findings: [] };
    return pass(observed2, findings4.length);
  }
  if (shapeMismatch(urgent, (f) => [f.openedAt])) return unknown("api.shape.openedAt");
  const cutoff = now.getTime() - REMEDIATION_DAYS * 864e5;
  const overdue = urgent.filter((f) => olderThan(f, cutoff)).map(describe);
  const observed = { openFindings: findings4.length, urgent: urgent.length, withinDays: REMEDIATION_DAYS, overdue: overdue.length, findings: overdue.slice(0, 10) };
  return overdue.length === 0 ? pass(observed, urgent.length) : fail(observed, urgent.length);
}
function judgeNoAncient(findings4, now) {
  if (findings4.length === 0) {
    return pass({ openFindings: 0, withinDays: LONG_STOP_DAYS, ancient: 0, findings: [] }, 0);
  }
  if (shapeMismatch(findings4, (f) => [f.openedAt])) return unknown("api.shape.openedAt");
  const cutoff = now.getTime() - LONG_STOP_DAYS * 864e5;
  const ancient = findings4.filter((f) => olderThan(f, cutoff)).map(describe);
  const observed = { openFindings: findings4.length, withinDays: LONG_STOP_DAYS, ancient: ancient.length, findings: ancient.slice(0, 10) };
  return ancient.length === 0 ? pass(observed, findings4.length) : fail(observed, findings4.length);
}
function judgeScanFresh(lastScan, now, label4) {
  if (!lastScan) return unknown("scanner.no_scan_date");
  const age = Math.floor((now.getTime() - Date.parse(lastScan)) / 864e5);
  if (!Number.isFinite(age)) return unknown("api.shape.lastScan");
  const observed = { subject: label4, lastScan: lastScan.slice(0, 10), daysAgo: age, withinDays: SCAN_DAYS };
  return age <= SCAN_DAYS ? pass(observed, lastScan) : fail(observed, lastScan);
}
function severityOf(raw) {
  const s = (raw ?? "").trim().toLowerCase();
  if (s === "critical" || s === "blocker") return "critical";
  if (s === "high" || s === "major") return "high";
  if (s === "medium" || s === "moderate" || s === "warning") return "medium";
  if (s === "low" || s === "info" || s === "note" || s === "minor") return "low";
  return "unknown";
}

// ../lib/checks/providers/snyk.ts
var need = (ctx) => {
  if (!ctx.api || !ctx.orgId) throw new Error("scope:snyk.unconfigured");
  return { api: ctx.api, orgId: ctx.orgId };
};
var VERSION = "2024-10-15";
var MAX_PAGES3 = 10;
var PER_PAGE = 100;
async function collect(ctx, first, scope) {
  const { api } = need(ctx);
  const out = [];
  let path = first;
  for (let i = 0; i < MAX_PAGES3 && path; i++) {
    const r = await api.get(path);
    const body = r.json;
    if (!body || !Array.isArray(body.data)) throw new Error(`scope:${scope}`);
    out.push(...body.data);
    path = body.links?.next;
  }
  return out;
}
async function openFindings(ctx) {
  const { orgId } = need(ctx);
  const issues = await collect(ctx, `/rest/orgs/${orgId}/issues?version=${VERSION}&limit=${PER_PAGE}&status=open`, "api.snyk.issues");
  return issues.filter((i) => !i.attributes?.ignored && (i.attributes?.status ?? "open") === "open").map((i) => ({
    ref: i.attributes?.key ?? i.attributes?.title ?? i.id ?? "an issue",
    severity: severityOf(i.attributes?.effective_severity_level),
    openedAt: i.attributes?.created_at
  }));
}
async function projects2(ctx) {
  const { orgId } = need(ctx);
  return collect(ctx, `/rest/orgs/${orgId}/projects?version=${VERSION}&limit=${PER_PAGE}&meta.latest_issue_counts=true`, "api.snyk.projects");
}
var noCritical = {
  code: "snyk.issues.no_critical",
  provider: "snyk",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC7.1", "iso:8.8", "ce:patching", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.snyk.issues", async () => judgeNoCritical(await openFindings(ctx)))
};
var withinWindow = {
  code: "snyk.issues.within_window",
  provider: "snyk",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.1", "soc2:CC7.4", "iso:8.8", "ce:patching", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.snyk.issues", async () => judgeWithinWindow(await openFindings(ctx), ctx.now ?? /* @__PURE__ */ new Date()))
};
var noAncient = {
  code: "snyk.issues.no_ancient",
  provider: "snyk",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.1", "iso:8.8", "iso:5.25", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.snyk.issues", async () => judgeNoAncient(await openFindings(ctx), ctx.now ?? /* @__PURE__ */ new Date()))
};
var scanningFresh = {
  code: "snyk.projects.scanned_recently",
  provider: "snyk",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.1", "iso:8.8", "ce:patching", "nist-csf:DE.CM"],
  run: (ctx) => guarded("api.snyk.projects", async () => {
    const list4 = await projects2(ctx);
    const active3 = list4.filter((p) => (p.attributes?.status ?? "active") === "active");
    if (active3.length === 0) return unknown("api.snyk.no_projects");
    const scannedAt = (p) => p.meta?.latest_issue_counts?.updated_at;
    const dated = active3.map(scannedAt).filter((d) => typeof d === "string");
    if (dated.length === 0) return unknown("api.shape.latest_issue_counts.updated_at");
    const oldest = dated.reduce((a, b) => Date.parse(a) < Date.parse(b) ? a : b);
    const stalest = active3.find((p) => scannedAt(p) === oldest);
    const r = judgeScanFresh(oldest, ctx.now ?? /* @__PURE__ */ new Date(), stalest?.attributes?.name ?? "a project");
    return { ...r, observed: { ...r.observed, projects: active3.length } };
  })
};
var SNYK_CHECKS = [noCritical, withinWindow, scanningFresh, noAncient];
var BASE = "https://api.snyk.io";
var UA2 = "snoopios-check/1 (+https://snoopios.com)";
var SNYK_ORG = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function snykApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`${BASE}${path}`, {
        headers: { authorization: `token ${token}`, accept: "application/vnd.api+json", "user-agent": UA2 },
        signal: AbortSignal.timeout(3e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403) throw new Error("scope:plan.no_api_access");
      const json = await res.json().catch(() => null);
      return { status: res.status, json };
    }
  };
}
async function runSnykChecks(ctx) {
  const out = [];
  for (const c of SNYK_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/gitguardian.ts
var need2 = (ctx) => {
  if (!ctx.api) throw new Error("scope:gitguardian.unconfigured");
  return ctx.api;
};
var MAX_PAGES4 = 10;
var PER_PAGE2 = 100;
var OPEN = /* @__PURE__ */ new Set(["TRIGGERED", "ASSIGNED"]);
var LIVE = "valid";
async function requireSources(api) {
  const r = await api.get("/v1/sources?per_page=1");
  if (r.status === 403) throw new Error("scope:scope.sources_read");
  if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.sources");
  if (r.json.length === 0) throw new Error("scope:api.no_sources");
}
async function incidents(ctx) {
  const api = need2(ctx);
  await requireSources(api);
  const out = [];
  let path = `/v1/incidents/secrets?per_page=${PER_PAGE2}`;
  for (let i = 0; i < MAX_PAGES4 && path; i++) {
    const r = await api.get(path);
    if (!Array.isArray(r.json)) return out.length > 0 ? out : null;
    out.push(...r.json);
    path = r.next;
  }
  if (path) throw new Error("scope:gitguardian.too_many_incidents");
  return out;
}
var openIncidents = (list4) => list4.filter((i) => OPEN.has((i.status ?? "").toUpperCase()));
var label3 = (i) => i.detector?.display_name ?? i.detector?.name ?? (i.id !== void 0 ? `incident ${i.id}` : "an incident");
function toFinding(i) {
  const live = (i.validity ?? "").toLowerCase() === LIVE;
  return { ref: label3(i), severity: live ? "critical" : severityOf(i.severity), openedAt: i.date };
}
async function findings(ctx) {
  const list4 = await incidents(ctx);
  return list4 === null ? null : openIncidents(list4).map(toFinding);
}
var noLiveSecrets = {
  code: "gitguardian.secrets.none_live",
  provider: "gitguardian",
  version: 2,
  severity: "critical",
  maps: ["soc2:CC6.1", "soc2:CC6.3", "iso:8.24", "iso:5.17", "gdpr:art32", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.gitguardian.incidents", async () => {
    const list4 = await incidents(ctx);
    if (list4 === null) return unknown("api.shape.incidents");
    const open = openIncidents(list4);
    const live = open.filter((i) => (i.validity ?? "").toLowerCase() === LIVE).map(label3);
    const observed = { openIncidents: open.length, stillValid: live.length, secrets: live.slice(0, 10) };
    return live.length === 0 ? pass(observed, open.length) : fail(observed, open.length);
  })
};
var noCritical2 = {
  code: "gitguardian.secrets.no_critical",
  provider: "gitguardian",
  version: 2,
  severity: "critical",
  maps: ["soc2:CC6.1", "iso:8.24", "iso:5.17", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.gitguardian.incidents", async () => {
    const list4 = await findings(ctx);
    return list4 === null ? unknown("api.shape.incidents") : judgeNoCritical(list4);
  })
};
var withinWindow2 = {
  code: "gitguardian.secrets.within_window",
  provider: "gitguardian",
  version: 2,
  severity: "high",
  maps: ["soc2:CC7.1", "soc2:CC7.4", "iso:5.17", "iso:8.8", "nist-csf:RS.MA"],
  run: (ctx) => guarded("api.gitguardian.incidents", async () => {
    const list4 = await findings(ctx);
    return list4 === null ? unknown("api.shape.incidents") : judgeWithinWindow(list4, ctx.now ?? /* @__PURE__ */ new Date());
  })
};
var noAncient2 = {
  code: "gitguardian.secrets.no_ancient",
  provider: "gitguardian",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC7.1", "iso:5.17", "iso:5.25", "nist-csf:RS.MA"],
  run: (ctx) => guarded("api.gitguardian.incidents", async () => {
    const list4 = await findings(ctx);
    return list4 === null ? unknown("api.shape.incidents") : judgeNoAncient(list4, ctx.now ?? /* @__PURE__ */ new Date());
  })
};
var GITGUARDIAN_CHECKS = [noLiveSecrets, noCritical2, withinWindow2, noAncient2];
var BASE2 = "https://api.gitguardian.com";
var UA3 = "snoopios-check/1 (+https://snoopios.com)";
function nextFromLink(link) {
  if (!link) return null;
  for (const part of link.split(",")) {
    const m = /<([^>]+)>\s*;\s*rel="next"/.exec(part.trim());
    if (!m) continue;
    try {
      const url = new URL(m[1]);
      if (url.origin !== BASE2) return null;
      return url.pathname + url.search;
    } catch {
      return null;
    }
  }
  return null;
}
function gitGuardianApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`${BASE2}${path}`, {
        headers: { authorization: `Token ${token}`, accept: "application/json", "user-agent": UA3 },
        signal: AbortSignal.timeout(3e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403 && !path.startsWith("/v1/sources")) throw new Error("scope:gitguardian.forbidden");
      const json = await res.json().catch(() => null);
      return { status: res.status, json, next: nextFromLink(res.headers.get("link")) };
    }
  };
}
async function runGitGuardianChecks(ctx) {
  const out = [];
  for (const c of GITGUARDIAN_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/semgrep.ts
var need3 = (ctx) => {
  if (!ctx.api || !ctx.slug) throw new Error("scope:semgrep.unconfigured");
  return { api: ctx.api, slug: ctx.slug };
};
var MAX_PAGES5 = 10;
var PER_PAGE3 = 100;
var OPEN2 = /* @__PURE__ */ new Set(["unresolved", "open", "reviewing"]);
async function findings2(ctx) {
  const { api, slug } = need3(ctx);
  const known = await projects3(ctx);
  if (known === null) return null;
  if (known.length === 0) throw new Error("scope:api.no_projects");
  if (!known.some((p) => typeof p.latest_scan_at === "string")) throw new Error("scope:api.no_completed_scan");
  const out = [];
  for (let page2 = 0; page2 < MAX_PAGES5; page2++) {
    const r = await api.get(`/api/v1/deployments/${slug}/findings?page=${page2}&page_size=${PER_PAGE3}&issue_type=sast`);
    const body = r.json;
    if (!body || !Array.isArray(body.findings)) return out.length > 0 ? toShared(out) : null;
    out.push(...body.findings);
    if (body.findings.length < PER_PAGE3) return toShared(out);
  }
  throw new Error("scope:semgrep.too_many_findings");
}
function toShared(list4) {
  return list4.filter((f) => OPEN2.has((f.state ?? "unresolved").toLowerCase())).map((f) => ({
    ref: f.rule_name ?? (f.id !== void 0 ? `finding ${f.id}` : "a finding"),
    severity: severityOf(f.severity),
    openedAt: f.created_at
  }));
}
async function projects3(ctx) {
  const { api, slug } = need3(ctx);
  const r = await api.get(`/api/v1/deployments/${slug}/projects`);
  const body = r.json;
  return Array.isArray(body?.projects) ? body.projects : null;
}
var noCritical3 = {
  code: "semgrep.findings.no_critical",
  provider: "semgrep",
  version: 3,
  severity: "critical",
  maps: ["soc2:CC7.1", "soc2:CC8.1", "iso:8.28", "iso:8.8", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.semgrep.findings", async () => {
    const list4 = await findings2(ctx);
    return list4 === null ? unknown("api.shape.findings") : judgeNoCritical(list4);
  })
};
var withinWindow3 = {
  code: "semgrep.findings.within_window",
  provider: "semgrep",
  version: 3,
  severity: "high",
  maps: ["soc2:CC7.1", "soc2:CC7.4", "iso:8.28", "iso:8.8", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.semgrep.findings", async () => {
    const list4 = await findings2(ctx);
    return list4 === null ? unknown("api.shape.findings") : judgeWithinWindow(list4, ctx.now ?? /* @__PURE__ */ new Date());
  })
};
var noAncient3 = {
  code: "semgrep.findings.no_ancient",
  provider: "semgrep",
  version: 3,
  severity: "medium",
  maps: ["soc2:CC7.1", "iso:8.28", "iso:5.25", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.semgrep.findings", async () => {
    const list4 = await findings2(ctx);
    return list4 === null ? unknown("api.shape.findings") : judgeNoAncient(list4, ctx.now ?? /* @__PURE__ */ new Date());
  })
};
var scanningFresh2 = {
  code: "semgrep.projects.scanned_recently",
  provider: "semgrep",
  version: 3,
  severity: "high",
  maps: ["soc2:CC7.1", "iso:8.28", "iso:8.8", "nist-csf:DE.CM"],
  run: (ctx) => guarded("api.semgrep.projects", async () => {
    const list4 = await projects3(ctx);
    if (list4 === null) return unknown("api.shape.projects");
    if (list4.length === 0) return unknown("api.semgrep.no_projects");
    const dated = list4.map((p) => p.latest_scan_at).filter((d) => typeof d === "string");
    if (dated.length === 0) return unknown(list4.every((p) => "latest_scan_at" in p) ? "api.no_completed_scan" : "api.shape.latest_scan_at");
    const oldest = dated.reduce((a, b) => Date.parse(a) < Date.parse(b) ? a : b);
    const stalest = list4.find((p) => p.latest_scan_at === oldest);
    const r = judgeScanFresh(oldest, ctx.now ?? /* @__PURE__ */ new Date(), stalest?.name ?? "a project");
    return { ...r, observed: { ...r.observed, projects: list4.length } };
  })
};
var SEMGREP_CHECKS = [noCritical3, withinWindow3, scanningFresh2, noAncient3];
var BASE3 = "https://semgrep.dev";
var UA4 = "snoopios-check/1 (+https://snoopios.com)";
var SEMGREP_SLUG = /^[a-z0-9][a-z0-9_-]{0,62}$/i;
function semgrepApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`${BASE3}${path}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json", "user-agent": UA4 },
        signal: AbortSignal.timeout(3e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403) throw new Error("scope:semgrep.forbidden");
      const json = await res.json().catch(() => null);
      return { status: res.status, json };
    }
  };
}
async function runSemgrepChecks(ctx) {
  const out = [];
  for (const c of SEMGREP_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/aikido.ts
var need4 = (ctx) => {
  if (!ctx.api) throw new Error("scope:aikido.unconfigured");
  return ctx.api;
};
var OPEN3 = /* @__PURE__ */ new Set(["open", "unresolved", "snoozed_expired"]);
function detectedAt(value) {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return new Date(value * 1e3).toISOString();
  }
  if (typeof value === "string" && value.trim() && Number.isFinite(Date.parse(value))) return value;
  return void 0;
}
async function findings3(ctx) {
  const repos = await need4(ctx).get("/api/public/v1/repositories/code");
  if (repos.status === 403) throw new Error("scope:scope.repositories_read");
  if (repos.status !== 200 || !Array.isArray(repos.json)) throw new Error("scope:api.repositories");
  if (repos.json.length === 0) throw new Error("scope:api.no_repositories");
  const r = await need4(ctx).get("/api/public/v1/issues/export?format=json&filter_status=open");
  const list4 = Array.isArray(r.json) ? r.json : null;
  if (list4 === null) return null;
  return list4.filter((i) => OPEN3.has((i.status ?? "open").toLowerCase())).map((i) => ({
    // Dependency issues carry no rule; the package is what a reader looks for.
    // On 12 Oct 2026 the first real run labelled a critical lodash finding
    // only as "open_source".
    ref: i.rule ?? (i.affected_package ? `${i.affected_package} (${i.type ?? "dependency"})` : void 0) ?? i.type ?? (i.id !== void 0 ? `issue ${i.id}` : "an issue"),
    severity: severityOf(i.severity),
    openedAt: detectedAt(i.first_detected_at)
  }));
}
var noCritical4 = {
  code: "aikido.issues.no_critical",
  provider: "aikido",
  version: 2,
  severity: "critical",
  maps: ["soc2:CC7.1", "iso:8.8", "iso:8.28", "ce:patching", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.aikido.issues", async () => {
    const list4 = await findings3(ctx);
    return list4 === null ? unknown("api.shape.issues") : judgeNoCritical(list4);
  })
};
var withinWindow4 = {
  code: "aikido.issues.within_window",
  provider: "aikido",
  version: 2,
  severity: "high",
  maps: ["soc2:CC7.1", "soc2:CC7.4", "iso:8.8", "ce:patching", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.aikido.issues", async () => {
    const list4 = await findings3(ctx);
    return list4 === null ? unknown("api.shape.issues") : judgeWithinWindow(list4, ctx.now ?? /* @__PURE__ */ new Date());
  })
};
var noAncient4 = {
  code: "aikido.issues.no_ancient",
  provider: "aikido",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC7.1", "iso:8.8", "iso:5.25", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.aikido.issues", async () => {
    const list4 = await findings3(ctx);
    return list4 === null ? unknown("api.shape.issues") : judgeNoAncient(list4, ctx.now ?? /* @__PURE__ */ new Date());
  })
};
var AIKIDO_CHECKS = [noCritical4, withinWindow4, noAncient4];
var BASE4 = "https://app.aikido.dev";
var UA5 = "snoopios-check/1 (+https://snoopios.com)";
async function aikidoAccessToken(clientId, clientSecret, fetchImpl = readOnlyFetch) {
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  const res = await fetchImpl(`${BASE4}/api/oauth/token`, {
    method: "POST",
    headers: { authorization: `Basic ${basic}`, "content-type": "application/json", "user-agent": UA5 },
    body: JSON.stringify({ grant_type: "client_credentials" }),
    signal: AbortSignal.timeout(2e4)
  });
  if (!res.ok) throw new Error("scope:auth");
  const body = await res.json().catch(() => null);
  if (!body?.access_token) throw new Error("scope:auth");
  return body.access_token;
}
function aikidoApi(accessToken, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`${BASE4}${path}`, {
        headers: { authorization: `Bearer ${accessToken}`, accept: "application/json", "user-agent": UA5 },
        signal: AbortSignal.timeout(3e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403) throw new Error("scope:aikido.forbidden");
      const json = await res.json().catch(() => null);
      return { status: res.status, json };
    }
  };
}
async function aikidoContext(clientId, clientSecret) {
  return { api: aikidoApi(await aikidoAccessToken(clientId, clientSecret)) };
}
async function runAikidoChecks(ctx) {
  const out = [];
  for (const c of AIKIDO_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/bitwarden.ts
var need5 = (ctx) => {
  if (!ctx.api) throw new Error("scope:bitwarden.unconfigured");
  return ctx.api;
};
var POLICY_TWO_FACTOR = 0;
var POLICY_MASTER_PASSWORD = 1;
var POLICY_PERSONAL_OWNERSHIP = 5;
var POLICY_VAULT_TIMEOUT = 9;
var STATUS_REVOKED = -1;
var STATUS_CONFIRMED = 2;
async function list3(ctx, path) {
  const r = await need5(ctx).get(path);
  const body = r.json;
  return Array.isArray(body?.data) ? body.data : null;
}
var active2 = (members) => members.filter((m) => m.status === STATUS_CONFIRMED);
var nameOf = (m) => m.email ?? m.name ?? m.id ?? "a member";
var policyOn = (policies, type) => policies.some((p) => p.type === type && p.enabled === true);
var membersTwoFactor = {
  code: "bitwarden.members.two_factor",
  provider: "bitwarden",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC6.1", "soc2:CC6.6", "iso:5.17", "iso:8.5", "ce:user-access", "gdpr:art32", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.bitwarden.members", async () => {
    const members = await list3(ctx, "/public/members");
    if (members === null) return unknown("api.shape.members");
    const confirmed = active2(members);
    if (confirmed.length === 0) return unknown("api.bitwarden.no_members");
    if (shapeMismatch(confirmed, (m) => [m.twoFactorEnabled])) return unknown("api.shape.twoFactorEnabled");
    const without = confirmed.filter((m) => m.twoFactorEnabled !== true).map(nameOf);
    const observed = { members: confirmed.length, withoutSecondFactor: without.length, accounts: without.slice(0, 10) };
    return without.length === 0 ? pass(observed, confirmed.length) : fail(observed, confirmed.length);
  })
};
var policyTwoFactor = {
  code: "bitwarden.policy.two_factor",
  provider: "bitwarden",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:5.17", "iso:8.5", "ce:user-access", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.bitwarden.policies", async () => {
    const policies = await list3(ctx, "/public/policies");
    if (policies === null) return unknown("api.shape.policies");
    const on = policyOn(policies, POLICY_TWO_FACTOR);
    const observed = { policies: policies.length, requiresSecondFactor: on };
    return on ? pass(observed, policies) : fail(observed, policies);
  })
};
var policyPersonalOwnership = {
  code: "bitwarden.policy.organisation_ownership",
  provider: "bitwarden",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "soc2:CC6.2", "iso:5.10", "iso:5.17", "iso:8.12", "nist-csf:PR.DS"],
  run: (ctx) => guarded("api.bitwarden.policies", async () => {
    const policies = await list3(ctx, "/public/policies");
    if (policies === null) return unknown("api.shape.policies");
    const on = policyOn(policies, POLICY_PERSONAL_OWNERSHIP);
    const observed = { policies: policies.length, itemsOwnedByTheOrganisation: on };
    return on ? pass(observed, policies) : fail(observed, policies);
  })
};
var policyMasterPassword = {
  code: "bitwarden.policy.master_password",
  provider: "bitwarden",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:5.17", "ce:user-access", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.bitwarden.policies", async () => {
    const policies = await list3(ctx, "/public/policies");
    if (policies === null) return unknown("api.shape.policies");
    const on = policyOn(policies, POLICY_MASTER_PASSWORD);
    const observed = { policies: policies.length, masterPasswordRules: on };
    return on ? pass(observed, policies) : fail(observed, policies);
  })
};
var policyVaultTimeout = {
  code: "bitwarden.policy.vault_timeout",
  provider: "bitwarden",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.1", "iso:7.7", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.bitwarden.policies", async () => {
    const policies = await list3(ctx, "/public/policies");
    if (policies === null) return unknown("api.shape.policies");
    const on = policyOn(policies, POLICY_VAULT_TIMEOUT);
    const observed = { policies: policies.length, vaultLocks: on };
    return on ? pass(observed, policies) : fail(observed, policies);
  })
};
var noBlanketAccess = {
  code: "bitwarden.members.least_privilege",
  provider: "bitwarden",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.1", "soc2:CC6.3", "iso:5.15", "iso:5.18", "ce:user-access", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.bitwarden.members", async () => {
    const members = await list3(ctx, "/public/members");
    if (members === null) return unknown("api.shape.members");
    const confirmed = active2(members);
    if (confirmed.length === 0) return unknown("api.bitwarden.no_members");
    const users = confirmed.filter((m) => m.type !== 0 && m.type !== 1);
    if (users.length === 0) return unknown("api.bitwarden.only_admins");
    if (shapeMismatch(users, (m) => [m.collections])) return unknown("api.shape.collections");
    const all = await list3(ctx, "/public/collections");
    if (all === null) return unknown("api.shape.collections");
    if (all.length < 2) return unknown("api.bitwarden.no_collection_structure", { collections: all.length });
    const ids = new Set(all.map((c) => c.id).filter(Boolean));
    const seesAll = (m) => m.accessAll === true || m.permissions?.editAnyCollection === true || [...ids].every((id) => (m.collections ?? []).some((c) => c.id === id));
    const blanket = users.filter(seesAll).map(nameOf);
    const observed = { members: confirmed.length, nonAdmins: users.length, seeEveryCollection: blanket.length, accounts: blanket.slice(0, 10) };
    return blanket.length === 0 ? pass(observed, users.length) : fail(observed, users.length);
  })
};
var noStaleInvites = {
  code: "bitwarden.members.no_stale_invites",
  provider: "bitwarden",
  version: 1,
  severity: "low",
  maps: ["soc2:CC6.2", "iso:5.16", "iso:5.18", "ce:user-access", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.bitwarden.members", async () => {
    const members = await list3(ctx, "/public/members");
    if (members === null) return unknown("api.shape.members");
    if (members.length === 0) return unknown("api.bitwarden.no_members");
    const pending = members.filter((m) => m.status === 0 || m.status === 1).map(nameOf);
    const revoked = members.filter((m) => m.status === STATUS_REVOKED).length;
    const observed = { members: members.length, notFinishedJoining: pending.length, revoked, accounts: pending.slice(0, 10) };
    return pending.length === 0 ? pass(observed, members.length) : fail(observed, members.length);
  })
};
var BITWARDEN_CHECKS = [
  membersTwoFactor,
  policyTwoFactor,
  policyPersonalOwnership,
  noBlanketAccess,
  policyMasterPassword,
  policyVaultTimeout,
  noStaleInvites
];
var BITWARDEN_REGIONS = { com: "bitwarden.com", eu: "bitwarden.eu" };
var identityUrl = (r) => `https://identity.${BITWARDEN_REGIONS[r]}/connect/token`;
var baseUrl = (r) => `https://api.${BITWARDEN_REGIONS[r]}`;
var UA6 = "snoopios-check/1 (+https://snoopios.com)";
async function bitwardenAccessToken(clientId, clientSecret, fetchImpl = readOnlyFetch, region = "com") {
  const res = await fetchImpl(identityUrl(region), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": UA6 },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "api.organization",
      client_id: clientId,
      client_secret: clientSecret
    }).toString(),
    signal: AbortSignal.timeout(2e4)
  });
  if (!res.ok) throw new Error("scope:auth");
  const body = await res.json().catch(() => null);
  if (!body?.access_token) throw new Error("scope:auth");
  return body.access_token;
}
function bitwardenApi(accessToken, fetchImpl = readOnlyFetch, region = "com") {
  return {
    async get(path) {
      const res = await fetchImpl(`${baseUrl(region)}${path}`, {
        headers: { authorization: `Bearer ${accessToken}`, accept: "application/json", "user-agent": UA6 },
        signal: AbortSignal.timeout(2e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403) throw new Error("scope:bitwarden.forbidden");
      const json = await res.json().catch(() => null);
      return { status: res.status, json };
    }
  };
}
async function bitwardenContext(clientId, clientSecret, region = "com") {
  return { api: bitwardenApi(await bitwardenAccessToken(clientId, clientSecret, readOnlyFetch, region), readOnlyFetch, region) };
}
async function runBitwardenChecks(ctx) {
  const out = [];
  for (const c of BITWARDEN_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/onepassword.ts
var WINDOW_DAYS = 30;
var FAILURE_LIMIT = 10;
var need6 = (ctx) => {
  if (!ctx.api) throw new Error("scope:onepassword.unconfigured");
  return ctx.api;
};
var MAX_PAGES6 = 20;
var PER_PAGE4 = 1e3;
var SECOND_FACTOR = /* @__PURE__ */ new Set(["mfa_ok", "sso_ok", "duo_ok"]);
async function page(ctx, feature, since2) {
  const api = need6(ctx);
  const out = [];
  let body = { limit: PER_PAGE4, start_time: since2.toISOString() };
  for (let i = 0; i < MAX_PAGES6; i++) {
    const res = await api.events(feature, body);
    if (!res || !Array.isArray(res.items)) return out.length > 0 ? out : null;
    out.push(...res.items);
    if (!res.has_more || !res.cursor) return out;
    body = { cursor: res.cursor };
  }
  throw new Error("scope:onepassword.too_many_events");
}
var since = (ctx) => new Date((ctx.now ?? /* @__PURE__ */ new Date()).getTime() - WINDOW_DAYS * 864e5);
var who = (s) => s.target_user?.email ?? s.target_user?.name ?? s.target_user?.uuid ?? "an account";
var secondFactorUsed = {
  code: "onepassword.signins.second_factor",
  provider: "onepassword",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC6.1", "soc2:CC6.6", "iso:5.17", "iso:8.5", "ce:user-access", "gdpr:art32", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.onepassword.signins", async () => {
    const events = await page(ctx, "signinattempts", since(ctx));
    if (events === null) return unknown("api.shape.signinattempts");
    const successes = events.filter((e) => (e.category ?? "") === "success");
    if (successes.length === 0) return unknown("api.onepassword.no_signins");
    const without = [...new Set(successes.filter((e) => !SECOND_FACTOR.has(e.type ?? "")).map(who))];
    const observed = { windowDays: WINDOW_DAYS, successfulSignIns: successes.length, withoutSecondFactor: without.length, accounts: without.slice(0, 10) };
    return without.length === 0 ? pass(observed, successes.length) : fail(observed, successes.length);
  })
};
var noRepeatedFailures = {
  code: "onepassword.signins.no_repeated_failures",
  provider: "onepassword",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.2", "soc2:CC6.1", "iso:8.15", "iso:8.16", "nist-csf:DE.CM"],
  run: (ctx) => guarded("api.onepassword.signins", async () => {
    const events = await page(ctx, "signinattempts", since(ctx));
    if (events === null) return unknown("api.shape.signinattempts");
    if (events.length === 0) return unknown("api.onepassword.no_signins");
    const failures = /* @__PURE__ */ new Map();
    for (const e of events) {
      if ((e.category ?? "") === "success" || (e.category ?? "") === "firewall_reported_success") continue;
      const key = who(e);
      failures.set(key, (failures.get(key) ?? 0) + 1);
    }
    const noisy = [...failures.entries()].filter(([, n]) => n > FAILURE_LIMIT).map(([k, n]) => `${k} (${n} failures)`);
    const observed = { windowDays: WINDOW_DAYS, events: events.length, limit: FAILURE_LIMIT, accounts: noisy.length, detail: noisy.slice(0, 10) };
    return noisy.length === 0 ? pass(observed, events.length) : fail(observed, events.length);
  })
};
var auditLogFlowing = {
  code: "onepassword.audit.log_available",
  provider: "onepassword",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.2", "iso:8.15", "iso:5.28", "nist-csf:DE.CM"],
  run: (ctx) => guarded("api.onepassword.auditevents", async () => {
    const events = await page(ctx, "auditevents", since(ctx));
    if (events === null) return unknown("api.shape.auditevents");
    const dated = events.filter((e) => typeof e.timestamp === "string").length;
    const actions = [...new Set(events.map((e) => e.action).filter(Boolean))].slice(0, 10);
    const observed = { windowDays: WINDOW_DAYS, events: events.length, dated, actions };
    return events.length > 0 && dated > 0 ? pass(observed, events.length) : fail(observed, events.length);
  })
};
var ONEPASSWORD_CHECKS = [secondFactorUsed, noRepeatedFailures, auditLogFlowing];
var UA7 = "snoopios-check/1 (+https://snoopios.com)";
var HOSTS = {
  com: "https://events.1password.com",
  ca: "https://events.1password.ca",
  eu: "https://events.1password.eu",
  ent: "https://events.ent.1password.com"
};
function onePasswordApi(token, region = "com", fetchImpl = readOnlyFetch) {
  const base = HOSTS[region];
  if (!base) throw new Error("scope:onepassword.region");
  return {
    async events(feature, body) {
      const res = await fetchImpl(`${base}/api/v2/${feature}`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "user-agent": UA7 },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(3e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403) throw new Error("scope:onepassword.forbidden");
      return res.json().catch(() => null);
    }
  };
}
async function runOnePasswordChecks(ctx) {
  const out = [];
  for (const c of ONEPASSWORD_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/doppler.ts
var ROTATION_DAYS = 365;
var need7 = (ctx) => {
  if (!ctx.api) throw new Error("scope:doppler.unconfigured");
  return ctx.api;
};
var MAX_PAGES7 = 10;
async function projects4(ctx) {
  const out = [];
  for (let page2 = 1; page2 <= MAX_PAGES7; page2++) {
    const r = await need7(ctx).get(`/v3/projects?page=${page2}&per_page=100`);
    const body = r.json;
    if (!body || !Array.isArray(body.projects)) return out.length > 0 ? out : null;
    out.push(...body.projects);
    if (body.projects.length < 100) return out;
  }
  return out;
}
async function configs(ctx, project2) {
  const r = await need7(ctx).get(`/v3/configs?project=${encodeURIComponent(project2)}`);
  const body = r.json;
  return Array.isArray(body?.configs) ? body.configs : [];
}
async function serviceTokens(ctx) {
  const list4 = await projects4(ctx);
  if (list4 === null) return null;
  const out = [];
  for (const p of list4) {
    const slug = p.slug ?? p.name;
    if (!slug) continue;
    for (const c of await configs(ctx, slug)) {
      if (!c.name) continue;
      const r = await need7(ctx).get(`/v3/configs/config/tokens?project=${encodeURIComponent(slug)}&config=${encodeURIComponent(c.name)}`);
      const body = r.json;
      if (!Array.isArray(body?.tokens)) continue;
      for (const t of body.tokens) out.push({ ...t, project: slug, config: c.name });
    }
  }
  return out;
}
var nameOf2 = (t) => `${t.project ?? "?"}/${t.config ?? "?"}: ${t.name ?? t.slug ?? "an unnamed token"}`;
var tokensReadOnly = {
  code: "doppler.tokens.read_only",
  provider: "doppler",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "soc2:CC6.3", "iso:5.15", "iso:5.17", "iso:8.2", "ce:user-access", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.doppler.tokens", async () => {
    const tokens = await serviceTokens(ctx);
    if (tokens === null) return unknown("api.shape.projects");
    if (tokens.length === 0) return unknown("api.doppler.no_tokens");
    if (shapeMismatch(tokens, (t) => [t.access])) return unknown("api.shape.access");
    const writable = tokens.filter((t) => (t.access ?? "").toLowerCase() !== "read").map(nameOf2);
    const observed = { tokens: tokens.length, canWrite: writable.length, names: writable.slice(0, 10) };
    return writable.length === 0 ? pass(observed, tokens.length) : fail(observed, tokens.length);
  })
};
var tokensRotated = {
  code: "doppler.tokens.rotated",
  provider: "doppler",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:5.17", "iso:8.24", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.doppler.tokens", async () => {
    const tokens = await serviceTokens(ctx);
    if (tokens === null) return unknown("api.shape.projects");
    if (tokens.length === 0) return unknown("api.doppler.no_tokens");
    if (shapeMismatch(tokens, (t) => [t.created_at])) return unknown("api.shape.created_at");
    const cutoff = (ctx.now ?? /* @__PURE__ */ new Date()).getTime() - ROTATION_DAYS * 864e5;
    const old = tokens.filter((t) => !t.created_at || Date.parse(t.created_at) < cutoff).map((t) => `${nameOf2(t)} (created ${(t.created_at ?? "date unknown").slice(0, 10)})`);
    const observed = { tokens: tokens.length, withinDays: ROTATION_DAYS, overdue: old.length, names: old.slice(0, 10) };
    return old.length === 0 ? pass(observed, tokens.length) : fail(observed, tokens.length);
  })
};
var tokensNotRoot = {
  code: "doppler.tokens.not_root_config",
  provider: "doppler",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "soc2:CC6.3", "iso:5.15", "iso:8.31", "nist-csf:PR.AA"],
  run: (ctx) => guarded("api.doppler.tokens", async () => {
    const tokens = await serviceTokens(ctx);
    if (tokens === null) return unknown("api.shape.projects");
    if (tokens.length === 0) return unknown("api.doppler.no_tokens");
    const roots = /* @__PURE__ */ new Set();
    for (const p of await projects4(ctx) ?? []) {
      const slug = p.slug ?? p.name;
      if (!slug) continue;
      for (const c of await configs(ctx, slug)) if (c.root === true && c.name) roots.add(`${slug}/${c.name}`);
    }
    if (roots.size === 0) return unknown("api.shape.root");
    const wide = tokens.filter((t) => roots.has(`${t.project}/${t.config}`)).map(nameOf2);
    const observed = { tokens: tokens.length, rootConfigs: roots.size, onARootConfig: wide.length, names: wide.slice(0, 10) };
    return wide.length === 0 ? pass(observed, tokens.length) : fail(observed, tokens.length);
  })
};
var DOPPLER_CHECKS = [tokensReadOnly, tokensNotRoot, tokensRotated];
var BASE5 = "https://api.doppler.com";
var UA8 = "snoopios-check/1 (+https://snoopios.com)";
function dopplerApi(token, fetchImpl = readOnlyFetch) {
  return {
    async get(path) {
      const res = await fetchImpl(`${BASE5}${path}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json", "user-agent": UA8 },
        signal: AbortSignal.timeout(2e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403) throw new Error(token.startsWith("dp.st.") ? "scope:doppler.service_token_given" : "scope:doppler.forbidden");
      const json = await res.json().catch(() => null);
      return { status: res.status, json };
    }
  };
}
async function runDopplerChecks(ctx) {
  const out = [];
  for (const c of DOPPLER_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/sonarqube.ts
var need8 = (ctx) => {
  if (!ctx.api || !ctx.projectKey) throw new Error("scope:sonarqube.unconfigured");
  return { api: ctx.api, projectKey: ctx.projectKey };
};
async function gate(ctx) {
  const { api, projectKey } = need8(ctx);
  const r = await api.get(`/api/qualitygates/project_status?projectKey=${encodeURIComponent(projectKey)}`);
  const body = r.json;
  return body?.projectStatus ?? null;
}
async function project(ctx) {
  const { api, projectKey } = need8(ctx);
  const r = await api.get(`/api/components/show?component=${encodeURIComponent(projectKey)}`);
  const body = r.json;
  return body?.component ?? null;
}
async function measures(ctx, metrics) {
  const { api, projectKey } = need8(ctx);
  const r = await api.get(`/api/measures/component?component=${encodeURIComponent(projectKey)}&metricKeys=${metrics.join(",")}`);
  const body = r.json;
  if (!body?.component) return null;
  const info = await project(ctx);
  return { measures: body.component.measures ?? [], analysedAt: info?.analysisDate ?? body.period?.date };
}
async function attachedGate(ctx) {
  const { api, projectKey } = need8(ctx);
  const info = await project(ctx);
  const org = info?.organization ? `&organization=${encodeURIComponent(info.organization)}` : "";
  const r = await api.get(`/api/qualitygates/get_by_project?project=${encodeURIComponent(projectKey)}${org}`);
  const g = r.json?.qualityGate;
  if (!g?.id) return null;
  const d = await api.get(`/api/qualitygates/show?id=${encodeURIComponent(String(g.id))}${org}`);
  const def = d.json;
  if (!def) return null;
  return { name: def.name ?? g.name ?? "gate", conditions: (def.conditions ?? []).length };
}
var metric = (list4, key) => list4.find((m) => m.metric === key)?.value;
var gatePasses = {
  code: "sonarqube.gate.passing",
  provider: "sonarqube",
  version: 2,
  severity: "high",
  maps: ["soc2:CC8.1", "soc2:CC7.1", "iso:8.32", "iso:8.28", "nist-csf:PR.PS"],
  run: (ctx) => guarded("api.sonarqube.gate", async () => {
    const status = await gate(ctx);
    if (!status?.status) return unknown("api.shape.projectStatus");
    const value = status.status.toUpperCase();
    if (value === "NONE") return unknown("api.gate_not_evaluated");
    const failing = (status.conditions ?? []).filter((c) => (c.status ?? "").toUpperCase() === "ERROR").map((c) => `${c.metricKey ?? "a condition"} is ${c.actualValue ?? "?"} against a limit of ${c.errorThreshold ?? "?"}`);
    const observed = { gate: value, conditions: (status.conditions ?? []).length, failing: failing.slice(0, 10) };
    return value === "OK" ? pass(observed, status) : fail(observed, status);
  })
};
var gateHasConditions = {
  code: "sonarqube.gate.has_conditions",
  provider: "sonarqube",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC8.1", "iso:8.32", "iso:8.28", "nist-csf:PR.PS"],
  run: (ctx) => guarded("api.sonarqube.gate", async () => {
    const attached = await attachedGate(ctx);
    if (attached === null) return unknown("api.shape.qualityGate");
    const observed = { gate: attached.name, conditions: attached.conditions };
    return attached.conditions > 0 ? pass(observed, attached) : fail(observed, attached);
  })
};
var analysedRecently = {
  code: "sonarqube.project.analysed_recently",
  provider: "sonarqube",
  version: 2,
  severity: "medium",
  maps: ["soc2:CC8.1", "iso:8.28", "iso:8.8", "nist-csf:DE.CM"],
  run: (ctx) => guarded("api.sonarqube.measures", async () => {
    const res = await measures(ctx, ["ncloc", "reliability_rating", "security_rating"]);
    if (res === null) return unknown("api.shape.component");
    if (!res.analysedAt) return unknown("api.sonarqube.no_analysis_date");
    const age = Math.floor(((ctx.now ?? /* @__PURE__ */ new Date()).getTime() - Date.parse(res.analysedAt)) / 864e5);
    if (!Number.isFinite(age)) return unknown("api.shape.period");
    const observed = {
      lastAnalysis: res.analysedAt.slice(0, 10),
      daysAgo: age,
      withinDays: SCAN_DAYS,
      linesOfCode: metric(res.measures, "ncloc") ?? "unknown"
    };
    return age <= SCAN_DAYS ? pass(observed, res) : fail(observed, res);
  })
};
var securityRating = {
  code: "sonarqube.project.security_rating",
  provider: "sonarqube",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.1", "iso:8.28", "iso:8.8", "nist-csf:ID.RA"],
  run: (ctx) => guarded("api.sonarqube.measures", async () => {
    const res = await measures(ctx, ["security_rating", "reliability_rating"]);
    if (res === null) return unknown("api.shape.component");
    const raw = metric(res.measures, "security_rating");
    if (!raw) return unknown("api.shape.security_rating");
    const grade = ["", "A", "B", "C", "D", "E"][Math.round(Number(raw))] ?? "unknown";
    const observed = { securityRating: grade, reliabilityRating: ["", "A", "B", "C", "D", "E"][Math.round(Number(metric(res.measures, "reliability_rating") ?? 0))] ?? "unknown" };
    if (grade === "unknown") return unknown("api.shape.security_rating");
    return grade === "A" ? pass(observed, res) : fail(observed, res);
  })
};
var SONARQUBE_CHECKS = [gatePasses, gateHasConditions, analysedRecently, securityRating];
var UA9 = "snoopios-check/1 (+https://snoopios.com)";
function sonarBase(raw) {
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error("scope:sonarqube.url");
  }
  if (url.protocol !== "https:") throw new Error("scope:sonarqube.url");
  if (url.username || url.password) throw new Error("scope:sonarqube.url");
  if (url.search || url.hash) throw new Error("scope:sonarqube.url");
  if (url.pathname !== "/" && url.pathname !== "") throw new Error("scope:sonarqube.url");
  return url.origin;
}
function sonarApi(baseUrl2, token, fetchImpl = readOnlyFetch) {
  const base = sonarBase(baseUrl2);
  const basic = Buffer.from(`${token}:`).toString("base64");
  return {
    async get(path) {
      const res = await fetchImpl(`${base}${path}`, {
        headers: { authorization: `Basic ${basic}`, accept: "application/json", "user-agent": UA9 },
        signal: AbortSignal.timeout(2e4)
      });
      if (res.status === 401) throw new Error("scope:auth");
      if (res.status === 403) throw new Error("scope:sonarqube.forbidden");
      const json = await res.json().catch(() => null);
      return { status: res.status, json };
    }
  };
}
async function runSonarChecks(ctx) {
  const out = [];
  for (const c of SONARQUBE_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/supabase.ts
var SECRET_KEY2 = /(secret|smtp_pass|_token|api_key|password)/i;
function scrubAuthConfig(cfg) {
  const out = {};
  for (const [k, v] of Object.entries(cfg)) {
    out[k] = SECRET_KEY2.test(k) ? v ? "[redacted]" : null : v;
  }
  return out;
}
var rlsAllTables = {
  code: "supabase.rls.all_tables",
  provider: "supabase",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.3", "iso:5.15"],
  run: (ctx) => guarded("sql.catalogue", async () => {
    if (!ctx.sql) return unknown("sql.not_connected");
    const rows2 = await ctx.sql.query(`
        select c.relname as table_name, c.relrowsecurity as rls_enabled,
               (select count(*) from pg_catalog.pg_policies p
                 where p.schemaname = 'public' and p.tablename = c.relname) as policy_count
        from pg_catalog.pg_class c
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind in ('r', 'p')
        order by c.relname`);
    const off = rows2.filter((r) => r.rls_enabled === false).map((r) => String(r.table_name));
    const observed = { tables: rows2.length, rlsOff: off };
    return off.length === 0 ? pass(observed, rows2) : fail(observed, rows2);
  })
};
var noAnonWritePolicy = {
  code: "supabase.rls.no_anon_write",
  provider: "supabase",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.3"],
  run: (ctx) => guarded("sql.catalogue", async () => {
    if (!ctx.sql) return unknown("sql.not_connected");
    const rows2 = await ctx.sql.query(`
        select tablename, policyname, roles::text as roles, cmd
        from pg_catalog.pg_policies
        where schemaname = 'public'
          and cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')
          and (roles::text like '%anon%' or roles::text like '%public%')
        order by tablename, policyname`);
    const observed = { openPolicies: rows2.map((r) => `${r.tablename}.${r.policyname} (${r.cmd})`) };
    return rows2.length === 0 ? pass(observed, rows2) : fail(observed, rows2);
  })
};
var privateSchemaClosed = {
  code: "supabase.private.closed",
  provider: "supabase",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.2", "iso:8.3"],
  run: (ctx) => guarded("sql.catalogue", async () => {
    if (!ctx.sql) return unknown("sql.not_connected");
    const rows2 = await ctx.sql.query(`
        select n.nspname as schema,
               pg_catalog.has_schema_privilege('anon', n.nspname, 'usage') as anon_usage,
               pg_catalog.has_schema_privilege('authenticated', n.nspname, 'usage') as auth_usage
        from pg_catalog.pg_namespace n
        where n.nspname = 'private'`);
    if (rows2.length === 0) return pass({ privateSchema: false }, rows2);
    const r = rows2[0];
    const observed = { privateSchema: true, anonUsage: r.anon_usage, authUsage: r.auth_usage };
    return !r.anon_usage && !r.auth_usage ? pass(observed, rows2) : fail(observed, rows2);
  })
};
var MANAGED_SCHEMAS = [
  "information_schema",
  "auth",
  "storage",
  "realtime",
  "supabase_functions",
  "supabase_migrations",
  "extensions",
  "graphql",
  "graphql_public",
  "pgbouncer",
  "vault",
  "cron",
  "net",
  "pgsodium",
  "pgsodium_masks",
  "_analytics",
  "_realtime",
  "_supavisor"
];
var definerSearchPath = {
  code: "supabase.definer.search_path",
  provider: "supabase",
  // v2 (14 Sep 2026): v1 looked only in `public` and `private`. A SECURITY
  // DEFINER function in any other schema the customer created was invisible,
  // and the search_path attack does not care which schema the function lives
  // in — only that a caller can put a schema in front of it. Supabase's own
  // lint 0011 covers every non-managed schema, so v1 could pass a project the
  // dashboard was already failing. Now every schema is read except the ones
  // Supabase owns.
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.28", "iso:8.2"],
  run: (ctx) => guarded("sql.catalogue", async () => {
    if (!ctx.sql) return unknown("sql.not_connected");
    const excluded = MANAGED_SCHEMAS.map((x) => `'${x}'`).join(", ");
    const rows2 = await ctx.sql.query(`
        select n.nspname as schema, p.proname as name,
               coalesce(pg_catalog.array_to_string(p.proconfig, ','), '') as config
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where p.prosecdef
          and n.nspname not in (${excluded})
          and n.nspname not like 'pg_%'
        order by n.nspname, p.proname`);
    const unpinned = rows2.filter((r) => !String(r.config).includes("search_path")).map((r) => `${r.schema}.${r.name}`);
    const observed = { definerFunctions: rows2.length, unpinned };
    return unpinned.length === 0 ? pass(observed, rows2) : fail(observed, rows2);
  })
};
var viewsSecurityInvoker = {
  code: "supabase.views.security_invoker",
  provider: "supabase",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.3", "iso:5.15"],
  run: (ctx) => guarded("sql.catalogue", async () => {
    if (!ctx.sql) return unknown("sql.not_connected");
    const rows2 = await ctx.sql.query(`
        select c.relname as name, c.relkind::text as kind,
               coalesce(pg_catalog.array_to_string(c.reloptions, ','), '') as options,
               current_setting('server_version_num')::int as server_version
        from pg_catalog.pg_class c
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind in ('v', 'm', 'f')
        order by c.relname`);
    if (rows2.length === 0) return pass({ views: 0, materialised: 0, foreign: 0 }, rows2);
    const version = Number(rows2[0]?.server_version ?? 0);
    if (version > 0 && version < 15e4) return unknown("sql.server_version_below_15", { serverVersion: version });
    const views = rows2.filter((r) => r.kind === "v");
    const definer = views.filter((r) => !/security_invoker\s*=\s*(on|true)/i.test(String(r.options))).map((r) => String(r.name));
    const observed = {
      views: views.length,
      definerViews: definer,
      materialised: rows2.filter((r) => r.kind === "m").map((r) => String(r.name)),
      foreign: rows2.filter((r) => r.kind === "f").map((r) => String(r.name))
    };
    return definer.length === 0 ? pass(observed, rows2) : fail(observed, rows2);
  })
};
var noAnonCallableFunctions = {
  code: "supabase.functions.anon_callable",
  provider: "supabase",
  // v2 (6 Sep 2026): v1 failed on ANY anon-callable SECURITY DEFINER function
  // and fired on Snoopios's own trust_page(), which is exactly the legitimate
  // shape — a narrow public read through a definer. The dangerous case is a
  // definer that anon can call AND that has no pinned search_path, or that
  // takes a caller-supplied identity. v2 lists every anon-callable definer for
  // review and fails only on the first of those two, which the catalogue can
  // see. Dogfood rule: fix the check, not the stack.
  version: 2,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.3", "iso:8.2"],
  run: (ctx) => guarded("sql.catalogue", async () => {
    if (!ctx.sql) return unknown("sql.not_connected");
    const rows2 = await ctx.sql.query(`
        select p.proname as name,
               pg_catalog.has_function_privilege('anon', p.oid, 'execute') as anon_exec,
               p.prosecdef as definer,
               coalesce(pg_catalog.array_to_string(p.proconfig, ','), '') as config,
               pg_catalog.pg_get_function_identity_arguments(p.oid) as args
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
        order by p.proname`);
    const anonDefiner = rows2.filter((r) => r.anon_exec === true && r.definer === true);
    const unpinned = anonDefiner.filter((r) => !String(r.config).includes("search_path")).map((r) => String(r.name));
    const takesIdentity = anonDefiner.filter((r) => /(user_id|org_id|account_id|owner_id)\b/i.test(String(r.args))).map((r) => String(r.name));
    const observed = {
      anonCallableDefiner: anonDefiner.map((r) => `${r.name}(${r.args})`),
      unpinned,
      takesCallerIdentity: takesIdentity
    };
    const ok = unpinned.length === 0 && takesIdentity.length === 0;
    return ok ? pass(observed, rows2) : fail(observed, rows2);
  })
};
async function authConfig(ctx) {
  if (!ctx.api) return null;
  return await ctx.api.get(`/v1/projects/${ctx.projectRef}/config/auth`);
}
var authConfirmations = {
  code: "supabase.auth.confirmations",
  provider: "supabase",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:5.16", "iso:8.5"],
  run: (ctx) => guarded("api.auth_config", async () => {
    const cfg = await authConfig(ctx);
    if (!cfg) return unknown("api.not_connected");
    const observed = {
      mailerAutoconfirm: cfg.mailer_autoconfirm,
      otpLength: cfg.mailer_otp_length,
      signupEnabled: cfg.disable_signup === false
    };
    const ok = cfg.mailer_autoconfirm === false && Number(cfg.mailer_otp_length ?? 0) >= 8;
    return ok ? pass(observed, scrubAuthConfig(cfg)) : fail(observed, scrubAuthConfig(cfg));
  })
};
var MIN_PASSWORD_LENGTH_REQUIRED = 12;
var authPasswordPolicy = {
  code: "supabase.auth.password_policy",
  provider: "supabase",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:5.17", "iso:8.5"],
  run: (ctx) => guarded("api.auth_config", async () => {
    const cfg = await authConfig(ctx);
    if (!cfg) return unknown("api.not_connected");
    const min = Number(cfg.password_min_length ?? NaN);
    if (!Number.isFinite(min)) return unknown("api.shape.password_min_length");
    const required = String(cfg.password_required_characters ?? "");
    const observed = {
      minimumLength: min,
      requiredMinimum: MIN_PASSWORD_LENGTH_REQUIRED,
      compositionRule: required === "" ? "none" : "set"
    };
    return min >= MIN_PASSWORD_LENGTH_REQUIRED ? pass(observed, scrubAuthConfig(cfg)) : fail(observed, scrubAuthConfig(cfg));
  })
};
var authCaptcha = {
  code: "supabase.auth.captcha",
  provider: "supabase",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.6", "iso:8.5"],
  run: (ctx) => guarded("api.auth_config", async () => {
    const cfg = await authConfig(ctx);
    if (!cfg) return unknown("api.not_connected");
    const observed = { enabled: cfg.security_captcha_enabled === true, provider: cfg.security_captcha_provider ?? null };
    return observed.enabled ? pass(observed, scrubAuthConfig(cfg)) : fail(observed, scrubAuthConfig(cfg));
  })
};
var authSiteUrl = {
  code: "supabase.auth.site_url",
  provider: "supabase",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.9"],
  run: (ctx) => guarded("api.auth_config", async () => {
    const cfg = await authConfig(ctx);
    if (!cfg) return unknown("api.not_connected");
    const site = String(cfg.site_url ?? "");
    const observed = { siteUrl: site, https: site.startsWith("https://"), local: /localhost|127\.0\.0\.1/.test(site) };
    return observed.https && !observed.local ? pass(observed, scrubAuthConfig(cfg)) : fail(observed, scrubAuthConfig(cfg));
  })
};
var authSmtp = {
  code: "supabase.auth.smtp",
  provider: "supabase",
  version: 1,
  severity: "medium",
  maps: ["iso:8.9", "iso:8.20"],
  run: (ctx) => guarded("api.auth_config", async () => {
    const cfg = await authConfig(ctx);
    if (!cfg) return unknown("api.not_connected");
    const observed = { smtpHost: cfg.smtp_host ?? null, configured: Boolean(cfg.smtp_host) };
    return observed.configured ? pass(observed, scrubAuthConfig(cfg)) : fail(observed, scrubAuthConfig(cfg));
  })
};
var backups = {
  code: "supabase.backups",
  provider: "supabase",
  version: 1,
  severity: "high",
  maps: ["soc2:A1.2", "iso:8.13"],
  run: (ctx) => guarded("api.backups", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const b = await ctx.api.get(`/v1/projects/${ctx.projectRef}/database/backups`);
    const recent = (b.backups ?? []).filter((x) => x.status === "COMPLETED").length;
    const observed = { pitr: b.pitr_enabled === true, walg: b.walg_enabled === true, completedBackups: recent };
    return observed.pitr || recent > 0 ? pass(observed, b) : fail(observed, b);
  })
};
var noPublicBuckets = {
  code: "supabase.storage.no_public_bucket",
  provider: "supabase",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.3", "iso:8.12"],
  run: (ctx) => guarded("api.buckets", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const buckets = await ctx.api.get(`/v1/projects/${ctx.projectRef}/storage/buckets`);
    const pub = buckets.filter((b) => b.public).map((b) => b.name);
    const observed = { buckets: buckets.length, publicBuckets: pub };
    return pub.length === 0 ? pass(observed, buckets) : fail(observed, buckets);
  })
};
var sslEnforced = {
  code: "supabase.db.ssl_enforced",
  provider: "supabase",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.24", "iso:8.20"],
  run: (ctx) => guarded("api.ssl", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const s = await ctx.api.get(`/v1/projects/${ctx.projectRef}/ssl-enforcement`);
    const observed = { enforced: s.currentConfig?.database === true };
    return observed.enforced ? pass(observed, s) : fail(observed, s);
  })
};
var SUPABASE_SQL_CHECKS = [
  rlsAllTables,
  noAnonWritePolicy,
  privateSchemaClosed,
  definerSearchPath,
  viewsSecurityInvoker,
  noAnonCallableFunctions
];
var SUPABASE_API_CHECKS = [
  authConfirmations,
  authPasswordPolicy,
  authCaptcha,
  authSiteUrl,
  authSmtp,
  backups,
  noPublicBuckets,
  sslEnforced
];
var SUPABASE_CHECKS = [...SUPABASE_SQL_CHECKS, ...SUPABASE_API_CHECKS];
async function runSupabaseChecks(ctx) {
  const out = [];
  for (const c of SUPABASE_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// ../lib/checks/providers/repo.ts
var HISTORY_CAP = 64 * 1024 * 1024;
var SECRET_PATTERNS = [
  { name: "AWS access key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { name: "GitLab token", re: /\bglpat-[A-Za-z0-9._-]{20,}\b/ },
  { name: "Stripe live key", re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/ },
  { name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "OpenAI key", re: /\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { name: "Supabase service key", re: /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]*"role":"service_role"|\bsb_secret_[A-Za-z0-9_-]{20,}\b/ },
  // A BEGIN marker alone is not a key. Our own gcp.ts carries the literal
  // "-----BEGIN PRIVATE KEY-----" as a guard on a service account field, and
  // version 2 failed this repository on it: the detector detected itself.
  // A real block has an END marker and a body between the two, so both are
  // required. A key committed without its END line is missed, which is the
  // right way round: a check that cries wolf is worse than one that cannot
  // fail. (12 Sep 2026, found by running snoopios repo on snoopios)
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]{40,4000}?-----END [A-Z ]*PRIVATE KEY-----/ },
  { name: "Resend key", re: /\bre_[A-Za-z0-9]{20,}\b/ },
  { name: "Vercel token", re: /\bvercel_[A-Za-z0-9]{20,}\b/ },
  { name: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/ }
];
var ENV_PATH = /(^|\/)\.env(\.[^/]+)?$/;
var ENV_ALLOWED = /\.env\.(example|sample|template|dist|test)$/;
var MANIFESTS = [
  { manifest: /(^|\/)package\.json$/, lockfiles: ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"] },
  { manifest: /(^|\/)pyproject\.toml$/, lockfiles: ["poetry.lock", "uv.lock", "pdm.lock", "requirements.txt"] },
  { manifest: /(^|\/)Cargo\.toml$/, lockfiles: ["Cargo.lock"] },
  { manifest: /(^|\/)go\.mod$/, lockfiles: ["go.sum"] },
  { manifest: /(^|\/)Gemfile$/, lockfiles: ["Gemfile.lock"] },
  { manifest: /(^|\/)composer\.json$/, lockfiles: ["composer.lock"] }
];
function src(ctx) {
  if (!ctx.source) throw new Error("scope:repo.not_opened");
  return ctx.source;
}
var envCommitted = {
  code: "repo.env_committed",
  provider: "repo",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.12", "iso:5.17"],
  run: (ctx) => guarded("repo.files", async () => {
    const files = await src(ctx).files();
    const hits = files.filter((f) => ENV_PATH.test(f) && !ENV_ALLOWED.test(f));
    const observed = { tracked: files.length, envFiles: hits };
    return hits.length === 0 ? pass(observed, { envFiles: hits }) : fail(observed, { envFiles: hits });
  })
};
var gitignoreEnv = {
  code: "repo.gitignore_env",
  provider: "repo",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.12"],
  run: (ctx) => guarded("repo.files", async () => {
    const text2 = await src(ctx).read(".gitignore");
    if (text2 === null) return fail({ gitignore: false, coversEnv: false }, { gitignore: null });
    const lines = text2.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    const covers = lines.some((l) => /^(\*\*\/)?\.env(\*|\.\*|\.local)?$|^\.env\*$|^\*\.env$/.test(l.replace(/^\//, "")));
    const observed = { gitignore: true, coversEnv: covers };
    return covers ? pass(observed, { lines: lines.filter((l) => /env/i.test(l)) }) : fail(observed, { lines: lines.slice(0, 50) });
  })
};
var TEST_PATH = /(^|\/)(__tests__|__fixtures__|__mocks__|fixtures?|tests?|specs?|testdata)\/|\.(test|spec|fixture)\.[cm]?[jt]sx?$|\.(test|spec)\.(py|rb|go|rs|java|kt|php|cs)$/i;
var secretsInHistory = {
  code: "repo.secrets_in_history",
  provider: "repo",
  version: 3,
  severity: "critical",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.12", "iso:8.28"],
  run: (ctx) => guarded("repo.history", async () => {
    const { text: text2, truncated } = await src(ctx).history(ctx.historyCap ?? HISTORY_CAP);
    const found = {};
    const inTests = {};
    const testPaths = /* @__PURE__ */ new Set();
    const parts = text2.split(/^diff --git a\/.+? b\/(.+)$/m);
    for (let i = -1; i < parts.length; i += 2) {
      const path = i < 0 ? "" : parts[i];
      const body = parts[i + 1] ?? "";
      const isTest = path !== "" && TEST_PATH.test(path);
      for (const { name, re } of SECRET_PATTERNS) {
        const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
        const n = (body.match(global) ?? []).length;
        if (!n) continue;
        if (isTest) {
          inTests[name] = (inTests[name] ?? 0) + n;
          testPaths.add(path);
        } else {
          found[name] = (found[name] ?? 0) + n;
        }
      }
    }
    const observed = { historyBytes: text2.length, truncated, shapesFound: found, inTestFiles: { shapes: inTests, paths: [...testPaths].sort() } };
    const evidence = { shapes: Object.keys(found), testFileShapes: Object.keys(inTests), testFilePaths: [...testPaths].sort() };
    if (Object.keys(found).length) return fail(observed, evidence);
    if (truncated) return unknown("repo.history_truncated", observed);
    return pass(observed, evidence);
  })
};
var lockfile = {
  code: "repo.lockfile",
  provider: "repo",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC8.1", "iso:8.28", "iso:8.8"],
  run: (ctx) => guarded("repo.files", async () => {
    const files = await src(ctx).files();
    const set = new Set(files);
    const missing = [];
    const evidence = {};
    let manifests = 0;
    for (const f of files) {
      for (const m of MANIFESTS) {
        if (!m.manifest.test(f)) continue;
        manifests++;
        const dir = f.includes("/") ? f.slice(0, f.lastIndexOf("/") + 1) : "";
        const has = m.lockfiles.some((l) => set.has(dir + l));
        evidence[f] = { lockfile: has };
        if (!has) missing.push(f);
      }
    }
    if (manifests === 0) return unknown("repo.no_manifest", { tracked: files.length });
    const observed = { manifests, withoutLockfile: missing };
    return missing.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var hygiene = {
  code: "repo.hygiene",
  provider: "repo",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC2.3", "iso:5.24", "iso:8.32"],
  run: (ctx) => guarded("repo.files", async () => {
    const files = await src(ctx).files();
    const has = (re) => files.some((f) => re.test(f));
    const missing = [];
    if (!has(/^(\.github\/|docs\/)?SECURITY\.md$/i)) missing.push("SECURITY.md");
    if (!has(/^(\.github\/|docs\/)?CODEOWNERS$/)) missing.push("CODEOWNERS");
    const observed = { missing };
    return missing.length === 0 ? pass(observed, { checked: ["SECURITY.md", "CODEOWNERS"] }) : fail(observed, { checked: ["SECURITY.md", "CODEOWNERS"] });
  })
};
var dependencyUpdates = {
  code: "repo.dependency_updates",
  provider: "repo",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.1", "iso:8.8", "ce:patching"],
  run: (ctx) => guarded("repo.files", async () => {
    const files = await src(ctx).files();
    const configs2 = files.filter((f) => /^\.github\/dependabot\.ya?ml$|^(\.github\/)?renovate\.json5?$|^\.renovaterc(\.json)?$/.test(f));
    const observed = { configured: configs2.length > 0, configs: configs2 };
    return configs2.length > 0 ? pass(observed, { configs: configs2 }) : fail(observed, { configs: configs2 });
  })
};
var vulnerableDependencies = {
  code: "repo.vulnerable_dependencies",
  provider: "repo",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.1", "iso:8.8", "ce:patching"],
  run: (ctx) => guarded("repo.audit", async () => {
    const s = src(ctx);
    if (!s.audit) return unknown("repo.no_auditor");
    const counts = await s.audit();
    if (!counts) return unknown("repo.audit_unavailable");
    const open = counts.critical + counts.high;
    const observed = { ...counts, criticalOrHigh: open };
    return open === 0 ? pass(observed, counts) : fail(observed, counts);
  })
};
var REPO_CHECKS = [envCommitted, gitignoreEnv, secretsInHistory, lockfile, hygiene, dependencyUpdates, vulnerableDependencies];
async function runRepoChecks(ctx) {
  const out = [];
  for (const c of REPO_CHECKS) {
    let result;
    try {
      result = await c.run(ctx);
    } catch {
      result = unknown("check.threw");
    }
    out.push({ code: c.code, version: c.version, result });
  }
  return out;
}

// src/index.ts
import { execFile, spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve, join, dirname } from "node:path";

// ../lib/copy.ts
var COPY = {
  // ── meta ──────────────────────────────────────────────────────────────────
  "meta.title": "Snoopios: continuous compliance for small software teams",
  "meta.description": "Snoopios watches the stack you actually run on, including Supabase, Vercel, Cloudflare, GitHub and Stripe. It collects real evidence and turns it into the documents customers and auditors ask for. Flat price. No sales call.",
  // ── accessibility ─────────────────────────────────────────────────────────
  "a11y.nav.primary": "Primary",
  "a11y.nav.menu": "Menu",
  "a11y.back": "Back",
  "a11y.dismiss": "Dismiss",
  "a11y.loading": "Loading",
  "a11y.logo": "Snoopios",
  "a11y.preview": "Example of the Snoopios check grid for one project",
  // ── errors & empty states ─────────────────────────────────────────────────
  "error.offline": "You're offline. This will work again once you're connected.",
  "error.generic": "Something went wrong. Try again in a moment.",
  "error.retry": "Try again",
  "error.notfound": "That page doesn't exist.",
  // dormant: first list screen that can be empty
  "empty.default": "Nothing here yet.",
  // ── app ───────────────────────────────────────────────────────────────────
  "app.name": "Snoopios",
  // dormant: the app shell TopBar subtitle, Phase 1
  "app.tagline": "Continuous compliance for the Supabase and Vercel generation.",
  // ── status words — the four states, everywhere ────────────────────────────
  "status.pass": "Pass",
  "status.fail": "Fail",
  "status.unknown": "Unknown",
  // dormant: first finding with a warning severity, Phase 2
  "status.warning": "Warning",
  // ── home: nav ─────────────────────────────────────────────────────────────
  "home.nav.pricing": "Pricing",
  "home.nav.signin": "Sign in",
  "home.nav.start": "Start free",
  "home.nav.open": "Open app",
  // ── home: hero ────────────────────────────────────────────────────────────
  "home.hero.title": "Eyes on your stack. Evidence in hand.",
  "home.hero.body": "Snoopios connects read-only to what you already run: the hosting, databases and code, and also the laptops, the payroll, the password manager and the scanners. It checks their configuration every hour and keeps the evidence. When a customer sends a security questionnaire or a regulator asks a question, the answer is already written.",
  "home.hero.cta": "Start with one project, free",
  "home.hero.secondary": "See what it checks",
  "home.hero.note": "A flat price per project, never per seat. No sales call.",
  "home.hero.cta.beta": "Ask for a place in the beta",
  "home.hero.note.beta": "Sign-ups are closed while we finish the first release. An invitation is fourteen days of the full product, no card.",
  // ── home: product preview (an example project) ────────────────────────────
  "preview.project": "acme-app",
  "preview.lastrun": "Last run 14 minutes ago \xB7 next in 5h 46m",
  "preview.summary": "17 pass \xB7 2 fail \xB7 1 unknown",
  "preview.c1": "RLS enabled on every public table",
  "preview.c2": "No policy admits anon writes",
  "preview.c3": "Preview deployments protected",
  "preview.c4": "DMARC policy is quarantine or reject",
  "preview.c5": "Default branch protected",
  "preview.c6": "Backups or PITR enabled",
  "preview.c6.why": "Token expired \xB7 reconnect Supabase",
  "preview.evidence": "Evidence stored \xB7 sha256 3f9a\u2026c21e",
  // ── home: the problem ─────────────────────────────────────────────────────
  "home.problem.title": "Compliance tools were not built for your stack, or your budget.",
  "home.problem.body": "The established compliance platforms start at five figures a year and were designed around large cloud accounts and enterprise identity providers. You run on modern hosting and a managed database, you are the data protection officer and the on-call engineer, and your first enterprise customer has just sent a forty-question spreadsheet.",
  "home.problem.p1.title": "The obligations don't wait",
  "home.problem.p1.body": "UK GDPR applies from your first user. The Data (Use and Access) Act 2025 added a complaints procedure every controller must have, in force from June 2026. A payment provider's review expects a privacy policy that matches the code.",
  "home.problem.p2.title": "Nobody checks the things that matter",
  "home.problem.p2.body": "Is row-level security on every table? Can an anonymous session write? Is a preview deployment open to the internet? The big platforms sync your user list and call it monitoring.",
  "home.problem.p3.title": "The documents rot",
  "home.problem.p3.body": "A privacy policy written once still says things the code stopped doing months ago. That gap is a misrepresentation, not a typo.",
  // ── home: how it works ────────────────────────────────────────────────────
  "home.how.title": "How it works",
  "home.how.s1.title": "Connect, read-only",
  "home.how.s1.body": "Grant Snoopios read access through each provider's own consent screen. No write scope is ever requested. Revoke it from their dashboard any time.",
  "home.how.s2.title": "Checks run every hour",
  "home.how.s2.body": "Each check is code with a recorded fixture. It returns pass, fail or unknown, and a check that cannot run says unknown. It never says pass.",
  "home.how.s3.title": "Evidence is kept, unchanged",
  "home.how.s3.body": "Every run stores the raw response, a timestamp and a hash. Nothing is edited after the fact. Corrections are new rows.",
  "home.how.s4.title": "Documents write themselves from the facts",
  "home.how.s4.body": "The sub-processor register comes from what's connected. Every policy claim links to a live check, so a sentence the code no longer honours is flagged in the document.",
  // ── home: checks ──────────────────────────────────────────────────────────
  "home.checks.title": "What it checks",
  "home.checks.aside": "No model decides whether you pass. The full feasibility table, endpoint by endpoint, is published in the documentation.",
  // ── home: the pack ────────────────────────────────────────────────────────
  "home.pack.title": "The pack",
  "home.pack.body": "The documents a customer, an auditor or the ICO asks for, generated from what's connected and checked against what's running. That includes the three an ISO certification body opens with, and the SOC 2 system description firms normally charge four figures to draft. Every one is a draft for your review, and says so.",
  "home.pack.d1": "Privacy policy, with a real last-updated date",
  "home.pack.d2": "Record of processing activities",
  "home.pack.d3": "Sub-processor register, derived from your connections",
  "home.pack.d4": "Retention schedule",
  "home.pack.d5": "Breach notification runbook, pre-filled, with the 72-hour clock",
  "home.pack.d6": "Data subject request procedure",
  "home.pack.d7": "Complaints procedure with the 30-day acknowledgement the 2025 Act requires",
  "home.pack.d8": "Security questionnaire answer bank, grounded in check results",
  "home.pack.d9": "Cyber Essentials self-assessment preparation",
  "home.pack.d10": "SOC 2 and ISO 27001 readiness maps: every control, ticked as checked, documented or yours to answer",
  "home.pack.soon": "Next",
  // ── home: trust page ──────────────────────────────────────────────────────
  "home.trust.title": "A trust page you can send instead of a spreadsheet",
  "home.trust.body": "A public page per project with live check status, your document list and NDA-gated downloads. When a prospect's security reviewer asks, you send a link. Unknown shows as unknown there too.",
  "home.trust.url": "snoopios.com/t/acme-app",
  // ── home: pricing ─────────────────────────────────────────────────────────
  "home.pricing.title": "Flat, published, by project.",
  "home.pricing.body": "No per-seat pricing, no renewal uplift, and no charging you again for each standard. You buy a regime, not a framework: the UAE plan covers the federal law, the DIFC and ADGM regimes, Dubai's security regulation and the federal assurance standards, all from the same evidence. Annual pays for ten months. Cancel monthly plans any time.",
  "home.pricing.permonth": "/month",
  "home.pricing.free.note": "Evaluate on one project",
  "home.pricing.popular": "Most teams",
  "home.pricing.cta.free": "Start free",
  "home.pricing.cta.paid": "Start",
  "home.pricing.compare": "For comparison, the enterprise platforms do not publish a rate card. Reported entry pricing for a small team runs from about \xA35,500 a year to roughly \xA311,000, with extra frameworks charged on top at \xA31,100 to \xA33,700 each and the trust page and questionnaire tools sold as further add-ons. Figures gathered September 2026 from vendor pages and third-party pricing trackers; treat them as ranges rather than quotes.",
  // ── tiers (also read by lib/access-policy.ts) ────────────────────────────
  "tier.free.name": "Free",
  "tier.free.f1": "One project, checked weekly",
  "tier.free.f2": "Findings with the evidence behind each one",
  "tier.free.f3": "One region pack: every framework for the country or region you choose",
  "tier.free.f4": "Evidence kept for one month",
  "tier.solo.name": "Solo",
  "tier.solo.f1": "One project, checked every hour",
  "tier.solo.f2": "One region pack, control by control: pick the United Kingdom, the European Union, the UAE, Saudi Arabia, the wider Gulf, North America or Asia",
  "tier.solo.f3": "The full document pack, exportable: privacy notice, record of processing, sub-processor register, retention schedule, breach runbook, requests procedure, security summary and the eleven policies",
  "tier.solo.f4": "Evidence vault: every run's raw response, hashed and kept twelve months, plus your own documents linked to the controls they evidence",
  "tier.solo.f5": "Public trust page with gated document downloads",
  "tier.studio.name": "Studio",
  "tier.studio.f1": "Everything in Solo",
  "tier.studio.f2": "A second region pack, for the market you sell into as well as the one you are registered in",
  "tier.studio.f3": "The Security pack: ISO 27001 and SOC 2, with ISO 27701 for privacy management, 27017 and 27018 for cloud, 22301 for continuity and the NIST framework",
  "tier.studio.f4": "The questionnaire answer bank: written answers, each citing a live check",
  "tier.scale.name": "Scale",
  "tier.scale.f1": "Everything in Studio",
  "tier.scale.f2": "Four region packs and two projects",
  "tier.scale.f3": "Two specialist packs of your choosing: AI governance, children's data, or the NHS supplier bundle",
  "tier.scale.f4": "Evidence vault extended to thirty-six months",
  "tier.scale.f5": "Accepted risks with a review date, shown beside the fail rather than hiding it",
  // ── home: faq ─────────────────────────────────────────────────────────────
  "home.faq.title": "Questions we get asked",
  "home.faq.q1": "Does Snoopios need write access to anything?",
  "home.faq.a1": "No. Every connection is a read-only grant through the provider's own consent screen, and a check that would need write access does not get built. You can revoke access from the provider's dashboard at any time.",
  "home.faq.q2": "What happens when a check can't run?",
  "home.faq.a2": "It reports unknown, with the reason. Unknown is shown as grey everywhere, including your trust page, and never counts as a pass. An expired token is the usual cause and the fix is a reconnect.",
  "home.faq.q3": "Is this legal advice, or a certification?",
  "home.faq.a3": "Neither. Snoopios produces evidence of what was checked and when, and documents drafted from that evidence for your review. It never says a customer is compliant or certified, and it never brokers or bundles an audit.",
  "home.faq.q4": "Can I get SOC 2 or ISO 27001 with it?",
  "home.faq.a4": "The Scale tier maps your checks and documents to the SOC 2 common criteria and ISO 27001 controls and exports a package an auditor can read. The audit itself is between you and an audit firm. We can point you at firms that already accept this kind of evidence, as a referral and nothing more.",
  "home.faq.q5": "Where is my data held?",
  "home.faq.a5": "In the United Kingdom, with Supabase in the London region, hosted on Vercel. Evidence is stored per organisation with row-level security and is never shared between customers. The full processor list is in the privacy policy.",
  // ── home: closing band ────────────────────────────────────────────────────
  "home.cta.title": "Connect one project. See what you'd have found out the hard way.",
  "home.cta.body": "Free for one project, weekly checks, no card. Upgrade when the evidence is worth paying for.",
  "home.cta.button": "Start free",
  // ── home: who ─────────────────────────────────────────────────────────────
  "home.who.title": "Built on the stack it checks.",
  "home.who.body": "Snoopios is built by the team behind several products that run on the same hosting, database and identity services it checks. Every check in it exists because it caught something real on one of those products. The document pack is the one the team wrote by hand, over and over, before deciding to build the tool properly.",
  // ── auth ──────────────────────────────────────────────────────────────────
  "auth.signup.title": "Create your account",
  "auth.signup.frame": "One project free, no card. Confirm your email and you're in.",
  "auth.signup.cta": "Create account",
  // Private beta: the live site refuses sign-ups until the founder opens them
  // (NEXT_PUBLIC_SIGNUPS_OPEN and the Supabase config together).
  "auth.signup.closed.title": "Private beta",
  "auth.signup.closed.body": "Snoopios is running with a small group of founding customers while we finish the first release. If you have been invited, your invitation email has the sign-in link. If you would like to join, email us and we will be in touch.",
  "auth.signup.closed.signin": "Already have an account? Sign in",
  "beta.title": "Ask for a place in the beta",
  "beta.intro": "Snoopios is running with a small group while we finish the first release. Tell us what you run on and we will be in touch. An invitation gives you fourteen days of the full product, every framework pack your plan allows, hourly checks and the trust page. No card, and nothing starts until you confirm your email.",
  "beta.email.label": "Email",
  "beta.email.placeholder": "you@company.com",
  "beta.platforms.label": "What do you run on?",
  "beta.platforms.hint": "Tick anything you use. This is the most useful thing on the form: it tells us which checks your account will exercise, so we can have them right before you arrive.",
  "beta.driver.label": "Who is asking you for this?",
  "beta.driver.hint": "An enterprise customer, an investor, a tender, an auditor, or nobody yet. One line is plenty.",
  "beta.driver.placeholder": "A customer has sent us a security questionnaire we cannot answer.",
  "beta.submit": "Ask for a place",
  "beta.sending": "Sending",
  "beta.done.title": "Thank you, that is with us",
  "beta.done.home": "Back to the homepage",
  "beta.done.body": "We read every one of these ourselves. If what you run on is something we have not checked against a real account yet, we will say so rather than let you find out.",
  "beta.error.email": "That does not look like an email address we can reply to.",
  "beta.error.driver": "That is longer than the box allows. A line or two is plenty.",
  "beta.error.rate": "That is more requests than we can take from here just now. Try again shortly, or email us.",
  "beta.error.failed": "We could not record that. Nothing has been saved; try again, or email us.",
  "beta.privacy": "We store your address, what you ticked and what you wrote, so that we can reply. Nothing else, and no tracking. See the privacy notice.",
  "auth.signup.closed.refused": "Sign-ups are closed for now. Email us to be invited.",
  "auth.signin.title": "Sign in",
  "auth.signin.cta": "Sign in",
  "auth.email.label": "Work email",
  "auth.password.label": "Password",
  "auth.password.hint": "At least twelve characters. A sentence you'll remember beats a word you won't.",
  "a11y.password.show": "Show password",
  "a11y.password.hide": "Hide password",
  "auth.switch.tosignup": "No account yet? Create one",
  "auth.switch.tosignin": "Already have an account? Sign in",
  "auth.signout": "Sign out",
  // The same message for an unknown email, a wrong password and an
  // unconfirmed address: distinguishing them tells an attacker which emails
  // have accounts.
  "auth.error.invalid": "That email and password don't match an account, or the address isn't confirmed yet.",
  // Carries no number on purpose, so the policy can move without a copy edit.
  "auth.error.weakpassword": "That password is too short.",
  "auth.error.exists": "There's already an account for that email. Sign in instead.",
  "auth.error.generic": "Couldn't create the account just now. Try again in a minute.",
  "auth.captcha.failed": "The bot check couldn't load. Refresh the page and try again.",
  "auth.error.mismatch": "The two passwords don't match.",
  "auth.error.samepassword": "That's the password you already have. Choose a different one.",
  "auth.error.reset": "Couldn't set the password. Request a new link and try again.",
  "auth.forgot.link": "Forgot your password?",
  "auth.forgot.title": "Reset your password",
  "auth.forgot.frame": "Enter your work email. If it has an account, we'll send a link to choose a new password.",
  "auth.forgot.cta": "Send reset link",
  "auth.forgot.back": "Back to sign in",
  "auth.forgot.sent.title": "Check your email",
  "auth.forgot.sent.body": "If there's an account for it, a reset link is on its way to",
  "auth.forgot.sent.spam": "The link works once and expires in an hour. Check spam if it hasn't arrived in a minute.",
  "auth.reset.title": "Choose a new password",
  "auth.reset.frame": "You're signed in from the reset link. Set the password you'll use from now on.",
  "auth.reset.label": "New password",
  "auth.reset.confirm.label": "New password again",
  "auth.reset.cta": "Set password",
  "auth.check.title": "Check your email",
  "auth.check.body": "We've sent a confirmation link to",
  "auth.check.step1": "Open the email from Snoopios.",
  "auth.check.step2": "Click the confirmation link. It signs you in.",
  "auth.check.step3": "Your 14-day trial starts the moment you confirm, not before.",
  "auth.check.spam": "It can take a minute. Check spam if it hasn't arrived.",
  // ── app: first screen ─────────────────────────────────────────────────────
  "nav.tab.checks": "Checks",
  "app.trial.days": "Days left in your trial:",
  "app.empty.title": "Connect your first project",
  "app.empty.body": "Grant read-only access to a Supabase project, a Vercel project or a GitHub organisation. The first checks run within a minute.",
  // ── app: projects ─────────────────────────────────────────────────────────
  "app.projects.add.title": "Add another project",
  "app.projects.name.label": "Project name",
  "app.projects.name.placeholder": "My app",
  "app.projects.domain.label": "Production domain",
  "app.projects.domain.placeholder": "app.example.com",
  "app.projects.domain.hint": "Optional. With a domain, eleven checks run straight away with no credentials: headers, TLS, DNS, security.txt and your privacy page.",
  "app.projects.create": "Create project",
  "app.projects.error.name": "Give the project a name.",
  "app.projects.error.domain": "That doesn't look like a hostname. Use the form app.example.com, without https://.",
  "app.projects.error.limit": "Your plan's project limit is reached. Choose a larger plan to add another.",
  "plan.meter.projects": "Projects",
  "plan.meter.unlimited": "unlimited",
  "plan.meter.interval": "Checks run every",
  "plan.meter.hours": "hours",
  "app.project.notrun": "Not run yet",
  "app.project.lastrun": "Last run",
  // ── app: run ──────────────────────────────────────────────────────────────
  "run.cta": "Run checks now",
  "run.running": "Running",
  "run.limited": "One manual run a minute. Try again shortly.",
  "run.error": "The run didn't complete. It will retry on the next schedule.",
  // ── app: connections ──────────────────────────────────────────────────────
  "stack.title": "Which platforms does this project run on?",
  "stack.intro": "Tick what you use and Snoopios shows only those connections. You can add the rest any time from the drawer below the connections.",
  "stack.save": "Show these connections",
  "stack.skip.hint": "Nothing ticked? Save anyway; every platform stays available under Add a platform.",
  "stack.add.title": "Add a platform",
  "stack.add.intro": "Tick a platform to show its connection above.",
  "stack.add.cta": "Add to this project",
  "stack.notusing": "Not using this",
  "stack.blurb.supabase": "Database, auth, storage: RLS, backups, SSL, auth doors",
  "stack.blurb.vercel": "Hosting: preview protection, fork protection, domains, Node",
  "stack.blurb.cloudflare": "Edge and DNS: TLS, HSTS, DNSSEC, WAF, R2, Pages",
  "stack.blurb.github": "Source: branch protection, Dependabot, secrets, hygiene",
  "stack.blurb.gitlab": "Source: group 2FA, protected branches, secret detection, hygiene",
  "stack.blurb.fly": "Hosting: forced HTTPS, encrypted volumes, no plaintext secrets, member 2FA",
  "stack.blurb.stripe": "Payments: webhook signing and delivery",
  "stack.blurb.email": "Sending domain: SPF, DKIM, DMARC, MTA-STS, TLS-RPT",
  "stack.blurb.google": "Google Workspace: two-step verification, admins, dormant accounts",
  "stack.blurb.microsoft": "Microsoft 365: MFA, Global Administrators, dormant accounts",
  "stack.blurb.slack": "Slack: 2FA, admins, guests, who can join",
  "stack.blurb.sentry": "Sentry: 2FA, data scrubbing, membership",
  "stack.blurb.uptimerobot": "UptimeRobot: production monitored, alerts, interval",
  "results.allclear": "all clear",
  "results.accepted.short": "accepted",
  "conn.title": "Connections",
  "conn.remove": "Remove",
  "conn.error": "Last run could not reach this connection:",
  "conn.assurance.verified": "read-only verified",
  "conn.assurance.verified.hint": "The grant or token was checked against the provider and would have been refused if it could write. Some providers scope a grant to the whole organisation rather than one project; Snoopios still reads only the project you named.",
  "conn.assurance.requested": "read-only requested",
  "conn.assurance.requested.hint": "You created this credential read-only, but the provider has no way to confirm a token's permissions. Snoopios's own requests are still limited to reads by code.",
  "conn.supabase.title": "Connect Supabase",
  "conn.supabase.oauth.intro": "Grant read-only access through Supabase. The Snoopios app asks for four read scopes (Auth, Database, Projects, Storage) and Supabase itself refuses anything else, so the connection shows as read-only verified. Supabase grants apply to a whole organisation, not one project: Snoopios stores one project ref and reads only that project, but the grant could read the others. If that matters, keep production in its own organisation. Enter the project ref, then approve on Supabase.",
  "conn.supabase.oauth.cta": "Grant read-only access on Supabase",
  "conn.supabase.oauth.fallback": "Or connect with a personal access token. Scope it to this project with the Read-only preset; that connection still shows as read-only requested, because Supabase will not tell us what you granted.",
  "conn.supabase.oauth.connected": "Supabase is connected through a read-only grant. The first run starts within a minute.",
  "conn.supabase.oauth.scope": "The grant does not cover that project ref. Approve with an account that belongs to the project's organisation, and check the ref.",
  "conn.supabase.oauth.denied": "The Supabase grant was cancelled, so nothing was connected. Try again from this page.",
  "conn.supabase.oauth.error": "The Supabase grant did not complete. Try again from this page; if it repeats, email us.",
  "conn.supabase.oauth.unconfigured": "The Supabase grant is not switched on in this deployment yet. Use a personal access token below, or email us.",
  "conn.supabase.intro": "Until the OAuth app is listed, connect with a personal access token. It is encrypted with a key that never enters the database, and only ever used for read-only calls: the auth config, backups, buckets, and catalogue queries through Supabase's read-only SQL endpoint.",
  "conn.supabase.ref.label": "Project ref",
  "conn.supabase.ref.placeholder": "abcdefghijklmnopqrst",
  "conn.supabase.token.label": "Personal access token",
  "conn.supabase.token.placeholder": "sbp_\u2026",
  "conn.supabase.token.hint": "Account, Access Tokens, Generate new token. Scope it: set Resource access to Project and pick only this project, set the permission preset to Read-only, and leave the expiry at seven days. Supabase calls an unrestricted token LEGACY now, and one of those carries everything your account can do. We still record this connection as read-only REQUESTED rather than verified, because Supabase gives no way to read a token's own permissions back, so we cannot prove what you granted. Scoping it is what makes that gap harmless.",
  "conn.supabase.cta": "Connect read-only",
  "conn.supabase.error.ref": "A project ref is twenty lowercase letters and digits.",
  "conn.supabase.error.token": "That doesn't look like a Supabase personal access token.",
  "conn.supabase.error.auth": "Supabase refused that token. Check it was copied whole and has not expired. Nothing has been saved.",
  "conn.supabase.error.project": "The token works, but that project ref belongs to no organisation it can see. The ref is the twenty characters in your project URL, and the token must belong to an account that is a member of that organisation. Nothing has been saved.",
  "conn.supabase.error.unreachable": "Supabase did not answer in a way we could read. Nothing has been saved; try again shortly.",
  "conn.github.title": "Connect GitHub",
  "conn.github.intro": "Until the GitHub App is listed, connect with a fine-grained personal access token scoped to read: Metadata, Contents, Administration, Dependabot alerts and Secret scanning alerts, plus Members if the owner is an organisation (a personal account has no Members permission; leave it out). Classic tokens are refused because they cannot be made read-only.",
  "conn.github.org.label": "Organisation or username",
  "conn.github.org.placeholder": "your-org or your-username",
  "conn.github.repos.label": "Repositories to check",
  "conn.github.repos.placeholder": "app, api, website",
  "conn.github.repos.hint": "Optional. Leave empty to check up to thirty active repositories.",
  "conn.github.token.label": "Fine-grained personal access token",
  "conn.github.token.placeholder": "github_pat_\u2026",
  "conn.github.token.hint": "Settings, Developer settings, Personal access tokens, Fine-grained tokens, Generate new token. Set Resource owner to the organisation, not your own account, or the token sees none of its repositories. Many organisations also have to approve a new token before it works, and until an owner does the token returns nothing and every check here says unknown rather than fail. Give it an expiry. It is encrypted before it reaches the database.",
  "conn.github.cta": "Connect read-only",
  "conn.github.error.org": "A GitHub organisation or username is letters, digits and hyphens.",
  "conn.github.error.token": "That isn't a fine-grained token. Classic tokens (ghp_) are refused because they can't be scoped read-only.",
  "conn.github.error.auth": "GitHub refused that token. If it was created minutes ago, check it has not expired and that you copied the whole value; GitHub shows it once.",
  "conn.github.error.owner": "GitHub has no organisation or username by that name. Check the spelling; it is the part of the repository URL before the slash. Nothing has been saved.",
  "conn.github.error.no_access": "The token works, but it can see no repository belonging to that owner, so every check would report unknown. There are three usual causes and GitHub does not let us tell them apart. Resource owner: a fine-grained token defaults to your personal account, so an organisation is invisible unless you selected it. Approval: a token for an organisation stays pending until an owner approves it, and reads nothing meanwhile. Repository access: check the token actually lists the repositories you want, and has Metadata read. Nothing has been saved.",
  "conn.cloudflare.title": "Connect Cloudflare",
  "conn.cloudflare.intro": "Create an API token with read permissions only: Zone Read, DNS Read, Zone Settings Read, Zone WAF Read, Bot Management Read, Workers R2 Storage Read, Turnstile Read, Cloudflare Pages Read and Access: Apps and Policies Read, scoped to the zones you want checked. Set an expiry and, if you can, restrict it to our IP ranges.",
  "conn.cloudflare.account.label": "Account ID",
  "conn.cloudflare.account.placeholder": "32 hex characters, from the dashboard overview",
  "conn.cloudflare.zones.label": "Zones to check",
  "conn.cloudflare.zones.placeholder": "example.com, api.example.com",
  "conn.cloudflare.zones.hint": "Optional. Leave empty to check every active zone the token can see, up to ten.",
  "conn.cloudflare.token.label": "API token",
  "conn.cloudflare.token.placeholder": "Token value, shown once by Cloudflare",
  "conn.cloudflare.token.hint": "Manage Account, Account API Tokens, Create Token, then Custom token, because none of the templates match this set. Your Account ID is on the right of any zone overview page. Turnstile cannot be read by an account-owned token at all, so that one check shows unknown rather than fail, and that is Cloudflare rather than your token.",
  "conn.cloudflare.cta": "Connect read-only",
  "conn.cloudflare.error.account": "An account ID is 32 hexadecimal characters.",
  "conn.cloudflare.error.token": "That doesn't look like a Cloudflare API token.",
  "conn.cloudflare.error.rate_limited": "Cloudflare is refusing to check that token for a moment, because it has seen several failed attempts from here. Wait a minute and try again. Nothing has been saved.",
  "conn.cloudflare.error.auth": "Cloudflare refused that token. Check you copied the whole value: it is shown once, when you create it.",
  "conn.cloudflare.error.account_invisible": "The token works but cannot see that account. Either the Account ID belongs to a different account, or the token was created under My Profile rather than Manage Account and is scoped to your user instead. Nothing has been saved.",
  "conn.stripe.title": "Connect Stripe",
  "conn.stripe.intro": "Create a restricted key with Read on Webhook Endpoints and Events, and nothing else. Those are the only two things Snoopios reads. Secret keys are refused, because nothing here needs one.",
  "conn.stripe.key.label": "Restricted key",
  "conn.stripe.key.placeholder": "rk_live_\u2026",
  "conn.stripe.key.hint": "Developers, API keys, Create restricted key. Stripe will offer to select permissions for you if you say the key is for a third-party application: that set runs to twenty-five and includes creating charges and moving balances. Decline it and tick the two above.",
  "conn.stripe.cta": "Connect read-only",
  "conn.stripe.error.key": "That isn't a restricted key. Secret keys (sk_) are refused; create a restricted key with Read permissions.",
  "conn.stripe.error.auth": "Stripe does not recognise that key. Check it was copied whole, and that it belongs to the account you meant: a test key from one account looks exactly like a test key from another. Nothing has been saved.",
  "conn.stripe.error.permission": "The key works, but Stripe will not let it read webhook endpoints, which is where both checks start. Edit the restricted key and set Webhook Endpoints and Events to Read. Nothing has been saved.",
  "conn.stripe.error.unreachable": "Stripe did not answer in a way we could read. Nothing has been saved; try again shortly.",
  "conn.stripe.label.live": "Live mode",
  "conn.stripe.label.test": "Test mode",
  // ── pack ──────────────────────────────────────────────────────────────────
  "pack.title": "Pack",
  "pack.intro": "Documents generated from what's connected and checked. Every status inside them is the live result of a check, with the date it was observed. Each one is a draft for your review: read it, fill in what only you know, and have a solicitor look at the pack before it's relied on.",
  "pack.coming": "Coming when customers ask: SOC 2 and ISO 27001 readiness maps.",
  "pack.questionnaire.title": "Questionnaire answer bank",
  "pack.questionnaire.body": "The questions a buyer\u2019s security review asks, each answered from live check results with the evidence cited. Copy an answer, or export the lot.",
  "pack.q.intro": "Every answer below is built from what the checks observed, with the badges showing each check\u2019s last result. Copy an answer into the questionnaire you were sent; the export carries the same words with dates.",
  "pack.q.copy": "Copy answer",
  "pack.q.copied": "Copied",
  "pack.q.backed": "checks passing",
  "pack.q.failing": "failing",
  "pack.q.unverified": "Not verified yet",
  "pack.q.policy": "Policy answer",
  "pack.q.download.md": "Download as markdown",
  "pack.q.download.csv": "Download as CSV",
  "pack.draft.notice": "Draft for review. Not legal advice, not a certification.",
  "pack.generated": "Generated from live facts on",
  "pack.legend": "Pass, Fail and Unknown inside a document are check results with the date observed. Not checked means the check has never run for this project, usually because the provider is not connected.",
  "pack.claim.notchecked": "Not checked",
  "pack.open": "Open the pack",
  "pack.download": "Download as markdown",
  "pack.doc.privacy.title": "Privacy notice",
  "pack.doc.privacy.body": "A draft in the Article 13 order with a real last-updated date: who you are, what you collect and why, the processors your connections imply, retention, the security your checks observed, rights and complaints. Every unknown is a fill-in.",
  "pack.doc.ropa.title": "Record of processing activities",
  "pack.doc.ropa.body": "The Article 30 record: one row per activity with purpose, subjects, categories, lawful basis, processors, transfers, retention and the security measures the checks observed.",
  "pack.doc.subprocessors.title": "Sub-processor register",
  "pack.doc.subprocessors.body": "Every third party that processes data for this project, derived from the services you've connected, with role, region and the link to each agreement.",
  "pack.doc.retention.title": "Retention schedule",
  "pack.doc.retention.body": 'Specific periods per category of data, never "as long as necessary", with the job or setting that enforces each one.',
  "pack.doc.breach.title": "Breach runbook",
  "pack.doc.breach.body": "Usable at 2am by one person: the 72-hour clock, contain first, preserve evidence, and what the checks say about your footing right now.",
  "pack.doc.dsr.title": "Requests and complaints procedure",
  "pack.doc.dsr.body": "How data subject requests are handled within a month, and the complaints procedure with the 30-day acknowledgement every UK controller needs since June 2026.",
  "pack.doc.security.title": "Security summary",
  "pack.doc.security.body": "The short answers a security questionnaire asks for, each tied to a live check. The start of the answer bank.",
  "pack.doc.infosec.title": "Information security policy",
  "pack.doc.infosec.body": "The parent policy: commitment, roles, the principles every other document hangs from, exceptions and review. Each principle cites the check that backs it.",
  "pack.doc.access.title": "Access control and review procedure",
  "pack.doc.access.body": "Personal accounts, multi-factor, least privilege, how access is granted and removed, and the quarterly review, with the source-control and database checks behind it.",
  "pack.doc.aup.title": "Acceptable use policy",
  "pack.doc.aup.body": "What everyone may and may not do with devices, accounts, software and information, written for a small team and short enough to be read.",
  "pack.doc.sdlc.title": "Secure development policy",
  "pack.doc.sdlc.body": "Branch to production: protected branches, reviews, secret scanning, dependency fixes within fourteen days, separate environments and the coding rules the checks enforce.",
  "pack.doc.bcp.title": "Business continuity and recovery plan",
  "pack.doc.bcp.body": "What must keep running, the backups behind it, the recovery steps, supplier and single-person failure, and the annual restore test.",
  "pack.doc.supplier.title": "Supplier security procedure",
  "pack.doc.supplier.body": "How a supplier is assessed before it holds your data, the contract terms it must carry, and how it is monitored and ended. Pairs with the sub-processor register.",
  "pack.doc.people.title": "People security policy",
  "pack.doc.people.body": "Before, during and after someone has access: screening, agreements, annual training, the reporting culture and the records that prove it.",
  "pack.doc.risk.title": "Risk assessment method and register",
  "pack.doc.risk.body": "The rating method, a live register in which every failing check is already a risk, and the organisational risks only you can rate.",
  "pack.doc.assets.title": "Information and asset inventory",
  "pack.doc.assets.body": "Systems, services and information with owner and classification, derived from your connections, plus the devices and records only you can list.",
  "pack.doc.logging.title": "Logging and monitoring statement",
  "pack.doc.logging.body": "What is logged, for how long, who looks, and how failures are noticed, including the monitoring Snoopios itself provides.",
  "pack.doc.dpia.title": "By design, DPIA screening and DPO statement",
  "pack.doc.dpia.body": "How privacy is built in, the DPIA screening questions with a recorded conclusion, and whether a data protection officer is required.",
  "pack.doc.governance.title": "Governance, duties and independent review",
  "pack.doc.governance.body": "How a small team separates duties and compensates where it cannot, who oversees security, who reviews it independently, and how audits are run safely.",
  "pack.doc.threat.title": "Threat intelligence and capacity statement",
  "pack.doc.threat.body": "Where threat information comes from, what happens with it each month, and how usage is watched against provider limits.",
  "pack.doc.ip.title": "Intellectual property and licence statement",
  "pack.doc.ip.body": "What the organisation owns, what it uses under licence, and how the two are kept straight.",
  "pack.doc.ce.title": "Cyber Essentials readiness",
  "pack.doc.ce.body": "The five controls of the UK scheme, with what the checks can show for this project and what the self-assessment will ask about devices and people. A working sheet, not a certificate.",
  // ── trust page ────────────────────────────────────────────────────────────
  "trust.eyebrow": "Security and compliance status",
  "trust.lastrun": "Last checked",
  "trust.notrun": "Checks have not run yet.",
  "trust.legend": "Pass means the check read the configuration and found it as expected. Fail means it did not. Unknown means the check could not run on the last attempt; it is never counted as a pass.",
  "trust.disclaimer": "This page shows what Snoopios checked and when. It is evidence of configuration, not a certification, and not a statement that the organisation is compliant with any standard.",
  "trust.powered": "Monitored by Snoopios",
  "trust.settings.title": "Trust page",
  "trust.settings.body": "A public page showing this project's check names and their current status. No evidence, no observed data, no connection details. Unknown shows as unknown there too.",
  "trust.settings.enable": "Publish trust page",
  "trust.settings.disable": "Unpublish",
  // Gated documents (Phase 3.5). The undertaking text is a click-through
  // confidentiality agreement between visitor and owner; solicitor review is
  // a Phase 4 gate (decisions.md). {name} is the project name.
  "trust.docs.title": "Documents",
  "trust.docs.body": "Available under a confidentiality undertaking. Request access and the team reviews it by hand.",
  "trust.docs.request": "Request access",
  "trust.request.title": "Request document access",
  "trust.request.back": "Back to the trust page",
  "trust.request.intro": "Tell the team who you are. Requests are approved by a person; an approved link arrives by email and works for seven days.",
  "trust.request.name.label": "Your name",
  "trust.request.email.label": "Work email",
  "trust.request.company.label": "Company",
  "trust.request.terms.body": "These documents are provided by {name} so you can evaluate it as a supplier. You agree to use them only for that purpose, not to share them outside your organisation, and to delete your copies when the evaluation ends. This is an undertaking between you and {name}. Snoopios hosts the documents and keeps a record of the request and each download.",
  "trust.request.terms.label": "I agree to the confidentiality undertaking",
  "trust.request.submit": "Send request",
  "trust.request.sent.title": "Request sent",
  "trust.request.sent.body": "The team has been told. If they approve, a link arrives at the address you gave, from Snoopios. Check spam if it is slow.",
  "trust.request.error.invalid": "Check the name, email and company and try again.",
  "trust.request.error.rate": "Too many requests for this page. Try again tomorrow, or contact the team directly.",
  "trust.request.error.captcha": "The challenge did not complete. Reload the page and try again.",
  "trust.access.title": "Documents for review",
  "trust.access.confidential": "Confidential. Provided under the confidentiality undertaking accepted when access was requested.",
  "trust.access.expires": "This link works until",
  "trust.access.download": "Download",
  "trust.access.expired.title": "This link has expired or is not valid",
  "trust.access.expired.body": "Approved links work for seven days. Request access again from the trust page and the team can issue a new one.",
  "trust.docs.settings.title": "Documents on the trust page",
  "trust.docs.settings.body": "Tick the pack documents visitors may request. Every request needs your approval, approved links work for seven days, and each download is recorded below.",
  "trust.docs.settings.save": "Save documents",
  "trust.docs.settings.error": "The documents could not be saved. Try again.",
  "trust.requests.title": "Access requests",
  "trust.requests.empty": "No requests yet. The trust page shows a request button once a document is ticked.",
  "trust.requests.approve": "Approve",
  "trust.requests.decline": "Decline",
  "trust.requests.approved": "Approved",
  "trust.requests.declined": "Declined",
  "trust.requests.expires": "link until",
  "trust.requests.downloads": "downloads",
  "trust.requests.accepted": "accepted the undertaking",
  "trust.requests.issued": "Approved. The link was emailed; if it does not arrive, pass this on yourself:",
  "trust.requests.unsent": "Approved, but the email did not send. Pass this link on yourself:",
  "trust.requests.error": "That request could not be updated. It may already be decided.",
  "trust.mail.owner.subject": "New document access request",
  "trust.mail.owner.body": "Someone has asked for the documents on the trust page of",
  "trust.mail.owner.cta": "Review it here:",
  "trust.mail.visitor.subject": "Your document access was approved",
  "trust.mail.visitor.body": "The team behind",
  "trust.mail.visitor.body2": "approved your request. This link works for seven days and each download is recorded:",
  // ── notifications (email; names and counts only) ──────────────────────────
  "notify.fail.subject": "New failing checks on",
  "notify.fail.intro": "The last run found new failures on",
  "notify.fail.link": "Open the project:",
  "notify.fail.outro": "You get one email per run that introduces a failure, and none for repeats. Reply to this email to reach a person.",
  // ── check copy: stripe ────────────────────────────────────────────────────
  "check.stripe.webhooks.healthy.title": "Webhook endpoints enabled, pinned and pointing at production",
  "check.stripe.webhooks.healthy.pass": "Every webhook endpoint is enabled, pinned to an API version, and uses a production HTTPS URL.",
  "check.stripe.webhooks.healthy.fail": "A webhook endpoint is disabled, has no pinned API version, or points at a local, preview or tunnel URL.",
  "check.stripe.webhooks.healthy.fix": "Developers \u2192 Webhooks: re-enable disabled endpoints (Stripe disables after repeated failures), set an explicit API version on each so an account upgrade cannot change event shapes under you, and delete endpoints left over from tunnels and preview deployments.",
  "check.stripe.webhooks.deliveries.title": "No undelivered webhook events in 30 days",
  "check.stripe.webhooks.deliveries.pass": "Every event in the last 30 days was delivered.",
  "check.stripe.webhooks.deliveries.fail": "Events failed delivery in the last 30 days. Money moved at Stripe that your database may not know about.",
  "check.stripe.webhooks.deliveries.fix": "Developers \u2192 Webhooks \u2192 the endpoint \u2192 Failed. Fix the cause (signature secret, proxy in front of the route, a 500) and resend the failed events from the dashboard so your records catch up.",
  // ── check copy: cloudflare ────────────────────────────────────────────────
  "check.cloudflare.tls.strict.title": "TLS mode Full (strict), minimum TLS 1.2",
  "check.cloudflare.tls.strict.pass": "Every zone uses Full (strict) to the origin and refuses TLS below 1.2.",
  "check.cloudflare.tls.strict.fail": "A zone uses Flexible or Full without certificate validation, or accepts TLS 1.0 or 1.1.",
  "check.cloudflare.tls.strict.fix": "SSL/TLS \u2192 Overview \u2192 Full (strict), which needs a valid certificate on the origin (Cloudflare's origin certificate is free). Then Edge Certificates \u2192 Minimum TLS Version \u2192 1.2.",
  "check.cloudflare.https.always.title": "Always HTTPS with HSTS at the edge",
  "check.cloudflare.https.always.pass": "Every zone redirects HTTP and sends HSTS for a year with subdomains.",
  "check.cloudflare.https.always.fail": "A zone serves plain HTTP or sends no year-long HSTS covering subdomains.",
  "check.cloudflare.https.always.fix": "SSL/TLS \u2192 Edge Certificates: turn on Always Use HTTPS and enable HSTS with max-age 12 months and Apply to subdomains. Leave preload off until you have submitted at hstspreload.org.",
  "check.cloudflare.zone.dnssec.title": "DNSSEC active",
  "check.cloudflare.zone.dnssec.pass": "DNSSEC is active on every zone.",
  "check.cloudflare.zone.dnssec.fail": "A zone has DNSSEC off or still pending at the registrar.",
  "check.cloudflare.zone.dnssec.fix": "DNS \u2192 Settings \u2192 Enable DNSSEC, then add the DS record Cloudflare shows at your registrar. It stays pending until the DS record is live.",
  "check.cloudflare.waf.managed.title": "WAF managed ruleset deployed",
  "check.cloudflare.waf.managed.pass": "A managed ruleset runs in the firewall phase on every zone: one you deployed, or on the Free plan the Free Managed Ruleset Cloudflare applies itself.",
  "check.cloudflare.waf.managed.fail": "A zone has no managed ruleset deployed, so known attack patterns reach the origin.",
  "check.cloudflare.waf.managed.fix": "Security \u2192 WAF \u2192 Managed rules \u2192 deploy the Cloudflare Managed Ruleset (Pro and above) or the Free Managed Ruleset. There is no longer a global WAF switch; the ruleset is the control.",
  "check.cloudflare.bot.fight_mode.title": "Bot protection on",
  "check.cloudflare.bot.fight_mode.pass": "Bot Fight Mode or Super Bot Fight Mode is enabled on every zone.",
  "check.cloudflare.bot.fight_mode.fail": "A zone has no bot protection enabled.",
  "check.cloudflare.bot.fight_mode.fix": "Security \u2192 Bots \u2192 enable Bot Fight Mode (Free) or configure Super Bot Fight Mode (Pro and above). Exempt your own API clients first or they will be challenged.. Bot Fight Mode challenges automated clients including uptime monitors and Snoopios's own domain checks, which then report unknown; on the Free plan it cannot be bypassed for chosen clients. If that matters more than the bot filtering, leave it off, record the acceptance here, and revisit with Super Bot Fight Mode on the Pro plan.",
  "check.cloudflare.r2.no_public_bucket.title": "No R2 bucket exposed through r2.dev",
  "check.cloudflare.r2.no_public_bucket.pass": "No bucket served under this project's zones has the public r2.dev URL enabled. Public buckets that belong to other products on the account are listed in the result, not counted.",
  "check.cloudflare.r2.no_public_bucket.fail": "A bucket served under one of this project's zones is reachable by anyone through its r2.dev URL, bypassing every access control on your real endpoint.",
  "check.cloudflare.r2.no_public_bucket.fix": "R2 \u2192 bucket \u2192 Settings \u2192 Public access \u2192 disable the r2.dev subdomain. Serve public assets through a custom domain behind Access or the WAF instead.",
  "check.cloudflare.turnstile.widgets.title": "Turnstile widget covers every zone",
  "check.cloudflare.turnstile.widgets.pass": "A Turnstile widget exists whose domains cover every checked zone.",
  "check.cloudflare.turnstile.widgets.fail": "A zone has no Turnstile widget, so its sign-up and sign-in doors have no bot check.",
  "check.cloudflare.turnstile.widgets.fix": "Turnstile \u2192 Add widget with the zone's hostnames, then deploy the widget in the app before enabling captcha verification at the auth provider.",
  // ── check copy: github ────────────────────────────────────────────────────
  "check.github.org.2fa.title": "Two-factor authentication required on the organisation or account",
  "check.github.org.2fa.pass": "Every member must have 2FA to access the organisation, or, for a personal account, the account itself has 2FA on.",
  "check.github.org.2fa.fail": "The organisation does not require two-factor authentication, or the personal account that owns the code has none.",
  "check.github.org.2fa.fix": "Organisation settings \u2192 Authentication security \u2192 Require two-factor authentication (members without it are removed, so warn them first). For a personal account: Settings \u2192 Password and authentication \u2192 Enable two-factor.",
  "check.github.repo.default_branch_protected.title": "Default branch protected on every repository",
  "check.github.repo.default_branch_protected.pass": "Every active repository has a ruleset or classic protection on its default branch.",
  "check.github.repo.default_branch_protected.fail": "At least one repository accepts direct pushes or force-pushes to its default branch.",
  "check.github.repo.default_branch_protected.fix": "Add a ruleset on the default branch: require a pull request with one approval, block force pushes and deletions, and require status checks once CI exists. Apply it at organisation level so new repositories inherit it.",
  "check.github.repo.secret_scanning.title": "Secret scanning and push protection on",
  "check.github.repo.secret_scanning.pass": "Every repository has secret scanning enabled. Where the connection is a personal token, push protection cannot be read and is listed as unverified in the result.",
  "check.github.repo.secret_scanning.fail": "At least one repository is not scanned for pushed credentials. A private repository under a personal account cannot be: GitHub sells Secret Protection only to organisations on Team or Enterprise, so the result says whether it is purchasable at all.",
  "check.github.repo.secret_scanning.fix": "Organisation on Team or Enterprise: Security settings \u2192 enable Secret Protection (secret scanning and push protection) for the organisation or the repository. Personal account: it cannot be bought; either move the repository into an organisation on Team, or accept the risk here and state how secrets are kept out of git (ignored env files, a secrets manager, pre-commit scanning), with a review date.",
  "check.github.repo.dependabot.title": "Dependabot alerts on with no open critical or high",
  "check.github.repo.dependabot.pass": "Dependabot alerts are enabled everywhere and nothing critical or high is open.",
  "check.github.repo.dependabot.fail": "Dependabot alerts are off on a repository, or critical or high alerts are open.",
  "check.github.repo.dependabot.fix": "Enable Dependabot alerts and security updates under Code security. Then work the open critical and high alerts: update, or record why an alert does not apply and dismiss it with a reason.",
  "check.github.repo.no_env_committed.title": "No .env file committed",
  "check.github.repo.no_env_committed.pass": "No .env file is present on any default branch. Example files are fine.",
  "check.github.repo.no_env_committed.fail": "A .env file is committed. Treat every secret in it as leaked.",
  "check.github.repo.no_env_committed.fix": "Rotate every key in the file first, then remove it from history (git filter-repo) and add .env* to .gitignore with a committed .env.example. Removing the file without rotating is theatre; the history still has it.",
  "check.github.repo.hygiene.title": ".gitignore covers .env; SECURITY.md and CODEOWNERS present",
  "check.github.repo.hygiene.pass": "Every repository ignores .env files and carries a SECURITY.md and a CODEOWNERS file.",
  "check.github.repo.hygiene.fail": "A repository is missing one of: an .env rule in .gitignore, SECURITY.md, CODEOWNERS.",
  "check.github.repo.hygiene.fix": "Add .env and .env*.local to .gitignore. Add SECURITY.md pointing at security@your-domain and your disclosure policy. Add CODEOWNERS so reviews are routed to a named person.",
  "check.github.org.outside_collaborators.title": "Outside collaborators reviewed",
  "check.github.org.outside_collaborators.pass": "No outside collaborators have access to the organisation's repositories.",
  "check.github.org.outside_collaborators.fail": "Outside collaborators have repository access. Review each one; access that outlives the contract is the usual finding.",
  "check.github.org.outside_collaborators.fix": "Organisation \u2192 People \u2192 Outside collaborators. Remove anyone whose engagement has ended and convert long-term contributors to members so 2FA enforcement covers them.",
  // ── providers ─────────────────────────────────────────────────────────────
  "provider.supabase": "Supabase",
  "provider.vercel": "Vercel",
  "provider.github": "GitHub",
  "provider.cloudflare": "Cloudflare",
  "provider.stripe": "Stripe",
  "provider.domain": "Your domain",
  // ── check detail ──────────────────────────────────────────────────────────
  "check.unknown.generic": "This check could not run on the last attempt. That is reported as unknown, never as a pass.",
  "check.fix.title": "How to fix it",
  "check.observed.title": "What was observed",
  "check.errorscope": "Failed call:",
  "check.evidence.download": "Download evidence",
  "check.maps": "Gives evidence for:",
  "check.history.title": "Recent runs",
  // ── check copy: domain ────────────────────────────────────────────────────
  // One title, one pass sentence, one fail sentence, one fix per check. The
  // fix is written once here and reviewed; no model is in this path.
  "check.domain.https.redirect.title": "HTTP redirects to HTTPS",
  "check.domain.https.redirect.pass": "Plain HTTP answers with a redirect to the HTTPS origin.",
  "check.domain.https.redirect.fail": "Plain HTTP serves content or redirects somewhere other than HTTPS.",
  "check.domain.https.redirect.fix": "Redirect every http:// request to https:// with a 301 or 308 at the edge. On Cloudflare, turn on Always Use HTTPS. On Vercel this is the default; check a custom domain isn't bypassing it.",
  "check.domain.headers.hsts.title": "HSTS is set with a year and includeSubDomains",
  "check.domain.headers.hsts.pass": "Strict-Transport-Security has max-age of at least a year and covers subdomains.",
  "check.domain.headers.hsts.fail": "Strict-Transport-Security is missing, shorter than a year, or leaves subdomains reachable over plain HTTP.",
  "check.domain.headers.hsts.fix": "Send Strict-Transport-Security: max-age=63072000; includeSubDomains on every HTTPS response. Without includeSubDomains a subdomain stays cookie-strippable. Add preload only once you're ready to submit at hstspreload.org; it is hard to reverse.",
  "check.domain.headers.csp.title": "A Content-Security-Policy that stops injected script",
  "check.domain.headers.csp.pass": "A CSP is present with object-src 'none', base-uri 'self', a framing rule, and a script-src that does not allow inline script, eval or any origin.",
  "check.domain.headers.csp.fail": "No CSP, or one missing object-src 'none', base-uri 'self' or a framing rule, or a script-src that allows inline script, eval or any origin.",
  "check.domain.headers.csp.fix": "Ship object-src 'none', base-uri 'self', form-action 'self' and frame-ancestors 'none'. Then close script-src: a per-request nonce is the usual answer for a framework that needs inline bootstrap script, and 'strict-dynamic' or a hash also work. 'unsafe-inline' beside a nonce is ignored by browsers that honour the nonce, so it is safe to keep for older ones.",
  "check.domain.headers.basics.title": "nosniff, framing protection, referrer policy, no server fingerprint",
  "check.domain.headers.basics.pass": "X-Content-Type-Options, a framing rule and a Referrer-Policy are set, and no server version is advertised.",
  "check.domain.headers.basics.fail": "One or more of nosniff, a framing rule, Referrer-Policy is missing, or the Server or X-Powered-By header reveals software versions.",
  "check.domain.headers.basics.fix": "Send X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, and either frame-ancestors in the CSP or X-Frame-Options: DENY. Remove X-Powered-By and any Server header that carries a version.",
  "check.domain.tls.modern.title": "TLS 1.2 or newer, certificate not about to expire",
  "check.domain.tls.modern.pass": "The handshake negotiated TLS 1.2 or 1.3 and the certificate has more than 14 days left.",
  "check.domain.tls.modern.fail": "The handshake used an old protocol or the certificate expires within 14 days.",
  "check.domain.tls.modern.fix": "Set the minimum TLS version to 1.2 at the edge (Cloudflare: SSL/TLS \u2192 Edge Certificates \u2192 Minimum TLS Version). If the certificate is close to expiry and auto-renewal is on, check the renewal isn't failing on a CAA record or a DNS change.",
  "check.domain.hsts.preload.title": "On the HSTS preload list",
  "check.domain.hsts.preload.pass": "The domain, or a parent, is on the browser preload list.",
  "check.domain.hsts.preload.fail": "The domain is not on the browser preload list. Low severity: preloading is a commitment, not a requirement.",
  "check.domain.hsts.preload.fix": "Only if every subdomain will always serve HTTPS: add preload to the HSTS header and submit at hstspreload.org. Removal takes months, so this is a deliberate choice rather than a box to tick.",
  "check.domain.dns.spf.title": "SPF record present with a fail policy",
  "check.domain.dns.spf.pass": "Exactly one SPF record, ending in -all or ~all.",
  "check.domain.dns.spf.fail": "No SPF record, more than one, or one that ends in +all or ?all.",
  "check.domain.dns.spf.fix": "Publish one TXT record at the apex: v=spf1 include:<your sender> -all. Two SPF records is an error in the standard and receivers treat it as none. Include every service that sends as your domain, including transactional email.",
  "check.domain.dns.dmarc.title": "DMARC policy is quarantine or reject",
  "check.domain.dns.dmarc.pass": "_dmarc has a policy of quarantine or reject.",
  "check.domain.dns.dmarc.fail": "No DMARC record, or a policy of none, which only monitors.",
  "check.domain.dns.dmarc.fix": "Publish a TXT record at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>. Quarantine applies to every failing message from the moment you publish it; pct= exists to ramp that in more slowly and is not a later step. Read the aggregate reports until every legitimate sender aligns, then move to reject.",
  "check.domain.dns.caa.title": "CAA record limits who can issue certificates",
  "check.domain.dns.caa.pass": "A CAA record names the permitted certificate authorities.",
  "check.domain.dns.caa.fail": "No CAA record: any authority may issue a certificate for this domain.",
  "check.domain.dns.caa.fix": 'Add CAA records naming your issuer, for example 0 issue "letsencrypt.org" plus the CA your host uses. Vercel and Cloudflare both document which to allow. Get it wrong and renewals fail, so add and test before the next renewal.',
  "check.domain.securitytxt.title": "security.txt is published and current",
  "check.domain.securitytxt.pass": "/.well-known/security.txt is served with a Contact and an unexpired Expires.",
  "check.domain.securitytxt.fail": "No security.txt, or one without Contact, or with an Expires in the past.",
  "check.domain.securitytxt.fix": "Serve a text/plain file at /.well-known/security.txt with Contact: mailto:security@<domain> and Expires: a date under a year away. It is how a researcher reaches you before they reach a journalist.",
  "check.domain.privacy.page.title": "Privacy page names a controller and a date",
  "check.domain.privacy.page.pass": "A privacy page was found that names a company and carries an updated or effective date, with no pending markers.",
  "check.domain.privacy.page.fail": "No privacy page at the usual paths, or one without a named controller, without a date, or with a placeholder marker still in it. These are indicators, not a legal verdict.",
  "check.domain.privacy.page.fix": "Serve the policy at /privacy. Name the legal entity that is the controller and how to contact it, state the last-updated date from the document itself rather than a file timestamp, and never publish a draft with a [PENDING] marker in it.",
  // ── check copy: supabase ──────────────────────────────────────────────────
  "check.supabase.rls.all_tables.title": "Row-level security on every public table",
  "check.supabase.rls.all_tables.pass": "Every table in the public schema has RLS enabled.",
  "check.supabase.rls.all_tables.fail": "At least one public table has RLS off and is readable by anyone holding the anon key, which ships in your browser bundle.",
  "check.supabase.rls.all_tables.fix": "alter table public.<table> enable row level security; then write the policies it needs in the same migration. RLS on with no policies denies everything, which is the safe starting point.",
  "check.supabase.rls.no_anon_write.title": "No policy lets anon write",
  "check.supabase.rls.no_anon_write.pass": "No INSERT, UPDATE, DELETE or ALL policy admits the anon or public role.",
  "check.supabase.rls.no_anon_write.fail": "A policy lets unauthenticated requests write to a public table.",
  "check.supabase.rls.no_anon_write.fix": "Restrict write policies to authenticated (to authenticated) with a using and with check clause tied to auth.uid(). Unauthenticated writes belong behind a server route with the service role and a rate limit.",
  "check.supabase.private.closed.title": "Private schema closed to session roles",
  "check.supabase.private.closed.pass": "Neither anon nor authenticated has usage on the private schema, or there is no private schema.",
  "check.supabase.private.closed.fail": "A session role has usage on the private schema, so its functions are one PostgREST setting away from being callable.",
  "check.supabase.private.closed.fix": "revoke usage on schema private from anon, authenticated; and expose only thin public wrappers that cannot name a user or an org.",
  "check.supabase.definer.search_path.title": "SECURITY DEFINER functions pin search_path",
  "check.supabase.definer.search_path.pass": "Every SECURITY DEFINER function you own sets search_path. Schemas Supabase manages are not counted, because you cannot alter them.",
  "check.supabase.definer.search_path.fail": "A SECURITY DEFINER function has no search_path, so a caller can put a schema in front and run their own code as the definer.",
  "check.supabase.definer.search_path.fix": "Add set search_path = '' to each function and schema-qualify every reference inside it. This is the most common SECURITY DEFINER vulnerability and the cheapest to fix.",
  "check.supabase.views.security_invoker.title": "Views in public respect the caller, not their creator",
  "check.supabase.views.security_invoker.pass": "Every view in the public schema is defined with security_invoker, so it runs with the permissions of whoever queries it and the row-level security on the tables underneath still applies.",
  "check.supabase.views.security_invoker.fail": "At least one view in the public schema runs as the admin who created it. Postgres views default this way, so the view returns every row of the tables underneath regardless of the policies written on them, to anyone who can reach the API.",
  "check.supabase.views.security_invoker.fix": "alter view public.<name> set (security_invoker = on); then read the view back as an anonymous user and confirm it returns what it should. Needs Postgres 15 or later. A materialised view or a foreign table cannot carry the option at all: move it out of public, or revoke select from anon and authenticated.",
  "check.supabase.functions.anon_callable.title": "Anon-callable SECURITY DEFINER functions are safe to expose",
  "check.supabase.functions.anon_callable.pass": "Every SECURITY DEFINER function the anon role can execute pins its search_path and takes no caller-supplied identity. They are listed for review.",
  "check.supabase.functions.anon_callable.fail": "An unauthenticated request can execute a definer function that has no pinned search_path, or that accepts a user, org or account id as an argument.",
  "check.supabase.functions.anon_callable.fix": "For each function listed: add set search_path = '' and remove any user_id, org_id or account_id parameter, deriving identity from auth.uid() inside. If anon has no business calling it, revoke execute on function public.<name>(...) from anon.",
  "check.supabase.auth.confirmations.title": "Email confirmation on, OTP of 8 or more",
  "check.supabase.auth.confirmations.pass": "Sign-ups must confirm their address and the email OTP is at least 8 characters.",
  "check.supabase.auth.confirmations.fail": "Sign-ups are auto-confirmed or the OTP is short enough to guess.",
  "check.supabase.auth.confirmations.fix": "In Authentication settings turn on Confirm email and set the OTP length to 8 or more. Turning confirmation on is a product change too: make sure the app has a confirmation screen and the trial clock starts at confirmation.",
  "check.supabase.auth.password_policy.title": "Password minimum of twelve or more",
  "check.supabase.auth.password_policy.pass": "Passwords must be at least twelve characters. Length is what makes a password hard to guess, and this is the minimum the product asks of itself.",
  "check.supabase.auth.password_policy.fail": "Passwords may be shorter than twelve characters. A short minimum is the one password setting an attacker can count on.",
  "check.supabase.auth.password_policy.fix": "Authentication \u2192 Sign In / Providers \u2192 Email \u2192 Minimum password length: set 12 or more. Leave Password requirements at \u201CNo required characters (default)\u201D: composition rules make passwords predictable, and leaked-password protection does the job they were meant to do.",
  "check.supabase.auth.captcha.title": "Captcha on the auth doors",
  "check.supabase.auth.captcha.pass": "A captcha provider is enabled for sign-up and sign-in.",
  "check.supabase.auth.captcha.fail": "No captcha: sign-up and sign-in are open to scripted abuse.",
  "check.supabase.auth.captcha.fix": "Deploy the Turnstile widget in the app first, then enable it under Authentication \u2192 Bot and abuse protection. Reversing the order breaks sign-up for everyone.",
  "check.supabase.auth.site_url.title": "Auth site URL is your production HTTPS origin",
  "check.supabase.auth.site_url.pass": "The site URL is an https:// origin and not localhost.",
  "check.supabase.auth.site_url.fail": "The site URL is localhost or plain HTTP, so every auth email links to the wrong place.",
  "check.supabase.auth.site_url.fix": "Set Site URL to https://<your domain> and add your preview origins to the redirect allow-list. If you use supabase config push, make site_url an env() reference so the local value never reaches production.",
  "check.supabase.auth.smtp.title": "Production SMTP configured for auth email",
  "check.supabase.auth.smtp.pass": "A custom SMTP host is configured.",
  "check.supabase.auth.smtp.fail": "Auth email uses Supabase's built-in mailer, which is rate limited and not meant for production.",
  "check.supabase.auth.smtp.fix": "Configure a transactional sender (Resend, Postmark, SES) under Authentication \u2192 SMTP with a verified domain, SPF, DKIM and DMARC.",
  "check.supabase.backups.title": "Backups or point-in-time recovery enabled",
  "check.supabase.backups.pass": "PITR is on, or completed backups exist.",
  "check.supabase.backups.fail": "No PITR and no completed backups were found.",
  "check.supabase.backups.fix": "Enable point-in-time recovery under Database \u2192 Backups, or at least confirm daily backups are completing. Restore one to a scratch project once so the runbook is real.",
  "check.supabase.storage.no_public_bucket.title": "No undeclared public storage bucket",
  "check.supabase.storage.no_public_bucket.pass": "No storage bucket is public.",
  "check.supabase.storage.no_public_bucket.fail": "At least one bucket is public: every object in it is readable by URL with no policy check.",
  "check.supabase.storage.no_public_bucket.fix": "Make the bucket private and serve objects through signed URLs, or keep it public only for genuinely public assets and record that decision. A public bucket that holds user uploads is a breach waiting for a URL.",
  "check.supabase.db.ssl_enforced.title": "SSL enforced on database connections",
  "check.supabase.db.ssl_enforced.pass": "Direct database connections must use SSL.",
  "check.supabase.db.ssl_enforced.fail": "Unencrypted database connections are accepted.",
  "check.supabase.db.ssl_enforced.fix": "Turn on Enforce SSL under Database \u2192 Settings. Check your connection strings carry sslmode=require first, or you'll lock yourself out.",
  "nav.tab.plan": "Plan",
  "nav.tab.support": "Support",
  "nav.tab.settings": "Settings",
  // ── settings ──────────────────────────────────────────────────────────────
  "settings.title": "Settings",
  "settings.you.title": "You",
  "settings.you.name.label": "Your name",
  "settings.you.name.placeholder": "Shown to your team and in emails",
  "settings.org.title": "Organisation",
  "settings.org.name.label": "Organisation name",
  "settings.org.owneronly": "Only the owner can rename the organisation.",
  "settings.org.error.name": "Give the organisation a name.",
  "settings.save": "Save",
  "settings.saved": "Saved.",
  "settings.data.title": "Your data",
  "settings.data.body": "Everything this account participates in, as one JSON file: profile, organisation, projects, connections (without secrets), findings and check runs with evidence references.",
  "account.export.cta": "Export my data",
  "account.delete.title": "Delete this account",
  "account.delete.body": "Deletion starts a 30-day grace period you can cancel from this page. After it, the organisation, its projects, connections, evidence and this sign-in are removed for good. If other people belong to the organisation, you leave it and their history stays.",
  "account.delete.request": "Request deletion",
  "account.delete.pending": "Deletion is scheduled for",
  "account.delete.cancel": "Keep my account",
  "account.delete.now": "Delete now",
  "account.delete.confirm": "Delete the account now? This removes the organisation, every project, all evidence and your sign-in. There is no undo.",
  // ── accepted risks ────────────────────────────────────────────────────────
  // A failing check the customer chose to live with. The status stays fail
  // everywhere; the tag says it was a decision. (decisions.md, 6 Sep 2026)
  "accept.tag": "Accepted",
  "accept.title": "Accept this risk",
  "accept.body": "If this failure is a considered decision rather than an oversight, record why and for how long. The check keeps running and keeps reporting fail; the trust page shows an Accepted tag beside it; the first-fail email stays quiet until the acceptance lapses.",
  "accept.reason.label": "Why is this acceptable for now?",
  "accept.reason.placeholder": "For example: the marketing site has no forms, so a Content-Security-Policy adds nothing until the app moves to this domain.",
  "accept.months.label": "Review again in",
  "accept.months.1": "1 month",
  "accept.months.3": "3 months",
  "accept.months.6": "6 months",
  "accept.months.12": "12 months",
  "accept.submit": "Record the acceptance",
  "accept.error": "The acceptance could not be recorded. Only a failing check can be accepted, and the reason needs at least ten characters.",
  "accept.active.title": "Accepted risk",
  "accept.active.until": "Review by",
  "accept.active.by": "Recorded by",
  "accept.withdraw": "Withdraw",
  "trust.accepted.legend": "Accepted marks a failing check the team has reviewed and chosen to carry for now, with a review date. It is still a fail.",
  "notify.expired.subject": "An accepted risk has lapsed on",
  "notify.expired.intro": "These checks were accepted for a period that has now ended, and they still fail on",
  "notify.expired.outro": "Fix them, or record a fresh acceptance with a new review date.",
  // ── framework coverage ────────────────────────────────────────────────────
  "coverage.title": "Framework coverage",
  "coverage.intro": "Every control each framework names, and what stands behind it on this project: an automated check with its live result, a document you attached, a statement you confirmed, a document in the pack, your hosting provider's report, a question the pack asks you, or nothing yet. The percentage counts everything but the questions.",
  "coverage.evidenced": "evidenced",
  "coverage.passing": "Automated checks passing:",
  "coverage.kind.automated": "Automated",
  "coverage.kind.document": "Document",
  "coverage.kind.manual": "You answer",
  "coverage.kind.none": "Not covered",
  "coverage.provider": "held by your hosting provider",
  "coverage.legend": "Evidenced means an automated check, an accepted document of yours, a statement you confirmed within the last twelve months, a generated document, or your hosting provider's report exists for the control. Held by your hosting provider marks controls such as data-centre security that your cloud provider attests to; they count only once that provider's report is attached, and never as ours. A percentage here is coverage of the checklist, never a statement that you are certified.",
  "coverage.open": "Framework coverage",
  // ── email connector (no token; public DNS) ───────────────────────────────
  "provider.email": "Email",
  "provider.sentry": "Sentry",
  "provider.slack": "Slack",
  "provider.google": "Google Workspace",
  "provider.microsoft": "Microsoft 365",
  "provider.uptimerobot": "UptimeRobot",
  "provider.gitlab": "GitLab",
  "provider.netlify": "Netlify",
  "provider.neon": "Neon",
  "provider.render": "Render",
  "provider.fly": "Fly.io",
  "conn.email.title": "Connect transactional email",
  "conn.email.intro": "No key needed. Everything a receiving mail server uses to judge your sending domain is public DNS, so tell us the domain and the provider and the checks read what your recipients read.",
  "conn.email.domain.label": "Sending domain",
  "conn.email.domain.placeholder": "mail.example.com",
  "conn.email.esp.label": "Provider",
  "conn.email.esp.resend": "Resend",
  "conn.email.esp.postmark": "Postmark",
  "conn.email.esp.mailgun": "Mailgun",
  "conn.email.esp.ses": "Amazon SES",
  "conn.email.esp.other": "Other",
  "conn.email.advanced": "Advanced: selector and return path",
  "conn.email.selector.label": "DKIM selector",
  "conn.email.selector.placeholder": "resend",
  "conn.email.selector.hint": "Leave blank to use the provider's usual selector. Amazon SES and some others give you a unique one; paste it here.",
  "conn.email.returnpath.label": "Return-path subdomain",
  "conn.email.returnpath.placeholder": "send",
  "conn.email.returnpath.hint": "The subdomain your provider uses for bounces. Leave blank for the provider's default.",
  "conn.email.submit": "Connect email",
  "conn.sentry.title": "Connect Sentry",
  "conn.sentry.intro": "Create an organisation auth token with read scopes only: org:read, project:read, member:read, team:read. Sentry tells us which scopes a token carries, and a token that can write is refused when the checks run.",
  "conn.sentry.org.label": "Organisation slug",
  "conn.sentry.org.placeholder": "your-org",
  "conn.sentry.region.label": "Region",
  "conn.sentry.region.us": "United States (sentry.io)",
  "conn.sentry.region.eu": "European Union (de.sentry.io)",
  "conn.sentry.token.label": "Auth token",
  "conn.sentry.token.placeholder": "sntrys_\u2026",
  "conn.sentry.token.hint": "Settings \u2192 Auth Tokens \u2192 Create new token. Tick only the four read scopes. It is encrypted before it reaches the database.",
  "conn.sentry.cta": "Connect read-only",
  "conn.sentry.error.org": "An organisation slug is lowercase letters, digits and hyphens.",
  "conn.sentry.error.token": "That isn't a Sentry auth token. Create one under Settings \u2192 Auth Tokens with read scopes only.",
  "conn.sentry.error.auth": "Sentry refused that token. One cause is easy to miss: Sentry runs separate European and United States installations, and a token issued on one is unknown on the other. Check which one your organisation is on. Nothing has been saved.",
  "conn.sentry.error.org_invisible": "The token works, but that organisation is not one it belongs to. The slug is the part of your Sentry URL after the host. Nothing has been saved.",
  "conn.sentry.error.unreachable": "Sentry did not answer in a way we could read. Nothing has been saved; try again shortly.",
  "conn.slack.title": "Connect Slack",
  "conn.slack.intro": "Create a Slack app for your workspace with two user scopes, users:read and team:read, install it, and paste the token. Nothing else is requested: the checks read who has a second factor, who is an admin, who is a guest, and whether joining is restricted.",
  "conn.slack.workspace.label": "Workspace",
  "conn.slack.workspace.placeholder": "your-workspace",
  "conn.slack.token.label": "Token",
  "conn.slack.token.placeholder": "xoxp-\u2026",
  "conn.slack.token.hint": "api.slack.com/apps \u2192 your app \u2192 OAuth & Permissions. A user token from a workspace admin sees two-factor status; a member's token does not, and the check says so.",
  "conn.slack.cta": "Connect read-only",
  "conn.slack.error.workspace": "A workspace name is lowercase letters, digits and hyphens, as in your-workspace.slack.com.",
  "conn.slack.error.token": "That isn't a Slack user (xoxp-) or bot (xoxb-) token.",
  "conn.microsoft.title": "Connect Microsoft 365",
  "conn.microsoft.intro": "A Global Administrator consents once to five read-only Microsoft Graph permissions (users, directory, policies, authentication methods, sign-in activity). Only your tenant id is stored, encrypted; nothing is written, and a grant carrying a write permission is refused. Revoke any time by deleting the Snoopios enterprise app in Entra.",
  "conn.microsoft.cta": "Grant read-only access on Microsoft",
  "conn.microsoft.tenant.label": "Tenant ID (optional)",
  "conn.microsoft.tenant.placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "conn.microsoft.tenant.invalid": "A tenant id is 36 characters: eight, four, four, four and twelve hex digits separated by hyphens.",
  "conn.microsoft.tenant.hint": "Leave empty if your administrator signs in with a work account. If they sign in with a personal Microsoft account, Microsoft refuses the consent without a tenant: paste the Directory (tenant) ID from Entra \u2192 Overview.",
  "conn.microsoft.label": "Microsoft 365",
  "conn.microsoft.connected": "Microsoft 365 is connected. The first run starts within a minute.",
  "conn.microsoft.scopes": "Microsoft granted permissions other than the read-only set, so the connection was refused. Check the Snoopios app registration and try again.",
  "conn.microsoft.pending": "Microsoft accepted the consent but has not finished applying it. Wait a minute, then grant again from this page; the second pass connects without asking twice.",
  "conn.microsoft.denied": "The consent was cancelled or declined, so nothing was connected. A Global Administrator can grant it from this page.",
  "conn.microsoft.error": "The Microsoft grant did not complete. Try again from this page; if it repeats, email us.",
  "conn.microsoft.unconfigured": "Microsoft 365 is not switched on in this deployment yet. Snoopios registers the app in Entra first; email us if you need it sooner.",
  "check.microsoft.tenant.mfa_enforced.title": "Multi-factor authentication required for every user",
  "check.microsoft.tenant.mfa_enforced.pass": "Security defaults are on, or an enabled Conditional Access policy requires MFA for all users on all apps.",
  "check.microsoft.tenant.mfa_enforced.fail": "Neither security defaults nor a Conditional Access policy requires MFA for every user. Anyone with a password alone can sign in.",
  "check.microsoft.tenant.mfa_enforced.fix": "Entra admin centre \u2192 Identity \u2192 Overview \u2192 Properties \u2192 Manage security defaults \u2192 Enabled. On Entra ID P1, use a Conditional Access policy instead: all users, all cloud apps, grant requires multifactor authentication, with one excluded break-glass account.",
  "check.microsoft.users.mfa_registered.title": "Every user has registered a second factor",
  "check.microsoft.users.mfa_registered.pass": "Every enabled member account has an authenticator app, phone, FIDO2 key, Windows Hello or OATH token registered.",
  "check.microsoft.users.mfa_registered.fail": "At least one enabled account has only a password (or an email method, which serves password reset, not sign-in) registered.",
  "check.microsoft.users.mfa_registered.fix": "Ask each listed user to register at aka.ms/mfasetup. With MFA required, Entra prompts them on the next sign-in; the registration campaign under Protection \u2192 Authentication methods nudges anyone who defers.",
  "check.microsoft.admins.limited.title": "Global Administrator rights are held by few",
  "check.microsoft.admins.limited.pass": "At least one Global Administrator exists and no more than three, or a quarter of users, whichever is larger.",
  "check.microsoft.admins.limited.fail": "Too many, or no, users hold the Global Administrator role.",
  "check.microsoft.admins.limited.fix": "Entra admin centre \u2192 Roles and administrators \u2192 Global Administrator: remove the role from everyone who does not administer the tenant; give least-privilege roles (User Administrator, Exchange Administrator) instead. Keep a second Global Administrator as a break-glass account.",
  "check.microsoft.users.dormant.title": "No account unused for ninety days",
  "check.microsoft.users.dormant.pass": "Every enabled member account has signed in within ninety days, or was created within the last month.",
  "check.microsoft.users.dormant.fail": "At least one enabled account has not signed in for ninety days. A dormant account is an entry nobody is watching.",
  "check.microsoft.users.dormant.fix": "Entra admin centre \u2192 Users: block sign-in or delete each listed account, or hand its mailbox over and remove it under the leaver procedure. Sign-in activity needs Entra ID P1; on the free tier this check reads unknown, and the leaver review stays an attestation.",
  "conn.gitlab.title": "Connect GitLab",
  "conn.gitlab.intro": "Create an access token with only read_api and read_repository (User settings \u2192 Access tokens, or a group token). Snoopios reads the token's own scopes on every run and refuses it if anything else is on it, so this connection shows as read-only verified.",
  "conn.gitlab.owner.label": "Group path or username",
  "conn.gitlab.owner.placeholder": "your-group or your-group/sub-group or your-username",
  "conn.gitlab.host.label": "GitLab host",
  "conn.gitlab.host.hint": "Leave empty for gitlab.com. Self-managed: https://gitlab.example.com.",
  "conn.gitlab.projects.label": "Projects to check",
  "conn.gitlab.projects.placeholder": "app, api, website",
  "conn.gitlab.projects.hint": "Optional. Leave empty to check up to thirty active projects under the group.",
  "conn.gitlab.open.label": "Projects that are meant to be public",
  "conn.gitlab.open.placeholder": "docs, sdk",
  "conn.gitlab.token.label": "Access token",
  "conn.gitlab.token.placeholder": "glpat-\u2026",
  "conn.gitlab.token.hint": "Scopes: read_api and read_repository. Set an expiry. A token with api or write_repository is refused at run time.",
  "conn.gitlab.cta": "Connect read-only",
  "conn.gitlab.error.owner": "A group path or username is letters, digits, dots, hyphens and underscores, with slashes between sub-groups.",
  "conn.gitlab.error.host": "The host must be an https:// origin, like https://gitlab.example.com.",
  "conn.gitlab.error.token": "That isn't a GitLab access token (glpat-\u2026).",
  "conn.gitlab.error.auth": "GitLab refused that token. Check it was copied whole and has not expired, and that it is for the host above if you self-host. Nothing has been saved.",
  "conn.gitlab.error.access": "The token works, but that group or username is not one it can reach. A token only sees groups you are a member of, and a public group being visible in a browser does not mean the token can read it. Nothing has been saved.",
  "conn.gitlab.error.unreachable": "GitLab did not answer in a way we could read. Nothing has been saved; try again shortly.",
  "check.gitlab.group.2fa.title": "Two-factor authentication required on the group",
  "check.gitlab.group.2fa.pass": "The group requires every member to use two-factor authentication.",
  "check.gitlab.group.2fa.fail": "The group does not require two-factor authentication; a member with a phished password can push code.",
  "check.gitlab.group.2fa.fix": "Group \u2192 Settings \u2192 General \u2192 Permissions and group features \u2192 Require all users in this group to set up two-factor authentication, with a short grace period.",
  "check.gitlab.repo.default_branch_protected.title": "Default branch protected on every project",
  "check.gitlab.repo.default_branch_protected.pass": "Every active project protects its default branch: no force push, and nobody below Maintainer can push directly.",
  "check.gitlab.repo.default_branch_protected.fail": "At least one project lets developers push straight to the default branch, or allows force pushes.",
  "check.gitlab.repo.default_branch_protected.fix": "Project \u2192 Settings \u2192 Repository \u2192 Protected branches: protect the default branch, Allowed to push: No one or Maintainers, Allowed to merge: Maintainers, force push off.",
  "check.gitlab.repo.no_env_committed.title": "No .env file committed",
  "check.gitlab.repo.no_env_committed.pass": "No .env file is present on any default branch. Example files are fine.",
  "check.gitlab.repo.no_env_committed.fail": "A .env file is committed on a default branch. Treat every value in it as leaked.",
  "check.gitlab.repo.no_env_committed.fix": "Remove the file, rotate every secret it held, add .env* to .gitignore, and keep a .env.example with placeholder values.",
  "check.gitlab.repo.hygiene.title": ".gitignore covers .env; SECURITY.md and CODEOWNERS present",
  "check.gitlab.repo.hygiene.pass": "Every project ignores .env files and carries a SECURITY.md and a CODEOWNERS file.",
  "check.gitlab.repo.hygiene.fail": "At least one project is missing .env in .gitignore, a SECURITY.md, or a CODEOWNERS file.",
  "check.gitlab.repo.hygiene.fix": "Add .env* to .gitignore, a SECURITY.md that says how to report a vulnerability, and a CODEOWNERS file (root, .gitlab/ or docs/) naming who reviews what.",
  "check.gitlab.repo.secret_detection.title": "Secret detection runs in the pipeline",
  "check.gitlab.repo.secret_detection.pass": "Every project's pipeline includes GitLab's Secret Detection template.",
  "check.gitlab.repo.secret_detection.fail": "At least one project's pipeline does not run secret detection, so a committed key is not caught.",
  "check.gitlab.repo.secret_detection.fix": "In .gitlab-ci.yml add include: - template: Security/Secret-Detection.gitlab-ci.yml. It is free on every tier.",
  "check.gitlab.repo.visibility.title": "No project is public by accident",
  "check.gitlab.repo.visibility.pass": "Every project is private or internal, or was declared open source on the connection.",
  "check.gitlab.repo.visibility.fail": "At least one project is public without being declared open source.",
  "check.gitlab.repo.visibility.fix": "Project \u2192 Settings \u2192 General \u2192 Visibility: set to Private, or add the project to the open-source list on the Snoopios connection if it is meant to be public.",
  "check.gitlab.group.members_reviewed.title": "Group members reviewed",
  "check.gitlab.group.members_reviewed.pass": "No expired membership lingers, at least one Owner exists, and Owners are few.",
  "check.gitlab.group.members_reviewed.fail": "An expired member is still present, or Owner rights are held too widely.",
  "check.gitlab.group.members_reviewed.fix": "Group \u2192 Manage \u2192 Members: remove expired members, and reduce Owners to the people who administer the group; give Maintainer to the rest.",
  "check.netlify.site.force_https.title": "HTTPS forced on every site",
  "check.netlify.site.force_https.pass": "Plain HTTP on every site answered with a redirect to the HTTPS origin, asked of each site in turn.",
  "check.netlify.site.force_https.fail": "At least one site answered plain HTTP without redirecting to HTTPS.",
  "check.netlify.site.force_https.fix": "For a site on your own domain: Site configuration \u2192 Domain management \u2192 HTTPS \u2192 Force HTTPS. A site on its default netlify.app address has no such switch, because Netlify already redirects and preloads HSTS there, so a failure on one of those is worth reporting to us rather than fixing.",
  "check.netlify.site.protected.title": "Sites are behind site protection",
  "check.netlify.site.protected.pass": "Every site requires a password or a team login before it can be viewed, so previews and branch deploys are not public.",
  "check.netlify.site.protected.fail": "At least one site is open to anyone, so its deploy previews and branch deploys are public too.",
  "check.netlify.site.protected.fix": "Site settings \u2192 Access control \u2192 Site protection: set a password or restrict to team members. Read-only on Netlify's Pro plan and above; on the free plan, keep previews private by not publishing them or accept the risk with a review date.",
  "check.netlify.env.secrets_marked.title": "Secret-looking variables are marked secret",
  "check.netlify.env.secrets_marked.pass": "Every environment variable named like a secret is marked secret, so its value is only readable by code running on Netlify.",
  "check.netlify.env.secrets_marked.fail": "At least one variable named like a secret is not marked secret, so anyone with site access can read its value in the UI and API.",
  "check.netlify.env.secrets_marked.fix": "Site configuration \u2192 Environment variables \u2192 edit the variable \u2192 tick 'Contains secret values'. Public values (NEXT_PUBLIC_, VITE_, publishable keys) are not counted.",
  "check.netlify.site.headers.title": "Live sites send the basic hardening headers",
  "check.netlify.site.headers.pass": "Every site answers with a framing rule, nosniff and a Referrer-Policy.",
  "check.netlify.site.headers.fail": "At least one site is missing a framing rule (X-Frame-Options or CSP frame-ancestors), nosniff, or a Referrer-Policy.",
  "check.netlify.site.headers.fix": "Add a _headers file or [[headers]] in netlify.toml with X-Frame-Options: DENY (or a CSP frame-ancestors), X-Content-Type-Options: nosniff and Referrer-Policy: strict-origin-when-cross-origin, then deploy.",
  "check.neon.project.ip_allowlist.title": "Database reachable only from listed addresses",
  "check.neon.project.ip_allowlist.pass": "Every project restricts connections to an IP allow list or blocks public connections.",
  "check.neon.project.ip_allowlist.fail": "At least one project accepts connections from any address on the internet; the password is the only barrier.",
  "check.neon.project.ip_allowlist.fix": "Project settings \u2192 IP Allow: add your application's egress addresses (and 'protected branches only' if previews need open access), or enable private networking and block public connections. IP Allow needs Neon's Scale plan or above.",
  "check.neon.branch.default_protected.title": "Production branch protected",
  "check.neon.branch.default_protected.pass": "Every project's default branch is protected against deletion and reset.",
  "check.neon.branch.default_protected.fail": "At least one project's default branch can be deleted or reset by anyone with project access.",
  "check.neon.branch.default_protected.fix": "Branches \u2192 the default branch \u2192 Set as protected. Protected branches also keep their own passwords from being reused in previews.",
  "check.neon.project.history_retention.title": "Point-in-time restore of at least seven days",
  "check.neon.project.history_retention.pass": "Every project keeps at least seven days of history for point-in-time restore.",
  "check.neon.project.history_retention.fail": "At least one project keeps less than seven days of history, so a bad migration or deletion found next week cannot be undone.",
  "check.neon.project.history_retention.fix": "Project settings \u2192 Storage \u2192 History retention: set at least 7 days. The free plan allows up to 1 day; Launch allows 7 and Scale 30, so this may mean a plan change or an accepted risk with a review date.",
  "check.neon.branch.stale_previews.title": "No preview branch older than thirty days",
  "check.neon.branch.stale_previews.pass": "Every non-default branch is under thirty days old, so preview copies of production data do not linger.",
  "check.neon.branch.stale_previews.fail": "At least one child branch is more than thirty days old: a copy of production data nobody is using, with its own connection string.",
  "check.neon.branch.stale_previews.fix": "Branches \u2192 delete the stale branches, and set a TTL (expires_at) when creating preview branches so they remove themselves.",
  "check.render.service.health_check.title": "Every web service has a health check",
  "check.render.service.health_check.pass": "Every running web service has a health check path, so a failed deploy is rolled back instead of served.",
  "check.render.service.health_check.fail": "At least one web service has no health check path, so a broken deploy goes live and a dead instance stays in rotation.",
  "check.render.service.health_check.fix": "Service \u2192 Settings \u2192 Health Check Path: point it at an endpoint that returns 200 only when the service can serve requests, for example /healthz.",
  "check.render.service.custom_domains_verified.title": "Every custom domain verified",
  "check.render.service.custom_domains_verified.pass": "Every custom domain on every web service and static site is verified, so it serves the right certificate.",
  "check.render.service.custom_domains_verified.fail": "At least one custom domain is unverified: it serves a certificate error or the default Render page instead of the site.",
  "check.render.service.custom_domains_verified.fix": "Service \u2192 Settings \u2192 Custom Domains: add the DNS record Render shows for each unverified domain and wait for verification.",
  "check.render.service.notify_on_fail.title": "Someone hears when a deploy fails",
  "check.render.service.notify_on_fail.pass": "No service has deploy-failure notifications switched off.",
  "check.render.service.notify_on_fail.fail": "At least one service ignores deploy failures, so a broken production deploy can go unnoticed.",
  "check.render.service.notify_on_fail.fix": "Service \u2192 Settings \u2192 Notifications: set deploy failure notifications to notify (or the workspace default), and make sure the workspace default sends to a channel someone reads.",
  "provider.repo": "Repository",
  "check.repo.env_committed.title": "No .env file committed",
  "check.repo.env_committed.pass": "No .env file is tracked in the repository. Example files are fine.",
  "check.repo.env_committed.fail": "At least one .env file is tracked, so its values are in the history of every clone.",
  "check.repo.env_committed.fix": "git rm --cached the file, add it to .gitignore, rotate every value it held, then purge it from history with git filter-repo if the repository is shared.",
  "check.repo.gitignore_env.title": ".gitignore covers .env",
  "check.repo.gitignore_env.pass": "The .gitignore ignores .env files, so a local secrets file cannot be committed by accident.",
  "check.repo.gitignore_env.fail": "There is no .gitignore rule for .env files, so one git add . commits your secrets.",
  "check.repo.gitignore_env.fix": "Add .env and .env.* to .gitignore (keep !.env.example if you ship an example).",
  "check.repo.secrets_in_history.title": "No credential shape anywhere in the history",
  "check.repo.secrets_in_history.pass": "No line in the full git history matches a known credential shape (AWS, GitHub, GitLab, Stripe, Slack, Google, OpenAI, Supabase, private key blocks, Resend, Vercel, npm) outside test fixtures. Shapes inside test files are listed by path for you to confirm they are placeholders.",
  "check.repo.secrets_in_history.fail": "The git history contains at least one line outside test fixtures matching a known credential shape. A rotated secret is still a leak if the history is public or shared.",
  "check.repo.secrets_in_history.fix": "Rotate the credential first, then rewrite the history with git filter-repo and force-push, and ask every collaborator to re-clone. The result names the shape found, never the value.",
  "check.repo.lockfile.title": "Dependencies pinned by a lockfile",
  "check.repo.lockfile.pass": "Every package manifest has a lockfile next to it, so a build installs exactly what was reviewed.",
  "check.repo.lockfile.fail": "At least one package manifest has no lockfile, so each install may pull different versions than the last review.",
  "check.repo.lockfile.fix": "Run the package manager once (npm install, pnpm install, poetry lock, cargo build, go mod tidy) and commit the lockfile it writes.",
  "check.repo.hygiene.title": "SECURITY.md and CODEOWNERS present",
  "check.repo.hygiene.pass": "The repository carries a security contact and a code owner file.",
  "check.repo.hygiene.fail": "The repository is missing a SECURITY.md, a CODEOWNERS file, or both.",
  "check.repo.hygiene.fix": "Add SECURITY.md with how to report a vulnerability and CODEOWNERS naming who reviews what. A reviewer reads both as evidence of ownership.",
  "check.repo.dependency_updates.title": "Automated dependency updates configured",
  "check.repo.dependency_updates.pass": "Dependabot or Renovate is configured, so vulnerable dependencies are raised as pull requests.",
  "check.repo.dependency_updates.fail": "No Dependabot or Renovate configuration was found, so vulnerable dependencies wait for someone to notice.",
  "check.repo.dependency_updates.fix": "Add .github/dependabot.yml (or renovate.json) with a weekly schedule for your package ecosystem.",
  "check.repo.vulnerable_dependencies.title": "No open critical or high vulnerability in dependencies",
  "check.repo.vulnerable_dependencies.pass": "The dependency audit reports no critical or high vulnerability.",
  "check.repo.vulnerable_dependencies.fail": "The dependency audit reports at least one critical or high vulnerability in an installed dependency.",
  "check.repo.vulnerable_dependencies.fix": "Run npm audit fix (or update the affected package) and commit the lockfile. If a fix is not available, record the accepted risk with a review date.",
  "provider.heroku": "Heroku",
  "check.heroku.app.managed_certs.title": "Every custom domain serves a certificate",
  "check.heroku.app.managed_certs.pass": "Every custom domain on every app has an issued certificate.",
  "check.heroku.app.managed_certs.fail": "At least one custom domain has no certificate or one still pending, so it serves a certificate error or the wrong site.",
  "check.heroku.app.managed_certs.fix": "heroku certs:auto:enable -a <app> (Automated Certificate Management is free on paid dynos), then check the DNS target Heroku shows for the domain.",
  "check.heroku.app.maintenance_off.title": "No app left in maintenance mode",
  "check.heroku.app.maintenance_off.pass": "No app is in maintenance mode.",
  "check.heroku.app.maintenance_off.fail": "At least one app is in maintenance mode, serving the maintenance page to every visitor.",
  "check.heroku.app.maintenance_off.fix": "heroku maintenance:off -a <app> once the work is done, or remove the app if it is no longer used.",
  "check.heroku.app.stack_supported.title": "Every app on a supported stack",
  "check.heroku.app.stack_supported.pass": "Every app runs on a stack Heroku still patches (heroku-22, heroku-24 or container).",
  "check.heroku.app.stack_supported.fail": "At least one app runs on a stack Heroku no longer patches; its OS libraries receive no security updates.",
  "check.heroku.app.stack_supported.fix": "heroku stack:set heroku-24 -a <app> and redeploy. heroku-20 reached end of life in April 2025.",
  "check.heroku.formation.web_redundant.title": "Web tier survives one dyno",
  "check.heroku.formation.web_redundant.pass": "Every app that serves web traffic runs at least two web dynos.",
  "check.heroku.formation.web_redundant.fail": "At least one app serves web traffic from a single dyno, so a dyno restart is an outage.",
  "check.heroku.formation.web_redundant.fix": "heroku ps:scale web=2 -a <app> on Standard dynos or above. Low severity: a solo project may accept this with a review date.",
  "provider.clerk": "Clerk",
  "check.clerk.redirect_urls.https_only.title": "Redirect URLs are HTTPS and not local",
  "check.clerk.redirect_urls.https_only.pass": "Every allowed redirect URL is HTTPS and points at a real host.",
  "check.clerk.redirect_urls.https_only.fail": "At least one allowed redirect URL is plain HTTP or a local address, so a sign-in can be redirected to a page an attacker controls.",
  "check.clerk.redirect_urls.https_only.fix": "Clerk Dashboard \u2192 Configure \u2192 Paths / Redirect URLs (or the Backend API): remove localhost and http:// entries from the production instance; keep them on the development instance only.",
  "check.clerk.jwt_templates.short_lifetime.title": "JWT templates expire within an hour",
  "check.clerk.jwt_templates.short_lifetime.pass": "Every JWT template issues tokens that live an hour or less, or there are no templates.",
  "check.clerk.jwt_templates.short_lifetime.fail": "At least one JWT template issues tokens that live longer than an hour, so a leaked token stays valid for that long.",
  "check.clerk.jwt_templates.short_lifetime.fix": "Clerk Dashboard \u2192 Configure \u2192 JWT templates: set Token lifetime to 3600 seconds or less. Refresh through Clerk's session, not through long-lived tokens.",
  "check.clerk.users.dormant.title": "No dormant account able to sign in",
  "check.clerk.users.dormant.pass": "Every active account has signed in within ninety days, or was created within the last month.",
  "check.clerk.users.dormant.fail": "At least one account that can still sign in has not been active for ninety days, or never signed in and is older than a month.",
  "check.clerk.users.dormant.fix": "Clerk Dashboard \u2192 Users: ban or delete the dormant accounts, or accept the risk with a review date if this is a consumer product where dormancy is normal. Instances with more than five hundred users are not judged here.",
  "provider.atlas": "MongoDB Atlas",
  "check.atlas.project.ip_access_list.title": "Database reachable only from listed addresses",
  "check.atlas.project.ip_access_list.pass": "The project's IP access list names specific addresses; nothing admits the whole internet.",
  "check.atlas.project.ip_access_list.fail": "The project's IP access list admits every address (0.0.0.0/0), so the password is the only barrier.",
  "check.atlas.project.ip_access_list.fix": "Atlas \u2192 Network Access: replace 0.0.0.0/0 with your application's egress addresses, or use private endpoints and peering. For a serverless host with changing addresses, use a static egress IP or a private endpoint.",
  "check.atlas.cluster.backups_enabled.title": "Backups on every cluster",
  "check.atlas.cluster.backups_enabled.pass": "Every cluster has cloud backup enabled.",
  "check.atlas.cluster.backups_enabled.fail": "At least one cluster has backups off, so a bad migration or deletion cannot be undone.",
  "check.atlas.cluster.backups_enabled.fix": "Atlas \u2192 cluster \u2192 Backup: enable Cloud Backup with continuous backup if the tier allows. Shared tiers (M0, M2, M5) cannot; move production to M10 or above.",
  "check.atlas.cluster.version_supported.title": "Every cluster on a supported MongoDB version",
  "check.atlas.cluster.version_supported.pass": "Every cluster runs a MongoDB version that still receives patches.",
  "check.atlas.cluster.version_supported.fail": "At least one cluster runs a MongoDB version past its end of life; it no longer receives security patches.",
  "check.atlas.cluster.version_supported.fix": "Atlas \u2192 cluster \u2192 Edit configuration \u2192 MongoDB version: upgrade one major at a time to a supported release (8.0 as of 2026). Test against a restored copy first.",
  "check.atlas.cluster.termination_protection.title": "Termination protection on every cluster",
  "check.atlas.cluster.termination_protection.pass": "Every cluster has termination protection on, so it cannot be deleted by a stray click or script.",
  "check.atlas.cluster.termination_protection.fail": "At least one cluster can be deleted without a second step.",
  "check.atlas.cluster.termination_protection.fix": "Atlas \u2192 cluster \u2192 Edit configuration \u2192 Additional settings \u2192 Termination protection: on.",
  "check.atlas.db_users.least_privilege.title": "No database user holds a cluster-wide role",
  "check.atlas.db_users.least_privilege.pass": "Every database user holds only database-scoped roles.",
  "check.atlas.db_users.least_privilege.fail": "At least one database user holds an admin or cluster-wide role (atlasAdmin, root, readWriteAnyDatabase, readAnyDatabase, dbAdminAnyDatabase, userAdminAnyDatabase or clusterAdmin), so a leaked application credential reaches every database, not just its own.",
  "check.atlas.db_users.least_privilege.fix": "Atlas \u2192 Database Access: give application users readWrite on their own database only; keep admin roles for people, protected by Atlas login and MFA.",
  "stack.blurb.atlas": "MongoDB: IP access list, backups, version, termination protection, roles",
  "conn.atlas.title": "Connect MongoDB Atlas",
  "conn.atlas.intro": "Create a service account with the Project Read Only role (Atlas \u2192 Access Manager \u2192 Service Accounts) and paste its client id and secret with the project id. Snoopios exchanges them for one-hour tokens and only ever reads. Atlas gives no way to read the role back, so the connection shows as read-only requested; every request is limited to reads by code.",
  "conn.atlas.project.label": "Project ID",
  "conn.atlas.project.placeholder": "24 hex characters, from Project Settings",
  "conn.atlas.client.label": "Service account client ID",
  "conn.atlas.secret.label": "Service account client secret",
  "conn.atlas.secret.hint": "Shown once by Atlas. Rotate it from Access Manager \u2192 Service Accounts; the connection then needs re-entering.",
  "conn.atlas.cta": "Connect read-only",
  "conn.atlas.error.project": "A project id is 24 hex characters (Atlas \u2192 Project Settings \u2192 Project ID).",
  "conn.atlas.error.credentials": "The client id and secret look wrong. Both come from Access Manager \u2192 Service Accounts.",
  "provider.digitalocean": "DigitalOcean",
  "check.do.droplet.firewall.title": "Every public droplet behind a cloud firewall",
  "check.do.droplet.firewall.pass": "Every active droplet with a public address is attached to a cloud firewall, directly or by tag.",
  "check.do.droplet.firewall.fail": "At least one active droplet with a public address has no cloud firewall, so every port its software opens is reachable from the internet.",
  "check.do.droplet.firewall.fix": "Networking \u2192 Firewalls \u2192 create or edit a firewall allowing only 22 from your addresses and 80/443 from anywhere, and attach it to the droplet or its tag.",
  "check.do.droplet.backups.title": "Backups on every droplet",
  "check.do.droplet.backups.pass": "Every active droplet has automated backups enabled.",
  "check.do.droplet.backups.fail": "At least one active droplet has no automated backups, so a disk failure or a bad deploy loses it.",
  "check.do.droplet.backups.fix": "Droplet \u2192 Backups \u2192 Enable backups (weekly, 20% of the droplet price), or move state off the droplet to a managed database and object storage and accept the risk with a review date.",
  "check.do.database.trusted_sources.title": "Managed databases reachable only from trusted sources",
  "check.do.database.trusted_sources.pass": "Every managed database has at least one trusted-source rule, so it is not open to the whole internet.",
  "check.do.database.trusted_sources.fail": "At least one managed database has no trusted-source rules, so any address on the internet can attempt to connect.",
  "check.do.database.trusted_sources.fix": "Database \u2192 Settings \u2192 Trusted sources: add the droplets, apps, tags or addresses that need access. Databases with no rules accept connections from anywhere.",
  "check.do.database.version_supported.title": "Every managed database on a supported version",
  "check.do.database.version_supported.pass": "Every managed database runs an engine version that has not reached end of life.",
  "check.do.database.version_supported.fail": "At least one managed database runs an engine version past its end of life, so it no longer receives security patches.",
  "check.do.database.version_supported.fix": "Database \u2192 Settings \u2192 Version: upgrade to a supported release. DigitalOcean lists the end-of-life date on the cluster page.",
  "stack.blurb.digitalocean": "Droplets and managed databases: firewalls, backups, trusted sources, versions",
  "conn.digitalocean.title": "Connect DigitalOcean",
  "conn.digitalocean.intro": "Create a personal access token with the Read Only scope (API \u2192 Tokens \u2192 Generate new token \u2192 Read Only) and paste it. DigitalOcean gives no way to read a token's scopes back, so the connection shows as read-only requested; every request is limited to reads by code.",
  "conn.digitalocean.token.label": "Read-only personal access token",
  "conn.digitalocean.token.placeholder": "dop_v1_\u2026",
  "conn.digitalocean.token.hint": "Set an expiry. Revoke from API \u2192 Tokens.",
  "conn.digitalocean.cta": "Connect read-only",
  "conn.digitalocean.error.token": "That isn't a DigitalOcean personal access token (dop_v1_ followed by 64 hex characters).",
  "provider.upstash": "Upstash",
  "check.upstash.redis.tls.title": "TLS on every Redis database",
  "check.upstash.redis.tls.pass": "Every Upstash Redis database accepts encrypted connections only.",
  "check.upstash.redis.tls.fail": "At least one Upstash Redis database accepts unencrypted connections, so credentials and data cross the network in the clear.",
  "check.upstash.redis.tls.fix": "Upstash Console \u2192 the database \u2192 Details: TLS cannot be switched on after creation. Create a new database with TLS enabled, migrate with the console's backup and restore, and update the connection string.",
  "check.upstash.redis.daily_backup.title": "Daily backups on every paid Redis database",
  "check.upstash.redis.daily_backup.pass": "Every paid Upstash Redis database has daily backups enabled. Free databases cannot and are not judged.",
  "check.upstash.redis.daily_backup.fail": "At least one paid Upstash Redis database has daily backups off, so a bad deploy or a flush cannot be undone.",
  "check.upstash.redis.daily_backup.fix": "Upstash Console \u2192 the database \u2192 Backups \u2192 enable Daily Backup. If the database is a pure cache, accept the risk with a review date and say so.",
  "check.upstash.redis.none_suspended.title": "No Redis database suspended",
  "check.upstash.redis.none_suspended.pass": "Every Upstash Redis database is active.",
  "check.upstash.redis.none_suspended.fail": "At least one Upstash Redis database is suspended (usually a billing hold or a quota breach), so the application is failing or about to.",
  "check.upstash.redis.none_suspended.fix": "Upstash Console \u2192 Account \u2192 Billing: settle the hold or raise the quota, or delete the database if it is no longer used.",
  "provider.betterstack": "Better Stack",
  "check.betterstack.monitors.active.title": "Monitors exist and none is paused",
  "check.betterstack.monitors.active.pass": "The Better Stack team has at least one monitor and every monitor is running.",
  "check.betterstack.monitors.active.fail": "The Better Stack team has no monitors, or at least one monitor is paused, so an outage there goes unnoticed.",
  "check.betterstack.monitors.active.fix": "Better Stack \u2192 Monitors: resume the paused monitors or delete them; make sure the production host has a monitor of its own.",
  "check.betterstack.monitors.ssl_verified.title": "Certificate checks on every HTTPS monitor",
  "check.betterstack.monitors.ssl_verified.pass": "Every running HTTPS monitor verifies the certificate and alerts before it expires.",
  "check.betterstack.monitors.ssl_verified.fail": "At least one running HTTPS monitor skips certificate verification or has no expiry alert, so an expired or bad certificate goes unnoticed until users see it.",
  "check.betterstack.monitors.ssl_verified.fix": "Better Stack \u2192 the monitor \u2192 Advanced settings: turn on Verify SSL and set an SSL expiration alert (14 days is a sensible floor).",
  "check.betterstack.monitors.frequency.title": "Every monitor checks at least every five minutes",
  "check.betterstack.monitors.frequency.pass": "Every running monitor checks its target at least every five minutes.",
  "check.betterstack.monitors.frequency.fail": "At least one running monitor checks less often than every five minutes, so an outage can run unnoticed for longer than that.",
  "check.betterstack.monitors.frequency.fix": "Better Stack \u2192 the monitor \u2192 Check frequency: three minutes or less for production; the default plans allow thirty seconds.",
  "check.betterstack.monitors.alerting.title": "Every monitor alerts somebody",
  "check.betterstack.monitors.alerting.pass": "Every running monitor has an escalation policy or at least one alert channel (call, SMS, email or push).",
  "check.betterstack.monitors.alerting.fail": "At least one running monitor has no escalation policy and no alert channel, so it records outages without telling anyone.",
  "check.betterstack.monitors.alerting.fix": "Better Stack \u2192 the monitor \u2192 On-call and escalation: attach an escalation policy, or turn on at least email and push alerts.",
  "provider.railway": "Railway",
  "check.railway.service.healthcheck.title": "Health check on every public service",
  "check.railway.service.healthcheck.pass": "Every Railway service with a domain has a health check path, so a deploy that does not answer is rolled back instead of going live.",
  "check.railway.service.healthcheck.fail": "At least one Railway service with a domain has no health check path, so a broken deploy replaces the working one.",
  "check.railway.service.healthcheck.fix": "Railway \u2192 the service \u2192 Settings \u2192 Deploy \u2192 Healthcheck Path: point it at an endpoint that returns 200 only when the service can serve, such as /healthz.",
  "check.railway.service.restart_policy.title": "Every service restarts on failure",
  "check.railway.service.restart_policy.pass": "Every Railway service has a restart policy of On Failure or Always.",
  "check.railway.service.restart_policy.fail": "At least one Railway service has its restart policy set to Never, so a crash stays down until someone notices.",
  "check.railway.service.restart_policy.fix": "Railway \u2192 the service \u2192 Settings \u2192 Deploy \u2192 Restart Policy: On Failure, with a retry limit.",
  "check.railway.service.replicas.title": "More than one replica behind every public service",
  "check.railway.service.replicas.pass": "Every Railway service with a domain runs at least two replicas.",
  "check.railway.service.replicas.fail": "At least one Railway service with a domain runs a single replica, so one crash or a region incident takes it offline.",
  "check.railway.service.replicas.fix": "Railway \u2192 the service \u2192 Settings \u2192 Deploy \u2192 Replicas: two or more, or accept the risk with a review date for a low-stakes service.",
  "check.railway.domain.dns_valid.title": "Every custom domain points at Railway",
  "check.railway.domain.dns_valid.pass": "Every custom domain's DNS records match what Railway requires.",
  "check.railway.domain.dns_valid.fail": "At least one custom domain has a DNS record that does not match what Railway requires, so the site is unreachable or served by something else.",
  "check.railway.domain.dns_valid.fix": "Railway \u2192 the service \u2192 Settings \u2192 Networking \u2192 Custom Domains: copy the required record into your DNS provider and remove stale ones. Wait for propagation, then re-run.",
  "provider.auth0": "Auth0",
  "check.auth0.attack_protection.enabled.title": "Attack protection on",
  "check.auth0.attack_protection.enabled.pass": "Brute-force protection, breached-password detection and suspicious IP throttling are all enabled.",
  "check.auth0.attack_protection.enabled.fail": "At least one of brute-force protection, breached-password detection and suspicious IP throttling is off, so credential stuffing against your users goes unhindered.",
  "check.auth0.attack_protection.enabled.fix": "Auth0 Dashboard \u2192 Security \u2192 Attack Protection: enable all three. Breached-password detection and suspicious IP throttling are available on every plan.",
  "check.auth0.mfa.enforced.title": "Multi-factor authentication enforced",
  "check.auth0.mfa.enforced.pass": "MFA is required for all applications (or adaptively by risk) and at least one factor is enabled.",
  "check.auth0.mfa.enforced.fail": "MFA is not enforced, or no factor is enabled, so a stolen password is enough to sign in.",
  "check.auth0.mfa.enforced.fix": "Auth0 Dashboard \u2192 Security \u2192 Multi-factor Auth: enable at least one factor (one-time password or WebAuthn) and set the policy to Always, or Adaptive on plans that have it.",
  "check.auth0.clients.callbacks_https.title": "Every callback and origin is HTTPS and not local",
  "check.auth0.clients.callbacks_https.pass": "Every application's callback, logout and web-origin URL is HTTPS and points at a real host (native app schemes are allowed).",
  "check.auth0.clients.callbacks_https.fail": "At least one application allows an HTTP or local callback, logout or origin URL, so a sign-in can be redirected somewhere an attacker controls.",
  "check.auth0.clients.callbacks_https.fix": "Auth0 Dashboard \u2192 Applications \u2192 the application \u2192 Settings: remove http:// and localhost entries from production applications; keep them on a separate development tenant.",
  "check.auth0.clients.refresh_token_rotation.title": "Refresh tokens rotate and expire for public applications",
  "check.auth0.clients.refresh_token_rotation.pass": "Every single-page or native application that issues refresh tokens uses rotating, expiring refresh tokens.",
  "check.auth0.clients.refresh_token_rotation.fail": "At least one single-page or native application issues refresh tokens that neither rotate nor expire, so one leaked token is a permanent session.",
  "check.auth0.clients.refresh_token_rotation.fix": "Auth0 Dashboard \u2192 Applications \u2192 the application \u2192 Settings \u2192 Refresh Token Rotation: on, with expiration set (absolute and inactivity).",
  "check.auth0.tenant.session_lifetime.title": "Session lifetimes bounded",
  "check.auth0.tenant.session_lifetime.pass": "The tenant's absolute session lifetime is thirty days or less and the idle lifetime seven days or less.",
  "check.auth0.tenant.session_lifetime.fail": "The tenant lets sessions live longer than thirty days, or idle sessions longer than seven, so a forgotten browser stays signed in for months.",
  "check.auth0.tenant.session_lifetime.fix": "Auth0 Dashboard \u2192 Settings \u2192 Advanced \u2192 Login Session Management: idle session lifetime 72 hours (the default), absolute lifetime 168 hours or, at most, thirty days.",
  "check.auth0.connections.password_policy.title": "Strong password policy on every database connection",
  "check.auth0.connections.password_policy.pass": "Every username-password connection enforces a Good or Excellent password policy.",
  "check.auth0.connections.password_policy.fail": "At least one username-password connection allows weak passwords (policy Fair, Low or None).",
  "check.auth0.connections.password_policy.fix": "Auth0 Dashboard \u2192 Authentication \u2192 Database \u2192 the connection \u2192 Password Policy: Good or Excellent, with the password dictionary and personal-data rules on. Reading the policy needs the read:connections_options scope on the Snoopios application.",
  "stack.blurb.auth0": "Identity: attack protection, MFA, callbacks, refresh tokens, sessions, passwords",
  "conn.auth0.title": "Connect Auth0",
  "conn.auth0.intro": "Create a Machine to Machine application authorised for the Auth0 Management API with these read scopes only: read:clients, read:connections, read:connections_options, read:tenant_settings, read:attack_protection, read:guardian_factors, read:mfa_policies. Snoopios exchanges its credentials for a token on every run; Auth0 reports the token's scopes back, and a grant that could write is refused before any check runs.",
  "conn.auth0.domain.label": "Tenant domain",
  "conn.auth0.domain.placeholder": "acme.eu.auth0.com",
  "conn.auth0.domain.hint": "The Auth0 domain, not a custom domain.",
  "conn.auth0.client.label": "Client ID",
  "conn.auth0.secret.label": "Client secret",
  "conn.auth0.secret.hint": "Rotate from Applications \u2192 the application \u2192 Settings; the connection then needs re-entering.",
  "conn.auth0.cta": "Connect read-only",
  "conn.auth0.error.domain": "That isn't an Auth0 tenant domain (tenant.auth0.com or tenant.eu.auth0.com and similar). Custom domains are not accepted.",
  "conn.auth0.error.credentials": "The client id and secret look wrong. Both come from Applications \u2192 the application \u2192 Settings.",
  "provider.bitbucket": "Bitbucket",
  "check.bitbucket.repos.private.title": "Every repository private",
  "check.bitbucket.repos.private.pass": "Every repository in the workspace is private.",
  "check.bitbucket.repos.private.fail": "At least one repository in the workspace is public. If that is deliberate (open source), accept the risk and say so.",
  "check.bitbucket.repos.private.fix": "Bitbucket \u2192 the repository \u2192 Repository settings \u2192 Repository details \u2192 Access level: Private.",
  "check.bitbucket.repos.fork_policy.title": "No public forks of private repositories",
  "check.bitbucket.repos.fork_policy.pass": "Every private repository forbids public forks.",
  "check.bitbucket.repos.fork_policy.fail": "At least one private repository allows public forks, so a member can copy it into the open with one click.",
  "check.bitbucket.repos.fork_policy.fix": "Bitbucket \u2192 the repository \u2192 Repository settings \u2192 Repository details \u2192 Forking: No public forks, or No forks.",
  "check.bitbucket.repos.default_reviewers.title": "Default reviewers on every repository",
  "check.bitbucket.repos.default_reviewers.pass": "Every repository has at least one effective default reviewer, so every pull request starts with a reviewer assigned.",
  "check.bitbucket.repos.default_reviewers.fail": "At least one repository has no default reviewer, so a pull request can be raised and merged with nobody asked to look.",
  "check.bitbucket.repos.default_reviewers.fix": "Bitbucket \u2192 the repository \u2192 Repository settings \u2192 Default reviewers: add at least one person other than the usual author. Workspace-level defaults count.",
  "check.bitbucket.pipelines.secured_variables.title": "Pipeline secrets marked secured",
  "check.bitbucket.pipelines.secured_variables.pass": "Every pipeline variable named like a credential is marked secured, so its value is never shown in logs or the API.",
  "check.bitbucket.pipelines.secured_variables.fail": "At least one pipeline variable named like a credential is not secured, so its value is readable by anyone with pipeline access and can appear in logs.",
  "check.bitbucket.pipelines.secured_variables.fix": "Bitbucket \u2192 the repository \u2192 Repository settings \u2192 Pipelines \u2192 Repository variables: delete the variable and re-add it with Secured ticked. Rotate the value first.",
  "check.bitbucket.account.two_factor.title": "Two-step verification on the connecting account",
  "check.bitbucket.account.two_factor.pass": "The Atlassian account whose token Snoopios holds has two-step verification on.",
  "check.bitbucket.account.two_factor.fail": "The Atlassian account whose token Snoopios holds has no two-step verification, so a phished password reaches every repository it can see.",
  "check.bitbucket.account.two_factor.fix": "Atlassian account \u2192 Security \u2192 Two-step verification: enable it with an authenticator app or a security key.",
  "stack.blurb.bitbucket": "Bitbucket Cloud: private repos, forks, reviewers, deploy keys, pipeline secrets",
  "conn.bitbucket.title": "Connect Bitbucket",
  "conn.bitbucket.intro": "Create an Atlassian API token with scopes (Account settings \u2192 Security \u2192 API tokens \u2192 Create API token with scopes \u2192 Bitbucket) and tick only read:repository, read:pullrequest, read:pipeline, read:user and read:workspace. Bitbucket sometimes reports a token's scopes back; when it does, a write scope is refused. Otherwise the connection shows as read-only requested and every request is limited to reads by code.",
  "conn.bitbucket.workspace.label": "Workspace ID",
  "conn.bitbucket.workspace.placeholder": "acme",
  "conn.bitbucket.token.label": "API token",
  "conn.bitbucket.token.placeholder": "ATATT\u2026",
  "conn.bitbucket.token.hint": "Set an expiry. Revoke from Account settings \u2192 Security \u2192 API tokens.",
  "conn.bitbucket.cta": "Connect read-only",
  "conn.bitbucket.error.workspace": "A workspace ID is the slug in bitbucket.org/<workspace>/ (letters, digits, hyphens, underscores).",
  "conn.bitbucket.error.token": "That isn't an Atlassian API token (they start with ATATT). App passwords were withdrawn in 2026.",
  "provider.hetzner": "Hetzner Cloud",
  "check.hetzner.server.firewall.title": "Every public server behind a firewall",
  "check.hetzner.server.firewall.pass": "Every server with a public address has a Hetzner firewall applied.",
  "check.hetzner.server.firewall.fail": "At least one server with a public address has no firewall applied, so every port its software opens is reachable from the internet.",
  "check.hetzner.server.firewall.fix": "Hetzner Console \u2192 Firewalls: create a firewall allowing only 22 from your addresses and 80/443 from anywhere, and apply it to the server or its label.",
  "check.hetzner.server.backups.title": "Backups on every server",
  "check.hetzner.server.backups.pass": "Every server has automated backups enabled.",
  "check.hetzner.server.backups.fail": "At least one server has no automated backups, so a disk failure or a bad deploy loses it.",
  "check.hetzner.server.backups.fix": "Hetzner Console \u2192 the server \u2192 Backups \u2192 Enable (20% of the server price), or move state to a managed service and accept the risk with a review date.",
  "check.hetzner.server.delete_protection.title": "Delete protection on every server",
  "check.hetzner.server.delete_protection.pass": "Every server has delete protection on, so it cannot be removed by a stray click or script.",
  "check.hetzner.server.delete_protection.fail": "At least one server can be deleted without a second step.",
  "check.hetzner.server.delete_protection.fix": "Hetzner Console \u2192 the server \u2192 Overview \u2192 Protection: enable delete and rebuild protection.",
  "check.hetzner.firewall.admin_ports_restricted.title": "Admin ports closed to the internet",
  "check.hetzner.firewall.admin_ports_restricted.pass": "No applied firewall opens SSH, RDP, VNC, Docker or a database port to the whole internet.",
  "check.hetzner.firewall.admin_ports_restricted.fail": "At least one applied firewall opens an admin or database port (22, 3389, 5900, 2375, 3306, 5432, 6379, 27017, 9200, 11211) to every address, so it is one weak password away from a takeover.",
  "check.hetzner.firewall.admin_ports_restricted.fix": "Hetzner Console \u2192 Firewalls \u2192 the firewall \u2192 Rules: restrict those ports to your own addresses or a VPN, and keep only 80 and 443 open to anywhere.",
  "check.hetzner.load_balancer.https.title": "Load balancers terminate TLS and redirect HTTP",
  "check.hetzner.load_balancer.https.pass": "Every public load balancer has an HTTPS service with a certificate and redirects plain HTTP to it.",
  "check.hetzner.load_balancer.https.fail": "At least one public load balancer serves plain HTTP, has no HTTPS service, or lacks a certificate or the HTTP redirect.",
  "check.hetzner.load_balancer.https.fix": "Hetzner Console \u2192 the load balancer \u2192 Services: add an HTTPS service with a managed certificate, enable Redirect HTTP, and remove any separate plain-HTTP service on port 80.",
  "stack.blurb.hetzner": "Servers and load balancers: firewalls, backups, protection, admin ports, TLS",
  "conn.hetzner.title": "Connect Hetzner Cloud",
  "conn.hetzner.intro": "In the Hetzner Cloud project, go to Security \u2192 API tokens \u2192 Generate API token and choose the Read permission. Hetzner gives no way to read a token's permission back, so the connection shows as read-only requested; every request is limited to reads by code.",
  "conn.hetzner.token.label": "Read-only API token",
  "conn.hetzner.token.hint": "One token per project. Revoke from Security \u2192 API tokens.",
  "conn.hetzner.cta": "Connect read-only",
  "conn.hetzner.error.token": "That isn't a Hetzner Cloud API token (64 letters and digits).",
  "provider.azure": "Azure",
  "check.azure.storage.locked_down.title": "Storage accounts closed to the public",
  "check.azure.storage.locked_down.pass": "Every storage account forbids public blob access, requires HTTPS and accepts TLS 1.2 or newer only.",
  "check.azure.storage.locked_down.fail": "At least one storage account allows public blob access, plain HTTP, or TLS older than 1.2, so data in it can be read from the internet or in transit.",
  "check.azure.storage.locked_down.fix": "Azure Portal \u2192 the storage account \u2192 Configuration: set Allow Blob anonymous access to Disabled, Secure transfer required to Enabled, Minimum TLS version to 1.2. Under Networking, restrict public access to selected networks.",
  "check.azure.nsg.admin_ports_restricted.title": "Admin ports closed to the internet",
  "check.azure.nsg.admin_ports_restricted.pass": "No attached network security group allows SSH, RDP, VNC, Docker or a database port inbound from any address.",
  "check.azure.nsg.admin_ports_restricted.fail": "At least one attached network security group allows an admin or database port (22, 3389, 5900, 2375, 1433, 3306, 5432, 6379, 27017, 9200, 11211) inbound from the whole internet.",
  "check.azure.nsg.admin_ports_restricted.fix": "Azure Portal \u2192 the network security group \u2192 Inbound security rules: restrict the source of those rules to your own addresses or a VPN, or use Just-in-time VM access or Azure Bastion, and keep only 80 and 443 open to Any.",
  "check.azure.sql.hardened.title": "SQL servers audited, TLS 1.2, not open to the internet",
  "check.azure.sql.hardened.pass": "Every Azure SQL server has auditing enabled, requires TLS 1.2, and has no firewall rule spanning every address.",
  "check.azure.sql.hardened.fail": "At least one Azure SQL server has auditing off, accepts TLS older than 1.2, or has a firewall rule from 0.0.0.0 to 255.255.255.255.",
  "check.azure.sql.hardened.fix": "Azure Portal \u2192 the SQL server \u2192 Auditing: on, to a storage account or Log Analytics. Networking: Minimum TLS version 1.2, delete any rule spanning all addresses, use private endpoints or specific client addresses.",
  "check.azure.keyvault.protected.title": "Key Vaults protected from deletion",
  "check.azure.keyvault.protected.pass": "Every Key Vault has soft delete and purge protection on, so a deleted secret or the vault itself can be recovered.",
  "check.azure.keyvault.protected.fail": "At least one Key Vault lacks purge protection or soft delete, so a deleted key or secret can be gone for good.",
  "check.azure.keyvault.protected.fix": "Azure Portal \u2192 the Key Vault \u2192 Properties: enable Soft-delete and Purge protection. Purge protection cannot be turned off once on, which is the point.",
  "check.azure.appservice.https_only.title": "Web apps HTTPS only, TLS 1.2, no plain FTP",
  "check.azure.appservice.https_only.pass": "Every running App Service web app redirects HTTP to HTTPS, requires TLS 1.2 or newer, and does not allow plain FTP deployment.",
  "check.azure.appservice.https_only.fail": "At least one running web app accepts plain HTTP, TLS older than 1.2, or plain FTP for deployments.",
  "check.azure.appservice.https_only.fix": "Azure Portal \u2192 the web app \u2192 Configuration \u2192 General settings: HTTPS Only on, Minimum TLS version 1.2, FTP state Disabled or FTPS only.",
  "check.azure.rbac.owners_limited.title": "Subscription owners held by few",
  "check.azure.rbac.owners_limited.pass": "The subscription has between one and three Owner assignments at subscription scope.",
  "check.azure.rbac.owners_limited.fail": "The subscription has more than three Owner assignments at subscription scope, or none, so either too many people can do anything or nobody is accountable.",
  "check.azure.rbac.owners_limited.fix": "Azure Portal \u2192 the subscription \u2192 Access control (IAM): keep Owner for at most three people or one break-glass group, give everyone else Contributor or a narrower role, and use Privileged Identity Management for temporary elevation where the licence allows.",
  "stack.blurb.azure": "Azure: storage, network security groups, SQL, Key Vault, App Service, owners",
  "conn.azure.title": "Connect Azure",
  "conn.azure.intro": `Snoopios reads your subscription as its own Entra application holding the built-in Reader role, so there is no secret to paste. Two steps in Azure: create the application's service principal in your tenant (Cloud Shell: az ad sp create --id fb9fe616-787b-402a-b684-0b29d54d1a90, or connect Microsoft 365 above, which does the same), then on the subscription's Access control (IAM) page assign the Reader role to "Snoopios 365 connector". Every run reads the role assignments first and stops if anything beyond Reader is present, so the connection shows as read-only verified.`,
  "conn.azure.tenant.label": "Tenant ID",
  "conn.azure.tenant.placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "conn.azure.subscription.label": "Subscription ID",
  "conn.azure.subscription.hint": "Azure Portal \u2192 Subscriptions. One connection per subscription.",
  "conn.azure.cta": "Connect read-only",
  "conn.azure.error.no_role": "Snoopios reached your tenant but has no role on that subscription. Two things are needed and one of them is probably missing: the application's service principal in your tenant, and the Reader role assigned to it on this subscription. The commands are above. Role assignments can take a minute to take effect, so if you have just made one, wait and try again.",
  "conn.azure.error.write": "That service principal holds more than Reader on the subscription. Snoopios refuses a connection that could change anything, so nothing has been saved. Remove the wider assignment, leave Reader, and try again.",
  "conn.azure.error.auth": "Snoopios could not get a token for that tenant. Check the tenant id, and that the application's service principal exists in your directory.",
  "conn.azure.error.tenant": "A tenant id is 36 characters: eight, four, four, four and twelve hex digits separated by hyphens.",
  "conn.azure.error.subscription": "A subscription id is 36 characters: eight, four, four, four and twelve hex digits separated by hyphens.",
  "provider.pagerduty": "PagerDuty",
  "check.pagerduty.oncall.covered.title": "Someone on call all of next week",
  "check.pagerduty.oncall.covered.pass": "Every escalation policy has a level-one on-call shift covering the whole of the next seven days.",
  "check.pagerduty.oncall.covered.fail": "At least one escalation policy has a gap in level-one on-call cover during the next seven days, so a page in that window reaches nobody.",
  "check.pagerduty.oncall.covered.fix": "PagerDuty \u2192 People \u2192 Schedules: fill the gap with a layer or an override, and put the schedule on the policy's first level. Point every policy's first level at a schedule, not a single person.",
  "check.pagerduty.services.escalation_wired.title": "Every service pages a real escalation policy",
  "check.pagerduty.services.escalation_wired.pass": "Every active service has an escalation policy with at least one target.",
  "check.pagerduty.services.escalation_wired.fail": "At least one active service has no escalation policy, or a policy with no targets, so its incidents page nobody.",
  "check.pagerduty.services.escalation_wired.fix": "PagerDuty \u2192 Services \u2192 the service \u2192 Settings \u2192 Escalation policy: assign a policy whose first level targets a schedule or a person.",
  "check.pagerduty.escalation.backup_level.title": "Unanswered pages escalate",
  "check.pagerduty.escalation.backup_level.pass": "Every escalation policy has a second level or repeats, so an unanswered page is not simply dropped. A second level reaches somebody else; a repeat pages the same responder again.",
  "check.pagerduty.escalation.backup_level.fail": "At least one escalation policy has a single level and never repeats, so an unanswered page stops there.",
  "check.pagerduty.escalation.backup_level.fix": "PagerDuty \u2192 People \u2192 Escalation policies \u2192 the policy: add a second level (another schedule, a manager) or set the policy to repeat at least once.",
  "check.pagerduty.incidents.none_stale.title": "No incident open for more than a day",
  "check.pagerduty.incidents.none_stale.pass": "No triggered or acknowledged incident is older than twenty-four hours.",
  "check.pagerduty.incidents.none_stale.fail": "At least one incident has been triggered or acknowledged for more than a day without being resolved.",
  "check.pagerduty.incidents.none_stale.fix": "PagerDuty \u2192 Incidents: resolve or reassign the stale incidents, and set an acknowledgement timeout on the service so an acknowledged incident re-pages when it is forgotten.",
  "stack.blurb.pagerduty": "On-call: coverage next week, escalation wired, backup levels, stale incidents",
  "conn.pagerduty.title": "Connect PagerDuty",
  "conn.pagerduty.intro": "Create a general access REST API key with the Read-only box ticked (Integrations \u2192 API Access Keys \u2192 Create New API Key). PagerDuty gives no way to read a key's access level back, so the connection shows as read-only requested; every request is limited to reads by code. A user token also works and is checked against its user's role: only a read-only user is accepted.",
  "conn.pagerduty.token.label": "REST API key",
  "conn.pagerduty.token.hint": "Twenty characters. Revoke from Integrations \u2192 API Access Keys.",
  "conn.pagerduty.cta": "Connect read-only",
  "conn.pagerduty.error.token": "That isn't a PagerDuty REST API key (twenty characters).",
  "provider.datadog": "Datadog",
  "check.datadog.monitors.notify_someone.title": "Every monitor tells somebody",
  "check.datadog.monitors.notify_someone.pass": "There is at least one monitor and every monitor's message carries a notification handle.",
  "check.datadog.monitors.notify_someone.fail": "There are no monitors, or at least one monitor's message has no @-handle, so it changes colour on a dashboard and tells nobody.",
  "check.datadog.monitors.notify_someone.fix": "Datadog \u2192 Monitors \u2192 the monitor \u2192 Notify your team: add an @-handle (a Slack channel, PagerDuty service or email) to every monitor. Use a monitor tag and a notification template so new monitors inherit it.",
  "check.datadog.monitors.none_muted_forever.title": "No monitor muted indefinitely",
  "check.datadog.monitors.none_muted_forever.pass": "No monitor is muted without an expiry.",
  "check.datadog.monitors.none_muted_forever.fail": "At least one monitor is muted with no expiry, so it will never alert again unless someone remembers it.",
  "check.datadog.monitors.none_muted_forever.fix": "Datadog \u2192 Monitors \u2192 Manage downtimes: replace indefinite mutes with downtimes that have an end date, and delete monitors that are no longer wanted.",
  "check.datadog.monitors.no_data_alerts.title": "Silence is noticed",
  "check.datadog.monitors.no_data_alerts.pass": "Every metric monitor alerts when its data stops arriving.",
  "check.datadog.monitors.no_data_alerts.fail": "At least one metric monitor stays quiet when its data stops, so a dead host or agent looks healthy.",
  "check.datadog.monitors.no_data_alerts.fix": "Datadog \u2192 Monitors \u2192 the monitor \u2192 Advanced options: Notify if data is missing, with a sensible window (10 to 30 minutes).",
  "check.datadog.users.mfa.title": "Every user signs in with a second factor",
  "check.datadog.users.mfa.pass": "Every active human user has multi-factor authentication enabled, or the org enforces SAML.",
  "check.datadog.users.mfa.fail": "At least one active user signs in to Datadog with a password alone.",
  "check.datadog.users.mfa.fix": "Datadog \u2192 Organization Settings \u2192 Login Methods: require SAML or enforce MFA; ask the remaining users to enable it under Personal Settings \u2192 Password & Authentication.",
  "check.datadog.logs.retention.title": "Logs kept at least fifteen days",
  "check.datadog.logs.retention.pass": "Every log index retains logs for at least fifteen days.",
  "check.datadog.logs.retention.fail": "At least one log index retains logs for fewer than fifteen days, so an incident from last week may already be gone.",
  "check.datadog.logs.retention.fix": "Datadog \u2192 Logs \u2192 Configuration \u2192 Indexes: set retention to fifteen days or more on production indexes, or add an archive to cheap storage for the long tail.",
  "stack.blurb.datadog": "Monitoring: monitors notify, no permanent mutes, no-data alerts, MFA, log retention",
  "conn.datadog.title": "Connect Datadog",
  "conn.datadog.intro": "Create a scoped application key (Organization Settings \u2192 Application Keys \u2192 New Key) with exactly these scopes: monitors_read, user_access_read, logs_read_config and user_app_keys, from a user or service account holding the Datadog Read Only Role. Paste it with an API key and choose your site. Datadog reports the key's scopes back, so every run reads them first and refuses an unscoped key or any write scope: the connection shows as read-only verified.",
  "conn.datadog.site.label": "Datadog site",
  "conn.datadog.apikey.label": "API key",
  "conn.datadog.appkey.label": "Scoped application key",
  "conn.datadog.appkey.hint": "Revoke from Organization Settings \u2192 Application Keys.",
  "conn.datadog.cta": "Connect read-only",
  "conn.datadog.error.site": "Choose the Datadog site your organisation lives on (the host in your browser: datadoghq.com, datadoghq.eu, us3, us5, ap1, ap2 or uk1).",
  "conn.datadog.error.keys": "The keys look wrong: an API key is 32 hex characters and an application key is 40.",
  "provider.okta": "Okta",
  "check.okta.signon.mfa_required.title": "Second factor required at sign-in",
  "check.okta.signon.mfa_required.pass": "Every active sign-on policy rule that allows access requires a factor.",
  "check.okta.signon.mfa_required.fail": "At least one active sign-on policy rule allows access without a second factor, so a password alone can be enough.",
  "check.okta.signon.mfa_required.fix": "Okta Admin \u2192 Security \u2192 Authentication policies (or Global session policy): edit each Allow rule to require multifactor authentication. Keep the default rule strict and add exceptions only by network zone.",
  "check.okta.users.mfa_enrolled.title": "Every active user has enrolled a factor",
  "check.okta.users.mfa_enrolled.pass": "Every active user has at least one active factor enrolled.",
  "check.okta.users.mfa_enrolled.fail": "At least one active user has no active factor, so a required-factor policy cannot apply to them at sign-in.",
  "check.okta.users.mfa_enrolled.fix": "Okta Admin \u2192 Security \u2192 Authenticators: make enrollment required at first sign-in; Directory \u2192 People: reset factors for anyone stuck. Instances with more than two hundred users are not judged here.",
  "check.okta.admins.limited.title": "Super admins held by few",
  "check.okta.admins.limited.pass": "Between one and three active users hold the Super Administrator role.",
  "check.okta.admins.limited.fail": "More than three active users hold Super Administrator, or none does, so either too many people can do anything or nobody can recover the org.",
  "check.okta.admins.limited.fix": "Okta Admin \u2192 Security \u2192 Administrators: keep Super Administrator for at most three people, give everyone else a narrower role (Org, Group, Help Desk or Read-only Administrator).",
  "check.okta.users.dormant.title": "No dormant account still active",
  "check.okta.users.dormant.pass": "Every active user has signed in within ninety days, or was created within the last month.",
  "check.okta.users.dormant.fail": "At least one active user has not signed in for ninety days, or never signed in and is older than a month.",
  "check.okta.users.dormant.fix": "Okta Admin \u2192 Directory \u2192 People: suspend or deactivate the dormant accounts, or set up a lifecycle rule that suspends after ninety days without sign-in.",
  "check.okta.signon.sessions_bounded.title": "Sessions end",
  "check.okta.signon.sessions_bounded.pass": "Every Allow rule on an active sign-on policy limits idle sessions to a day and total sessions to thirty days.",
  "check.okta.signon.sessions_bounded.fail": "At least one Allow rule leaves the session idle limit above a day or the lifetime unlimited or above thirty days, so a forgotten browser stays signed in.",
  "check.okta.signon.sessions_bounded.fix": "Okta Admin \u2192 Security \u2192 Global session policy \u2192 the rule \u2192 Session management: Maximum idle time 24 hours or less, Maximum lifetime set (30 days is generous), and expire on browser close where the app allows.",
  "stack.blurb.okta": "Workforce identity: MFA required and enrolled, super admins, dormant users, sessions",
  "conn.okta.title": "Connect Okta",
  "conn.okta.intro": "Create a dedicated user, give it only the Read-only Administrator role, sign in as that user and create an API token (Security \u2192 API \u2192 Tokens). Okta tokens inherit their creator's role and cannot be scoped, so every run reads the token's own user first and stops if any role it can see could write. Okta refuses to show a read-only administrator its own roles, so that reading usually cannot be made: the connection shows as read-only requested. Note that Okta revokes a token unused for thirty days; Snoopios uses it hourly.",
  "conn.okta.org.label": "Okta org domain",
  "conn.okta.org.placeholder": "acme.okta.com",
  "conn.okta.token.label": "API token",
  "conn.okta.token.hint": "Revoke from Security \u2192 API \u2192 Tokens.",
  "conn.okta.cta": "Connect read-only",
  "conn.okta.error.org": "That isn't an Okta org domain (acme.okta.com, acme.okta-emea.com or acme.oktapreview.com). Custom domains are not accepted.",
  "conn.okta.error.token": "That doesn't look like an Okta API token.",
  "provider.azuredevops": "Azure DevOps",
  "check.azuredevops.projects.private.title": "Every project private",
  "check.azuredevops.projects.private.pass": "Every project in the organisation is private.",
  "check.azuredevops.projects.private.fail": "At least one project in the organisation is public. If that is deliberate (open source), accept the risk and say so.",
  "check.azuredevops.projects.private.fix": "Azure DevOps \u2192 Organization settings \u2192 Projects \u2192 the project \u2192 Visibility: Private.",
  "check.azuredevops.repos.default_branch_reviewed.title": "Default branch needs a review",
  "check.azuredevops.repos.default_branch_reviewed.pass": "Every enabled repository's default branch has a blocking minimum-reviewers policy of at least one approver, and the author's vote does not count.",
  "check.azuredevops.repos.default_branch_reviewed.fail": "At least one repository's default branch can be changed without a blocking review from someone other than the author.",
  "check.azuredevops.repos.default_branch_reviewed.fix": "Azure DevOps \u2192 Repos \u2192 Branches \u2192 the default branch \u2192 Branch policies: Require a minimum number of reviewers (1 or more), Required, and untick 'Allow requestors to approve their own changes'.",
  "check.azuredevops.pipelines.yaml.title": "Pipelines defined as code",
  "check.azuredevops.pipelines.yaml.pass": "Every pipeline is a YAML pipeline, so its definition is reviewed like any other change.",
  "check.azuredevops.pipelines.yaml.fail": "At least one pipeline is a classic designer pipeline, edited outside source control and outside review.",
  "check.azuredevops.pipelines.yaml.fix": "Azure DevOps \u2192 Pipelines: recreate classic pipelines as YAML in the repository and retire the designer ones.",
  "check.azuredevops.members.dormant.title": "No dormant member still licensed",
  "check.azuredevops.members.dormant.pass": "Every active member has signed in within ninety days, or was added within the last month.",
  "check.azuredevops.members.dormant.fail": "At least one active member has not signed in for ninety days, or never signed in and was added over a month ago.",
  "check.azuredevops.members.dormant.fix": "Azure DevOps \u2192 Organization settings \u2192 Users: remove the dormant members. Entra-backed organisations can also use group rules so leavers lose access automatically.",
  "stack.blurb.azuredevops": "Azure DevOps: private projects, reviewed default branches, YAML pipelines, dormant members",
  "conn.azuredevops.title": "Connect Azure DevOps",
  "conn.azuredevops.intro": "Create a personal access token (User settings \u2192 Personal access tokens) scoped to this organisation with these Read scopes only: Project and Team, Code, Build, Graph, Member Entitlement Management. Azure DevOps cannot report a token's scopes back to the token itself, so the connection shows as read-only requested; every request is limited to reads by code. Set an expiry and note that Entra-backed organisations deactivate a token unused for ninety days.",
  "conn.azuredevops.org.label": "Organisation name",
  "conn.azuredevops.org.placeholder": "the part after dev.azure.com/",
  "conn.azuredevops.token.label": "Personal access token",
  "conn.azuredevops.token.hint": "Revoke from User settings \u2192 Personal access tokens.",
  "conn.azuredevops.cta": "Connect read-only",
  "conn.azuredevops.error.org": "An organisation name is the segment after dev.azure.com/ (letters, digits and hyphens).",
  "conn.azuredevops.error.token": "That isn't an Azure DevOps personal access token (52 or 84 letters and digits).",
  "provider.circleci": "CircleCI",
  "check.circleci.project.builds_private.title": "Builds hidden from the public",
  "check.circleci.project.builds_private.pass": "The project's builds are visible only to members.",
  "check.circleci.project.builds_private.fail": "The project is marked open source, so anyone can read its builds and their output through the web and the API.",
  "check.circleci.project.builds_private.fix": "CircleCI \u2192 Project Settings \u2192 Advanced: turn off Free and Open Source unless the repository is public on purpose.",
  "check.circleci.project.settings_admin_only.title": "Project settings changed by admins only",
  "check.circleci.project.settings_admin_only.pass": "Changing the project's settings requires an organisation administrator.",
  "check.circleci.project.settings_admin_only.fail": "Any member can change the project's settings, including the ones below.",
  "check.circleci.project.settings_admin_only.fix": "CircleCI \u2192 Project Settings \u2192 Advanced: turn on 'Only org admins can change project settings'.",
  "check.circleci.project.forks_no_secrets.title": "Forks do not receive secrets",
  "check.circleci.project.forks_no_secrets.pass": "Builds of pull requests from forks do not receive the project's secret environment variables.",
  "check.circleci.project.forks_no_secrets.fail": "Builds of pull requests from forks receive the project's secret environment variables, so anyone who can open a pull request can read them.",
  "check.circleci.project.forks_no_secrets.fix": "CircleCI \u2192 Project Settings \u2192 Advanced: turn off 'Pass secrets to builds from forked pull requests'.",
  "provider.checkly": "Checkly",
  "check.checkly.checks.active.title": "Checks exist and none is muted",
  "check.checkly.checks.active.pass": "The account has at least one check and every check is activated and unmuted.",
  "check.checkly.checks.active.fail": "The account has no checks, or at least one check is deactivated or muted, so an outage there goes unnoticed.",
  "check.checkly.checks.active.fix": "Checkly \u2192 Checks: activate or unmute the checks, or delete the ones no longer wanted; make sure production has a check of its own.",
  "check.checkly.checks.alerting.title": "Every check alerts somebody",
  "check.checkly.checks.alerting.pass": "Every active check subscribes to at least one alert channel.",
  "check.checkly.checks.alerting.fail": "At least one active check has no alert channel subscription, so it records failures without telling anyone.",
  "check.checkly.checks.alerting.fix": "Checkly \u2192 the check \u2192 Alerting: subscribe it to an alert channel, or set alert channels on its group.",
  "check.checkly.alert_channels.ssl_expiry.title": "Certificate expiry alerts on",
  "check.checkly.alert_channels.ssl_expiry.pass": "At least one alert channel sends certificate-expiry alerts.",
  "check.checkly.alert_channels.ssl_expiry.fail": "No alert channel sends certificate-expiry alerts, so an expiring certificate is noticed by users first.",
  "check.checkly.alert_channels.ssl_expiry.fix": "Checkly \u2192 Alerts \u2192 the channel \u2192 tick SSL certificate expiry and set the threshold (14 days is a sensible floor).",
  "check.checkly.checks.multi_location.title": "Checks run from more than one place",
  "check.checkly.checks.multi_location.pass": "Every active check runs from at least two locations.",
  "check.checkly.checks.multi_location.fail": "At least one active check runs from a single location, so a regional blip looks like an outage and a real outage can be missed.",
  "check.checkly.checks.multi_location.fix": "Checkly \u2192 the check \u2192 Locations: add a second region.",
  "provider.turso": "Turso",
  "check.turso.databases.delete_protection.title": "Delete protection on every database",
  "check.turso.databases.delete_protection.pass": "Every database has delete protection on.",
  "check.turso.databases.delete_protection.fail": "At least one database can be deleted without a second step.",
  "check.turso.databases.delete_protection.fix": "Turso: `turso db update <name> --delete-protection` or the dashboard's database settings.",
  "check.turso.groups.delete_protection.title": "Delete protection on every group",
  "check.turso.groups.delete_protection.pass": "Every group has delete protection on.",
  "check.turso.groups.delete_protection.fail": "At least one group can be deleted without a second step, taking every database in it.",
  "check.turso.groups.delete_protection.fix": "Turso: `turso group update <name> --delete-protection` or the dashboard's group settings.",
  "check.turso.members.owners_limited.title": "Organisation owners held by few",
  "check.turso.members.owners_limited.pass": "Between one and three members hold the owner role.",
  "check.turso.members.owners_limited.fail": "More than three members own the organisation, or none does.",
  "check.turso.members.owners_limited.fix": "Turso dashboard \u2192 Organization \u2192 Members: keep owner for at most three people, give everyone else admin or member.",
  "provider.workos": "WorkOS",
  "check.workos.connections.active.title": "SSO connections live",
  "check.workos.connections.active.pass": "Every SSO connection is active.",
  "check.workos.connections.active.fail": "At least one SSO connection is a draft or still needs a type, so a customer's single sign-on is not actually working.",
  "check.workos.connections.active.fix": "WorkOS Dashboard \u2192 Organizations \u2192 the connection: finish the setup, or delete drafts that were never completed.",
  "check.workos.directories.linked.title": "Directory syncs healthy",
  "check.workos.directories.linked.pass": "Every directory sync is linked.",
  "check.workos.directories.linked.fail": "At least one directory sync is unlinked or has invalid credentials, so joiners and leavers at that customer are not being synced.",
  "check.workos.directories.linked.fix": "WorkOS Dashboard \u2192 the directory: reconnect it or ask the customer to re-authorise the sync.",
  "check.workos.organizations.domains_verified.title": "Customer domains verified",
  "check.workos.organizations.domains_verified.pass": "Every organisation domain is verified.",
  "check.workos.organizations.domains_verified.fail": "At least one organisation domain is unverified, so sign-in could be routed for a domain nobody has proved they own.",
  "check.workos.organizations.domains_verified.fix": "WorkOS Dashboard \u2192 the organization \u2192 Domains: complete verification or remove the domain.",
  "check.workos.users.email_verified.title": "User emails verified",
  "check.workos.users.email_verified.pass": "Every user has a verified email address.",
  "check.workos.users.email_verified.fail": "At least one user has an unverified email address.",
  "check.workos.users.email_verified.fix": "WorkOS \u2192 User Management: require email verification at sign-up, and prompt existing users to verify. Environments with more than five hundred users are not judged here.",
  "conn.fly.title": "Connect Fly.io",
  "conn.fly.intro": "Run fly tokens create readonly -o <org> and paste the token. Fly's read-only org token cannot create, deploy or modify anything. Fly tokens are sealed macaroons that Snoopios cannot open to prove the restriction, so this connection shows as read-only requested; every Snoopios request is still limited to reads by code.",
  "conn.fly.org.label": "Organisation slug",
  "conn.fly.org.placeholder": "personal or acme-labs",
  "conn.fly.apps.label": "Apps to check",
  "conn.fly.apps.placeholder": "acme-web, acme-api",
  "conn.fly.apps.hint": "Optional. Leave empty to check every app in the organisation, up to thirty.",
  "conn.fly.token.label": "Read-only org token",
  "conn.fly.token.placeholder": "FlyV1 fm2_\u2026",
  "conn.fly.token.hint": "Set an expiry: fly tokens create readonly -o <org> -x 8760h for a year. Revoke with fly tokens revoke.",
  "conn.fly.cta": "Connect read-only",
  "conn.fly.error.org": "An organisation slug is lowercase letters, digits and hyphens.",
  "conn.fly.error.token": "That isn't a Fly token (FlyV1 fm2_\u2026). Create one with fly tokens create readonly.",
  "conn.fly.error.auth": "Fly refused that token. Check it was copied whole, including the FlyV1 prefix, which is easy to leave behind. Nothing has been saved.",
  "conn.fly.error.org_invisible": "The token works, but it does not cover an organisation by that slug. Either the slug is wrong, and it is the one in your Fly dashboard URL rather than the display name, or the token was issued for a different organisation: a read-only token names one org when you create it. Nothing has been saved.",
  "conn.fly.error.unreachable": "Fly did not answer in a way we could read. Nothing has been saved; try again shortly.",
  "check.fly.services.force_https.title": "Plain HTTP redirects to HTTPS on every service",
  "check.fly.services.force_https.pass": "Every machine service that listens on plain HTTP has force_https on, or listens on TLS only.",
  "check.fly.services.force_https.fail": "At least one service accepts plain HTTP without redirecting to HTTPS.",
  "check.fly.services.force_https.fix": 'In fly.toml, under [http_service] set force_https = true, or under each [[services.ports]] with handlers = ["http"] add force_https = true, then deploy.',
  "check.fly.volumes.encrypted.title": "Volumes encrypted at rest",
  "check.fly.volumes.encrypted.pass": "Every volume is encrypted at rest, which is Fly's default.",
  "check.fly.volumes.encrypted.fail": "At least one volume was created with encryption off.",
  "check.fly.volumes.encrypted.fix": "Create a new encrypted volume (fly volumes create without --no-encryption), move the data across, and delete the unencrypted one.",
  "check.fly.machines.no_plaintext_secrets.title": "No secret-looking value in plaintext machine env",
  "check.fly.machines.no_plaintext_secrets.pass": "No machine carries a key named like a secret in its plaintext environment.",
  "check.fly.machines.no_plaintext_secrets.fail": "At least one machine has a key named like a secret in plaintext env, visible to anyone who can read the machine config.",
  "check.fly.machines.no_plaintext_secrets.fix": "Move each listed key to fly secrets set, remove it from [env] in fly.toml, and deploy. Public values (NEXT_PUBLIC_, publishable keys) are not counted.",
  "check.fly.org.members_2fa.title": "Every organisation member has two-factor authentication",
  "check.fly.org.members_2fa.pass": "Every member of the Fly organisation has two-factor authentication on.",
  "check.fly.org.members_2fa.fail": "At least one member of the Fly organisation has no second factor.",
  "check.fly.org.members_2fa.fix": "Ask each listed member to enable two-factor authentication at fly.io/user/personal_access_tokens \u2192 Security, or remove them from the organisation.",
  "check.fly.app.certificates.title": "Every custom hostname has an issued certificate",
  "check.fly.app.certificates.pass": "Every custom hostname on every app has a ready certificate.",
  "check.fly.app.certificates.fail": "At least one custom hostname is waiting for a certificate, so it serves an error or a mismatched certificate.",
  "check.fly.app.certificates.fix": "fly certs check <hostname> shows the DNS record Fly needs; add it and wait for the certificate to become ready.",
  "conn.uptimerobot.title": "Connect UptimeRobot",
  "conn.uptimerobot.intro": "Paste a read-only API key: UptimeRobot \u2192 Integrations & API \u2192 Read-Only API Key. It starts with ur. The main key (u\u2026) can create and delete monitors and is refused.",
  "conn.uptimerobot.key.label": "Read-only API key",
  "conn.uptimerobot.key.placeholder": "ur1234567-\u2026",
  "conn.uptimerobot.key.hint": "Stored encrypted; only getMonitors is called. Revoke it in UptimeRobot at any time.",
  "conn.uptimerobot.cta": "Connect UptimeRobot",
  "conn.uptimerobot.label": "UptimeRobot",
  "conn.uptimerobot.error.key": "That isn't a read-only key. It must start with ur; the main key and monitor-specific keys are refused.",
  "conn.uptimerobot.error.host": "This project has no production domain yet. Add it first so the checks know which monitor matters.",
  "check.uptimerobot.monitor.production.title": "Production host is monitored",
  "check.uptimerobot.monitor.production.pass": "An active HTTP or keyword monitor watches the project's production host.",
  "check.uptimerobot.monitor.production.fail": "No active monitor watches the production host, so an outage is noticed by customers before you.",
  "check.uptimerobot.monitor.production.fix": "UptimeRobot \u2192 Add monitor \u2192 HTTP(s), the production URL, five-minute interval, and at least one alert contact. Un-pause it if it exists.",
  "check.uptimerobot.alerts.configured.title": "Every active monitor alerts someone",
  "check.uptimerobot.alerts.configured.pass": "Every active monitor has at least one alert contact.",
  "check.uptimerobot.alerts.configured.fail": "At least one active monitor has no alert contact: it records downtime and tells nobody.",
  "check.uptimerobot.alerts.configured.fix": "Edit each listed monitor and add an alert contact (email, SMS, Slack). Prefer a shared contact, not one person's phone.",
  "check.uptimerobot.monitor.interval.title": "Production check runs at least every five minutes",
  "check.uptimerobot.monitor.interval.pass": "Every production monitor checks at an interval of five minutes or less.",
  "check.uptimerobot.monitor.interval.fail": "A production monitor checks less often than every five minutes, so an outage can run unnoticed for longer than that.",
  "check.uptimerobot.monitor.interval.fix": "Edit the monitor and set the interval to 5 minutes (the free plan allows it). Shorter intervals need a paid plan and are not required.",
  "check.cloudflare.pages.compat_date.title": "Pages compatibility date within a year",
  "check.cloudflare.pages.compat_date.pass": "Every Pages project's production compatibility date is under a year old.",
  "check.cloudflare.pages.compat_date.fail": "At least one Pages project runs on a Workers runtime compatibility date older than a year, missing runtime fixes since.",
  "check.cloudflare.pages.compat_date.fix": "Pages \u2192 the project \u2192 Settings \u2192 Functions \u2192 Compatibility date: set to today's date, redeploy, and check the site. Repeat yearly.",
  "check.cloudflare.pages.preview_protected.title": "Pages preview deployments behind Access",
  "check.cloudflare.pages.preview_protected.pass": "Every Pages project has a Cloudflare Access application covering its preview deployments.",
  "check.cloudflare.pages.preview_protected.fail": "At least one Pages project serves its preview deployments to anyone with the link.",
  "check.cloudflare.pages.preview_protected.fix": "Pages \u2192 the project \u2192 Settings \u2192 General \u2192 Access policy \u2192 Enable. Cloudflare creates the Access application for *.<project>.pages.dev; Zero Trust's free tier covers it.",
  "conn.google.title": "Connect Google Workspace",
  "conn.google.intro": "A super-admin grants Snoopios one read-only Admin SDK scope: the user directory. Google returns a refresh token, which is stored encrypted; nothing is written, and a grant with more scopes than asked is refused.",
  "conn.google.cta": "Grant read-only access on Google",
  "conn.google.label": "Google Workspace",
  "conn.google.connected": "Google Workspace is connected. The first run starts within a minute.",
  "conn.google.scopes": "Google granted different scopes from the single read-only one requested, so the connection was refused. Try again and leave the scope as shown.",
  "conn.google.error": "The Google grant did not complete. Try again from this page; if it repeats, email us.",
  "conn.google.unconfigured": "Google Workspace is not switched on in this deployment yet: the OAuth client has not been registered.",
  "check.google.users.2sv_enforced.title": "Two-step verification enforced for every user",
  "check.google.users.2sv_enforced.pass": "Every active user is in an organisational unit that enforces two-step verification.",
  "check.google.users.2sv_enforced.fail": "At least one active user is not required to use two-step verification. The result lists roles with masked addresses.",
  "check.google.users.2sv_enforced.fix": "Admin console \u2192 Security \u2192 Authentication \u2192 2-Step Verification \u2192 Enforcement on, for the whole organisation, with an enrolment period.",
  "check.google.users.2sv_enrolled.title": "Every user has enrolled in two-step verification",
  "check.google.users.2sv_enrolled.pass": "Every active user has a second factor enrolled.",
  "check.google.users.2sv_enrolled.fail": "At least one active user has not enrolled a second factor, so enforcement is not yet protecting that account.",
  "check.google.users.2sv_enrolled.fix": "Ask each listed user to enrol at myaccount.google.com \u2192 Security \u2192 2-Step Verification; once enforcement is on, Google locks out anyone who has not.",
  "check.google.admins.limited.title": "Super-admin rights are held by few",
  "check.google.admins.limited.pass": "At least one super-admin exists and no more than three, or a quarter of users, whichever is larger.",
  "check.google.admins.limited.fail": "Too many, or no, users hold the super-admin role.",
  "check.google.admins.limited.fix": "Admin console \u2192 Account \u2192 Admin roles: remove the super-admin role from everyone who does not administer Google Workspace; give delegated roles instead. Keep a second super-admin for continuity.",
  "check.google.users.dormant.title": "No account unused for ninety days",
  "check.google.users.dormant.pass": "Every active account has signed in within ninety days, or was created within the last month.",
  "check.google.users.dormant.fail": "At least one active account has not signed in for ninety days. A dormant account is an entry nobody is watching.",
  "check.google.users.dormant.fix": "Admin console \u2192 Directory \u2192 Users: suspend or delete each listed account, or transfer its data and remove it under the leaver procedure.",
  "check.sentry.org.require_2fa.title": "Sentry requires two-factor authentication",
  "check.sentry.org.require_2fa.pass": "The organisation requires every member to use two-factor authentication.",
  "check.sentry.org.require_2fa.fail": "Members can reach error data, which often contains personal data, with a password alone.",
  "check.sentry.org.require_2fa.fix": "Settings \u2192 General \u2192 Require Two-Factor Authentication. Members without it are locked out until they enrol, so warn them first.",
  "check.sentry.members.2fa.title": "Every Sentry member has two-factor authentication",
  "check.sentry.members.2fa.pass": "Every active member has a second factor enrolled.",
  "check.sentry.members.2fa.fail": "At least one member has no second factor. The result names the role and a masked address.",
  "check.sentry.members.2fa.fix": "Ask each listed member to enrol under Account \u2192 Security, or require it at the organisation so the platform enforces it.",
  "check.sentry.org.data_scrubbing.title": "Sentry scrubs sensitive data and IP addresses",
  "check.sentry.org.data_scrubbing.pass": "Data scrubbing is on with the default sensitive fields, and IP addresses are removed before storage.",
  "check.sentry.org.data_scrubbing.fail": "Passwords, tokens, card numbers or IP addresses can be stored inside error events.",
  "check.sentry.org.data_scrubbing.fix": "Settings \u2192 Security & Privacy: turn on Data Scrubber, Use Default Scrubbers and Prevent Storing of IP Addresses. Add your own field names under Additional Sensitive Fields.",
  "check.sentry.projects.data_scrubbing.title": "No Sentry project weakens scrubbing",
  "check.sentry.projects.data_scrubbing.pass": "Every project keeps scrubbing on and stores no native crash dumps.",
  "check.sentry.projects.data_scrubbing.fail": "A project has switched scrubbing off, keeps IP addresses, or stores crash dumps that can hold memory contents.",
  "check.sentry.projects.data_scrubbing.fix": "Project \u2192 Settings \u2192 Security & Privacy: leave Data Scrubber and Prevent Storing of IP Addresses on, and set Store Native Crash Reports to none unless you need them.",
  "check.sentry.org.membership_closed.title": "Sentry membership is by invitation",
  "check.sentry.org.membership_closed.pass": "Open membership and join requests are off; people join only when invited.",
  "check.sentry.org.membership_closed.fail": "Anyone with a company email can join or request to join without an invitation.",
  "check.sentry.org.membership_closed.fix": "Settings \u2192 General \u2192 Membership: turn off Open Membership and Allow Join Requests.",
  "check.sentry.org.no_shared_issues.title": "Sentry issues cannot be shared by public link",
  "check.sentry.org.no_shared_issues.pass": "Public issue sharing is off, so an error page cannot be opened without signing in.",
  "check.sentry.org.no_shared_issues.fail": "Issues can be shared by public link; a link pasted anywhere exposes the event, stack and any data in it.",
  "check.sentry.org.no_shared_issues.fix": "Settings \u2192 Security & Privacy \u2192 turn off Allow Shared Issues.",
  "check.slack.members.2fa.title": "Every Slack member has two-factor authentication",
  "check.slack.members.2fa.pass": "Every active member has a second factor enrolled.",
  "check.slack.members.2fa.fail": "At least one member signs in with a password alone. The result lists roles with masked handles.",
  "check.slack.members.2fa.fix": "Workspace settings \u2192 Authentication \u2192 require two-factor authentication for the whole workspace, then ask the listed members to enrol.",
  "check.slack.admins.limited.title": "Slack admin rights are held by few",
  "check.slack.admins.limited.pass": "The workspace has at least one owner or admin and no more than three or a quarter of members, whichever is larger.",
  "check.slack.admins.limited.fail": "Too many, or no, members hold owner or admin rights.",
  "check.slack.admins.limited.fix": "Manage members \u2192 change the role of everyone who does not administer the workspace to Member. Keep a second owner for continuity.",
  "check.slack.guests.none.title": "Slack guest accounts reviewed",
  "check.slack.guests.none.pass": "No guest accounts exist.",
  "check.slack.guests.none.fail": "Guest accounts exist. Review each one; access that outlived the engagement is the usual finding.",
  "check.slack.guests.none.fix": "Manage members \u2192 filter Guests \u2192 deactivate anyone whose work has ended, or convert long-term collaborators to members so the 2FA requirement covers them.",
  "check.slack.team.join_restricted.title": "Joining Slack is restricted to the company domain",
  "check.slack.team.join_restricted.pass": "Sign-up is limited to the workspace's approved email domains.",
  "check.slack.team.join_restricted.fail": "No approved email domain is set, so joining depends on invitation hygiene alone.",
  "check.slack.team.join_restricted.fix": "Workspace settings \u2192 Settings \u2192 Joining this workspace \u2192 allow sign-ups only from your company email domain.",
  "conn.email.error.domain": "Enter the domain you send from, like mail.example.com.",
  "conn.email.error.label": "Selector and return path are lowercase letters, digits and hyphens.",
  "check.email.dkim.present.title": "DKIM key published for the sending domain",
  "check.email.dkim.present.pass": "A DKIM public key of at least 1024 bits is published at the selector your provider signs with.",
  "check.email.dkim.present.fail": "No usable DKIM key at the expected selector. Receivers cannot verify your messages were sent by you, and DMARC cannot pass on DKIM.",
  "check.email.dkim.present.fix": "Add the DKIM TXT record your provider shows on its domain page (for Resend, the resend._domainkey record). If the selector differs, set it under Advanced on the connection. A record with an empty p= is a revoked key: rotate it at the provider and publish the new one.",
  "check.email.spf.returnpath.title": "SPF on the bounce domain names your provider",
  "check.email.spf.returnpath.pass": "Exactly one SPF record on the return-path domain includes your provider and ends with a fail policy.",
  "check.email.spf.returnpath.fail": "The return-path domain has no single SPF record naming your provider with a fail policy, so bounces and SPF alignment cannot be trusted.",
  "check.email.spf.returnpath.fix": "Publish one TXT record on the return-path subdomain (for Resend: send.yourdomain) reading v=spf1 include:<provider> ~all. Two SPF records is a permanent error; merge them into one.",
  "check.email.dmarc.enforced.title": "DMARC at quarantine or reject on the sending domain",
  "check.email.dmarc.enforced.pass": "DMARC is published with a quarantine or reject policy, so forged mail from this domain is filtered.",
  "check.email.dmarc.enforced.fail": "DMARC is missing or set to none, so anyone can send as this domain and receivers will accept it.",
  "check.email.dmarc.enforced.fix": "Publish a TXT record at _dmarc.yourdomain with v=DMARC1; p=quarantine (or reject once reports show only your mail aligns). Start with quarantine and a rua address, watch a week of reports, then move to reject.",
  "check.email.dmarc.reporting.title": "DMARC reports go somewhere",
  "check.email.dmarc.reporting.pass": "The DMARC record names a reporting address, so someone learns when the domain is spoofed or a legitimate source breaks.",
  "check.email.dmarc.reporting.fail": "The DMARC record has no rua= address. Failures and spoofing attempts are invisible.",
  "check.email.dmarc.reporting.fix": "Add rua=mailto:dmarc@yourdomain (or a report processor's address) to the _dmarc TXT record. Receivers send daily aggregate reports there; read them before tightening the policy.",
  "check.email.mta_sts.title": "MTA-STS enforces TLS on mail delivered to you",
  "check.email.mta_sts.pass": "An MTA-STS policy is published in enforce mode, served directly as text/plain, and its mx: lines cover every MX record for the domain.",
  "check.email.mta_sts.fail": "No MTA-STS policy a sending server will act on. Either there is no policy in enforce mode, or the policy is published in a way conforming senders reject: reached through a redirect, not served as text/plain, missing a usable max_age, or listing exchangers that do not match this domain's MX records. Mail sent to this domain can be downgraded to plain text by an attacker on the path.",
  "check.email.mta_sts.fix": "Publish _mta-sts.yourdomain TXT v=STSv1; id=<date>, and serve https://mta-sts.yourdomain/.well-known/mta-sts.txt with version: STSv1, mode: enforce, your mx: lines and max_age: 604800. Serve it directly as text/plain with no redirect, and check the mx: lines against your live MX records before you switch to enforce: in enforce mode an exchanger the policy does not list makes senders reject your mail rather than deliver it. Run in testing mode for a week first if you receive mail through more than one provider, and change the id when you change the policy or senders keep the cached one until max_age expires.",
  "check.email.mta_sts.mx_match.title": "Your enforcing MTA-STS policy lists the right mail exchangers",
  "check.email.mta_sts.mx_match.pass": "Either no MTA-STS policy is in force, or the one that is lists every MX record this domain publishes.",
  "check.email.mta_sts.mx_match.fail": "Your MTA-STS policy is in enforce mode and does not list every mail exchanger for this domain. Senders that honour the policy are rejecting mail to the missing ones rather than delivering it, so mail is being lost now.",
  "check.email.mta_sts.mx_match.fix": "Add the missing exchangers to the mx: lines at https://mta-sts.yourdomain/.well-known/mta-sts.txt, or switch mode: to testing until they match. Then change the id in the _mta-sts.yourdomain TXT record, because senders keep the policy they already fetched until max_age runs out and will go on rejecting until they refresh.",
  "check.email.tlsrpt.title": "TLS reporting is configured",
  "check.email.tlsrpt.pass": "A TLS-RPT record names where senders should report failed TLS negotiations to your mail servers.",
  "check.email.tlsrpt.fail": "No TLS-RPT record. If TLS to your mail servers breaks, nobody is told.",
  "check.email.tlsrpt.fix": "Publish _smtp._tls.yourdomain TXT v=TLSRPTv1; rua=mailto:tls@yourdomain. Pair it with MTA-STS; the reports are what tell you enforce mode is safe.",
  // ── terms of service (private beta draft) ────────────────────────────────
  // Describes how the product behaves today. Solicitor review replaces it in
  // Phase 4; change the code, change the sentence, change the date.
  "terms.title": "Terms of service",
  "terms.updated": "Private beta terms, last updated 6 September 2026. A solicitor-reviewed version replaces these before general availability.",
  "terms.intro": "These terms are the agreement between Archema Labs, the company in the United Kingdom that operates Snoopios, and you, the organisation using it. By creating an account or connecting a service you accept them.",
  "terms.s1.h": "What Snoopios does",
  "terms.s1.p": "Snoopios reads the configuration of the services you connect, using read-only credentials you supply, runs deterministic checks against them on a schedule, stores the raw evidence each check read, and generates documents and a public status page from the results. Every result describes what was observed at a point in time. Snoopios does not certify you, does not give legal advice, and is not a substitute for a qualified assessor or solicitor.",
  "terms.s2.h": "Your account and your credentials",
  "terms.s2.p": "You are responsible for keeping your sign-in private and for the credentials you connect. Connect only read-only credentials; Snoopios refuses credential types it can recognise as write-capable, but the scope you grant is yours to set. You may remove a connection at any time and its credential is deleted immediately. You confirm you are entitled to connect the services you connect.",
  "terms.s3.h": "Acceptable use",
  "terms.s3.p": "Use Snoopios only against services you own or are authorised to assess. Do not attempt to access other customers' data, to circumvent rate limits or access controls, or to use the trust-page request flow to harass or spam. We may suspend an account that does.",
  "terms.s4.h": "Documents and the trust page",
  "terms.s4.p": "Generated documents are drafts for your review. You decide what to publish on your trust page and which documents visitors may request. The confidentiality undertaking a visitor accepts is between that visitor and you; Snoopios hosts the documents and keeps the register of requests and downloads on your behalf.",
  "terms.s5.h": "Fees and trial",
  "terms.s5.p": "New accounts have a 14-day trial with Studio limits and no card. After it, the Free tier continues with one project on weekly checks, or you choose a paid plan at the published price, billed monthly per organisation. Prices may change with 30 days' notice by email; a change never applies to a period you have already paid for.",
  "terms.s6.h": "Your data",
  "terms.s6.p": "How we handle personal data is set out in the privacy notice, which forms part of these terms. The configuration data and evidence Snoopios stores about your services belong to you; you can export them from Settings and delete them by deleting your account, after a 30-day grace period you can cancel.",
  "terms.s7.h": "Availability and liability",
  "terms.s7.p": "Snoopios is provided as it is, during a private beta, without a guarantee of uninterrupted availability. A check that cannot run reports unknown rather than a result. To the extent the law allows, Archema Labs' total liability under these terms is limited to the fees you paid in the twelve months before the claim, and Archema Labs is not liable for indirect or consequential loss, including the outcome of any audit, assessment, certification or regulatory action. Nothing in these terms limits liability that cannot be limited by law.",
  "terms.s8.h": "Ending the agreement",
  "terms.s8.p": "You may stop at any time by deleting your account. We may end the agreement with 30 days' notice, or immediately if these terms are breached. On ending, your data is deleted as the privacy notice describes.",
  "terms.s9.h": "Law",
  "terms.s9.p": "These terms are governed by the law of England and Wales, and the courts of England and Wales have jurisdiction. If a part of these terms is found unenforceable, the rest still applies.",
  "terms.contact": "Questions about these terms:",
  // ── vercel connector (integration install, read-only scopes) ────────────
  "conn.vercel.title": "Connect Vercel",
  "conn.vercel.intro": "Vercel personal tokens cannot be made read-only, so Snoopios connects as an integration whose scopes are fixed: read on projects, deployments, domains and team settings, nothing else. You approve it on Vercel and come straight back.",
  "conn.vercel.cta": "Install the Snoopios integration on Vercel",
  "conn.vercel.label.team": "Vercel team",
  "conn.vercel.label.personal": "Vercel personal account",
  "conn.vercel.connected": "Vercel is connected. The first run starts within a minute.",
  "conn.vercel.error": "The Vercel install did not complete. Try again from this page; if it repeats, email us.",
  "conn.vercel.error.no_projects": "The install completed, but it can see no projects, so there would be nothing to check. If Vercel asked you to choose specific projects, install again and include the ones you want checked. Nothing has been saved.",
  "conn.vercel.error.auth": "Vercel would not let the new installation read your projects. That usually means the install was removed on Vercel's side before it finished. Install again from this page. Nothing has been saved.",
  "conn.vercel.error.unreachable": "Vercel did not answer in a way we could read. Nothing has been saved; try again shortly.",
  "check.vercel.projects.preview_protection.title": "Preview deployments are protected",
  "check.vercel.projects.preview_protection.pass": "Every project protects its preview deployments with Vercel Authentication or a password.",
  "check.vercel.projects.preview_protection.fail": "Some projects serve preview deployments to anyone with the link, including branches with unreleased features and test data.",
  "check.vercel.projects.preview_protection.fix": "Project \u2192 Settings \u2192 Deployment Protection \u2192 Vercel Authentication (or Password Protection on Pro) for Preview Deployments. Do it for each project named in the observed list.",
  "check.vercel.projects.fork_protection.title": "Git fork protection is on",
  "check.vercel.projects.fork_protection.pass": "Pull requests from forks need a team member's approval before a deployment with your environment variables is built.",
  "check.vercel.projects.fork_protection.fail": "A pull request from a stranger's fork can trigger a build that runs with your environment variables.",
  "check.vercel.projects.fork_protection.fix": "Project \u2192 Settings \u2192 Git \u2192 Git Fork Protection: on. Then review who can push to the connected repository.",
  "check.vercel.projects.node_supported.title": "Node.js version is a supported release",
  "check.vercel.projects.node_supported.pass": "Every project builds on a Node.js release Vercel still patches.",
  "check.vercel.projects.node_supported.fail": "A project builds on a Node.js release that no longer receives security fixes.",
  "check.vercel.projects.node_supported.fix": "Project \u2192 Settings \u2192 General \u2192 Node.js Version: choose the newest LTS Vercel offers, redeploy, and fix anything the upgrade breaks. Also pin engines in package.json so local and hosted agree.",
  "check.vercel.domains.verified.title": "Every project domain is verified",
  "check.vercel.domains.verified.pass": "All domains attached to your projects are verified and serving.",
  "check.vercel.domains.verified.fail": "A domain is attached but not verified, so it is not serving your site and could be claimed elsewhere.",
  "check.vercel.domains.verified.fix": "Project \u2192 Settings \u2192 Domains \u2192 the unverified domain shows the DNS record to add. Add it at your DNS host, then Refresh.",
  "check.vercel.deployments.no_recent_errors.title": "No failed production deployments in 30 days",
  "check.vercel.deployments.no_recent_errors.pass": "Every production deployment in the last 30 days built and deployed.",
  "check.vercel.deployments.no_recent_errors.fail": "Production deployments failed in the last 30 days. A build that fails on main means the fix for the next incident may not ship.",
  "check.vercel.deployments.no_recent_errors.fix": "Deployments \u2192 filter Errors \u2192 open the failed build's logs. Fix the cause, and add the failing step to CI so it breaks before it reaches Vercel.",
  // ── evidence locker (customer uploads per control) ───────────────────────
  "locker.title": "Your evidence",
  "locker.body": "Attach the document that shows this control is in place: a signed policy, a training record, a screenshot of a setting. Each file gets a plain review the moment it lands: dated within a year, an owner, an approver, your organisation named, and the topics the control is about. The review is a checklist, not an opinion.",
  "locker.empty": "Nothing attached yet.",
  "locker.backing.title": "What Snoopios already holds for this control",
  "locker.verdict.pass": "Accepted",
  "locker.verdict.review": "Needs attention",
  "locker.remove": "Remove",
  "locker.form.title": "Attach a document",
  "locker.form.topics": "Terms the review looks for:",
  "locker.form.file": "File",
  "locker.form.file.hint": "PDF, PNG, JPEG, text, markdown or Word, up to 10 MB. Text, markdown and Word are read for the topic check; PDFs and images are not.",
  "locker.form.date": "Document date",
  "locker.form.owner": "Owner",
  "locker.form.approver": "Approved by",
  "locker.form.note": "Note",
  "locker.form.note.placeholder": "Optional: where the original lives, or what an assessor should read first",
  "locker.form.submit": "Attach and review",
  "locker.notice.pass": "Attached and accepted. This control now counts as evidenced by you.",
  "locker.notice.review": "Attached. The review found something to fix; see the lines under the file. It counts once every line holds.",
  "locker.notice.removed": "Removed.",
  "locker.notice.toolarge": "That file is over 10 MB.",
  "locker.notice.type": "That file type is not accepted. Use PDF, PNG, JPEG, text, markdown or Word.",
  "locker.notice.nofile": "Choose a file first.",
  "locker.notice.error": "The file could not be attached. Only an owner or admin can attach evidence, and there is a cap of twenty files per control.",
  "coverage.kind.upload": "Your evidence",
  "coverage.attach": "Evidence",
  "coverage.kind.attested": "Attested",
  "coverage.kind.provider": "Provider report",
  "coverage.provider.open": "Provider reports",
  "attest.title": "Confirm it yourself",
  "attest.body": "Tick the statement below if it is true of your organisation today. Snoopios records who confirmed it, when, and the exact words, and counts the control as attested for twelve months. It is shown everywhere as your statement, never as something Snoopios checked. Attaching a document below is optional and outranks the tick once its review passes.",
  "attest.confirm": "I confirm this statement is true today",
  "attest.submit": "Record attestation",
  "attest.current": "Attested by",
  "attest.on": "on",
  "attest.expires": "lapses",
  "attest.withdraw": "Withdraw",
  "attest.lapsed": "This attestation lapsed. Confirm the statement again if it is still true.",
  "attest.notice.done": "Recorded. This control now counts as attested until the date shown; renew it before then.",
  "attest.notice.withdrawn": "Attestation withdrawn.",
  "attest.notice.reference": "The reference does not look right. Check the hint under the field.",
  "attest.notice.confirm": "Tick the box to confirm the statement.",
  "attest.notice.error": "The attestation could not be recorded. Only an owner or admin can attest.",
  "attest.ico.statement": "{org} is registered with the Information Commissioner's Office as a data controller and the annual data protection fee is paid.",
  "attest.ico.reference": "ICO registration number",
  "attest.ico.hint": "Starts with Z, for example ZA123456. It is on your ICO confirmation email and in the public register.",
  "attest.malware.statement": "Every device used to reach {org}'s systems runs malware protection that updates itself, or is a platform whose built-in protection is switched on and current.",
  "attest.malware.reference": "Protection in use",
  "attest.malware.hint": "For example Microsoft Defender, macOS XProtect and Gatekeeper, CrowdStrike, or a managed device policy.",
  "attest.oversight.statement": "Someone independent of day-to-day operations (a board, an adviser, an investor or a named external reviewer) reviews {org}'s security posture at least twice a year and the review is minuted.",
  "attest.oversight.reference": "Who reviews, and the date of the last review",
  "attest.capacity.statement": "{org} reviews usage of its hosting, database and edge providers against plan limits at least monthly and has headroom or an upgrade path for each.",
  "attest.capacity.reference": "Where usage is watched",
  "attest.capacity.hint": "For example the Supabase and Vercel usage pages, or a dashboard.",
  "attest.duties.statement": "Where one person at {org} holds conflicting duties (writing and approving code, administering and using production), the conflict is written down and compensated: branch protection that requires review, immutable evidence, or a second person's periodic check.",
  "attest.duties.reference": "Compensating control",
  "attest.duties.hint": "Which of those applies, in a few words.",
  "attest.groups.statement": "{org} follows at least one security advisory source relevant to its stack (provider status and security pages, the NCSC, GitHub security advisories) and acts on what it reads.",
  "attest.groups.reference": "Sources followed",
  "attest.threat.statement": "{org} collects threat information about its stack (dependency alerts, provider advisories, vulnerability disclosures), reviews it at least monthly and records what changed as a result.",
  "attest.threat.reference": "Where threat information comes from",
  "attest.ip.statement": "{org} owns or is licensed for all software, content and data it uses; the licences of its open-source dependencies are reviewed and no licence term is breached by how the software is distributed.",
  "attest.ip.reference": "Where the licence inventory lives",
  "attest.ip.hint": "For example a LICENSES file, a dependency report, or the package manifest.",
  "attest.review.statement": "{org}'s information security arrangements are reviewed by someone independent of the people who run them at least annually, and the findings are recorded.",
  "attest.review.reference": "Reviewer and date of the last review",
  "attest.webfilter.statement": "Devices used for {org}'s work block known malicious sites through browser safe-browsing, DNS filtering or endpoint protection, and that protection is switched on.",
  "attest.webfilter.reference": "Protection in use",
  "attest.audit.statement": "Audits and penetration tests of {org}'s systems are agreed in writing beforehand, scoped, run against non-production data where possible, and give the tester read-only access.",
  "advice.title": "Written feedback",
  "advice.body": "If you ask, the file's text and the review lines are sent to an AI language model provider, which writes suggestions for making it stronger evidence for this control. The suggestions are advice; the review's verdict does not change.",
  "advice.ask": "Ask for feedback",
  "advice.written": "Written by an AI language model on",
  "advice.notice.done": "Feedback written; it is shown under the file.",
  "advice.notice.unavailable": "Written feedback is not switched on in this deployment yet.",
  "advice.notice.limit": "Feedback is limited to ten requests an hour for your organisation. Try again later.",
  "advice.notice.uninspected": "That file's text cannot be read (PDF or image), so there is nothing to comment on. Attach a text, markdown or Word version for feedback.",
  "advice.notice.error": "Feedback could not be written. Try again in a minute.",
  "provider.title": "Provider reports",
  "provider.intro": "Data-centre controls (physical perimeters, cabling, utilities, redundancy, network segregation) are held by the companies that run the machines. Each publishes an independent SOC 2 or ISO 27001 report you can download from its trust page, usually after accepting a non-disclosure agreement. Attach the current report for every connected host and those controls count as evidenced by the provider.",
  "provider.none": "No hosting provider is connected to this project yet. Connect Supabase, Vercel or Cloudflare first.",
  "provider.all": "Every connected host has an accepted report. The provider-held controls count as evidenced.",
  "provider.some": "Attach an accepted report for every connected host before the provider-held controls count.",
  "provider.status.accepted": "Report attached",
  "provider.status.missing": "No accepted report",
  "provider.status.disconnected": "Host no longer connected; remove the report or reconnect",
  "provider.trust": "Trust page",
  "provider.publishes": "Publishes:",
  "provider.form.title": "Attach a report",
  "provider.form.date": "Report date (end of the audit period, or issue date)",
  "provider.form.obtained": "Obtained by (you or a colleague)",
  "provider.form.issuer": "Issued by (the audit firm)",
  // ── support ───────────────────────────────────────────────────────────────
  // The answer tree (lib/support-content.ts). Every answer describes code that
  // exists and numbers that come from the same place the product reads them.
  // Change the code, change the answer. Policy-level answers where no screen
  // shows the figure; deep links wherever a screen does.
  "support.title": "Support",
  "support.intro": "Answers first, a person second. Pick a topic, or jump straight to the question.",
  "support.nav": "Topics",
  "support.human": "Not answered above? A person reads every email:",
  "support.other.title": "Something else",
  "support.other.body": "If your question isn't here, email us with the project name and what you expected to see. Replies come from a person, usually the same working day.",
  "support.other.cta": "Email support",
  "support.other.subject": "Snoopios support",
  "support.link.checks": "Open Checks",
  "support.link.plan": "Open Plan",
  "support.link.settings": "Open Settings",
  "support.link.privacy": "Read the privacy notice",
  "support.cat.start.title": "Getting started",
  "support.q.start.1": "What do I need to connect first?",
  "support.a.start.1": "Create a project with the domain you serve customers from. The domain checks run with no credentials at all, so you see real findings within a minute. Then add the providers you use: Supabase, GitHub, Cloudflare and Stripe each take one read-only token.",
  "support.q.start.2": "How often do checks run?",
  "support.a.start.2": "Every hour on Studio, Scale and the trial, every six hours on Solo, and weekly on the Free tier. You can also press Run now on any project once a minute. The Plan page shows the interval your organisation is on.",
  "support.q.start.3": "What is a check, exactly?",
  "support.a.start.3": "A check is a small piece of code that reads one fact from your stack, compares it to a rule, and stores what it read as evidence. It returns pass, fail or unknown. No model decides a result, and the same input always gives the same answer.",
  "support.q.start.4": "Can several people share an organisation?",
  "support.a.start.4": "Not yet. Every account gets its own organisation and one sign-in. Shared organisations and client switching are planned for when paying customers ask for them; until then, share the trust page and the exported documents rather than the sign-in.",
  "support.cat.results.title": "Results and evidence",
  "support.q.results.1": "What do pass, fail and unknown mean?",
  "support.a.results.1": "Pass means the rule was met when the check ran. Fail means it was not. Unknown means the check could not read what it needed, usually because of a missing permission or a network error. Unknown is never shown as a pass, anywhere, including your public trust page.",
  "support.q.results.2": "A check says unknown. What do I do?",
  "support.a.results.2": "Open the check. The page names the scope or setting it could not reach. Most unknowns are a token without the read permission the check needs; add the permission on the provider's side and press Run now. If the provider was briefly unreachable, the next scheduled run clears it.",
  "support.q.results.3": "How do I fix a failing check?",
  "support.a.results.3": "Each check page says what was observed, what the rule expects, and where to change it in the provider's dashboard. Fix it there, then press Run now. The next pass is recorded as a new run; the failing run stays in the history because evidence is never rewritten.",
  "support.q.results.4": "Where is the evidence and can I download it?",
  "support.a.results.4": "Every run stores the raw response the check read, in a private bucket only your organisation can reach. The check page lists runs with a download for each and the SHA-256 of the file, so an assessor can confirm the copy you send them is the copy we stored.",
  "support.q.results.5": "How long is evidence kept?",
  "support.a.results.5": "For as long as your tier's retention window: one month on Free, twelve months on Solo and Studio, twenty-four on Scale. Runs older than the window are removed by the nightly job, along with their stored files. The current state of every check survives the prune.",
  "support.q.results.6": "Will I be told when something starts failing?",
  "support.a.results.6": "Yes. The first time a check goes from passing to failing you get one email naming the project and the check. Repeated failures of the same check do not repeat the email; a check going back to pass ends the episode.",
  "support.q.results.7": "Can I accept a failing check instead of fixing it?",
  "support.a.results.7": "Yes, with a reason and a review date of one to twelve months, from the check page. The check keeps running and keeps reporting fail everywhere, including the trust page, which shows an Accepted tag beside it so a reviewer knows it was a decision. The first-fail email stays quiet until the acceptance lapses; if the check still fails then, you get one email. Only a failing check can be accepted.",
  "support.cat.tokens.title": "Connections and tokens",
  "support.q.tokens.1": "Which token does each provider need?",
  "support.a.tokens.1": "Supabase: a personal access token, used only against read endpoints. GitHub: a fine-grained personal access token with read-only repository and organisation permissions; classic tokens are refused. Cloudflare: an API token scoped to read on the zones you name. Stripe: a restricted key with read permissions; a secret key is refused. Email: no key at all; the checks read the public DNS your recipients read.",
  "support.q.tokens.2": "How are my tokens stored?",
  "support.a.tokens.2": "Encrypted with AES-256-GCM before they reach the database, with a key that is held on the host and never stored alongside the data. Tokens are never logged and never appear in an error message. A connection that would need a write scope is not built.",
  "support.q.tokens.3": "How do I remove a connection or rotate a token?",
  "support.a.tokens.3": "On the project page, press Remove next to the connection. The ciphertext is deleted immediately; the findings and evidence it produced stay, because they are a record of what was true. To rotate, remove and add again with the new token, then revoke the old one at the provider.",
  "support.q.tokens.4": "Where is Vercel?",
  "support.a.tokens.4": "Coming. Vercel's personal tokens cannot be scoped read-only, so we will not accept one. The Vercel checks arrive with an official integration that grants exactly the read access they need and nothing more.",
  "support.cat.trust.title": "Trust page",
  "support.q.trust.1": "What does the public trust page show?",
  "support.a.trust.1": "Each check's name, its current status and when it was last seen, grouped by provider, plus the counts and the time of the last run. No evidence, no observed values, no organisation or connection details leave through it. Unknown is shown grey.",
  "support.q.trust.2": "Who can see it, and can it be guessed?",
  "support.a.trust.2": "Anyone with the link, while the page is switched on. The address ends in six random characters, so it cannot be built from your project name. Switch it off on the project page and the link stops working straight away.",
  "support.q.trust.3": "The trust page is behind my latest run.",
  "support.a.trust.3": "It is cached for five minutes. A reviewer does not need the last thirty seconds, and the cache keeps the page fast when a prospect shares it around. Wait five minutes and reload.",
  "support.q.trust.4": "How do gated documents on the trust page work?",
  "support.a.trust.4": "On the project page, tick the pack documents visitors may request. The trust page then shows a request button. A visitor gives a name, work email and company and accepts a confidentiality undertaking; you approve or decline on the project page; approval emails a link that works for seven days, and every download is recorded against the request so you hold a register of who received what.",
  "support.cat.pack.title": "Document pack",
  "support.q.pack.1": "Which documents can I generate?",
  "support.a.pack.1": "Nineteen today: the privacy notice, the record of processing activities, the sub-processor register, the retention schedule, the breach runbook, the requests and complaints procedure, the security summary, a Cyber Essentials readiness sheet, and eleven policies from the information security policy to the DPIA screening, plus a questionnaire answer bank you can export. Each is built from what is connected and what the checks observed.",
  "support.q.pack.2": "What are the coloured badges in a document?",
  "support.a.pack.2": "Each badge is a claim tied to a check. Green: the check passed on the date shown. Red: it failed, so the sentence is not true yet. Grey: the check could not read what it needed, so we do not know. A document never asserts something its checks cannot support.",
  "support.q.pack.3": "Are these documents legal advice, or a certification?",
  "support.a.pack.3": "Neither. Every document is a draft for your review and says so, with the date it was generated. Snoopios tells you what was checked and when. It does not certify you, and a document should go past a person who knows your business before it goes to a customer.",
  "support.q.pack.4": "Can I download or edit a document?",
  "support.a.pack.4": "Each document downloads as markdown with the claim statuses written as words and dates, so it stands alone. Edit the file in whatever you write in. Sections marked fill in are the facts only you know.",
  "support.cat.plan.title": "Plan and billing",
  "support.q.plan.1": "What does the trial include?",
  "support.a.plan.1": "Fourteen days with Studio limits: up to five projects, hourly checks, the evidence vault and the document pack. Nothing is charged, and no card is asked for. The trial starts the day you confirm your email and cannot be extended.",
  "support.q.plan.2": "What happens when the trial ends?",
  "support.a.plan.2": "The organisation moves to the Free tier: one project on weekly checks, one month of evidence. Nothing is deleted, but projects beyond the first stop running until you choose a plan. Support and Settings keep working.",
  "support.q.plan.3": "How do I pay?",
  "support.a.plan.3": "Card checkout is coming with the next release. Until then, email us from the Plan page and we set the plan up by hand and invoice you. Prices are per organisation, counted by projects, never by headcount.",
  "support.q.plan.4": "Can I change or cancel a plan?",
  "support.a.plan.4": "Yes, at any time, with no notice period. Moving down applies the lower tier's limits from the next run; evidence beyond the new retention window is pruned by the nightly job, so download anything you want to keep first.",
  "support.cat.account.title": "Account and data",
  "support.q.account.1": "How do I get a copy of my data?",
  "support.a.account.1": "Settings has an export button. It produces one JSON file with your profile, organisation, projects, connections without their secrets, findings and check runs with evidence references. One export a minute.",
  "support.q.account.2": "How do I delete my account?",
  "support.a.account.2": "Request deletion from Settings. A thirty-day grace period starts, during which you can cancel from the same page or delete immediately. When it ends, the organisation, its projects, connections, evidence and your sign-in are removed. If others belong to the organisation, you leave it and their history stays.",
  "support.q.account.3": "Where is my data held?",
  "support.a.account.3": "In a Supabase project hosted in London, with evidence storage in the same region. The privacy notice lists every provider that touches it and why.",
  "support.q.account.4": "I did not get the confirmation email.",
  "support.a.account.4": "Check spam for a message from Snoopios, and give it a minute; sending is limited to one message a minute per address. The link is valid for an hour. If it has expired, sign up again with the same address and a fresh one is sent.",
  // ── plan ──────────────────────────────────────────────────────────────────
  "plan.title": "Plan",
  "plan.current": "Current",
  "plan.state.trial": "You're on the 14-day trial with Studio limits. Nothing is charged until you choose a plan.",
  "plan.state.paid": "Your plan is active. Thank you.",
  "plan.state.free": "Your trial has ended. The Free tier keeps one project on weekly checks; choose a plan to keep scheduled checks, the evidence vault and the document pack.",
  "plan.checkout.soon": "Card checkout is coming with the next release. To start a paid plan now, email",
  // ── onboarding fallback ───────────────────────────────────────────────────
  "onboarding.title": "Finishing your account",
  "onboarding.body": "Your sign-in worked but the account setup behind it didn't complete. Sign out, sign in again, and if this screen comes back, email hello@snoopios.com.",
  // ── footer ────────────────────────────────────────────────────────────────
  "footer.company": "Snoopios is a product of Archema Labs, United Kingdom.",
  "footer.privacy": "Privacy",
  "footer.terms": "Terms",
  "footer.contact": "Contact",
  "footer.contact.email": "hello@snoopios.com",
  // ── privacy notice (marketing site) ──────────────────────────────────────
  // Every sentence here describes code that exists. Change the code, change
  // the sentence, change the date. In that order.
  "privacy.title": "Privacy notice",
  "privacy.updated": "Last updated 12 September 2026",
  "privacy.intro": "This notice describes what Snoopios does with personal data today. Every sentence describes code that exists. A solicitor reviews it before launch; until then it is a draft that is nonetheless true.",
  "privacy.s1.h": "Who we are",
  "privacy.s1.p": "Snoopios is a product of Archema Labs, a company in the United Kingdom and the controller for the data described here. Archema Labs is registered with the Information Commissioner's Office.",
  "privacy.s10.h": "Asking for a place in the beta",
  "privacy.s10.p": "While sign-ups are closed you can ask for a place using the form at /beta. It records three things: your email address, which platforms you ticked, and the line you wrote about who is asking you for compliance. We use them to decide who to invite and to reply to you, and for nothing else. There is no marketing list and nothing is shared with anyone. Your address is the key, so asking twice updates what you sent rather than adding a second entry. We keep a request until we invite you or close it, and for twelve months after that, then it is deleted by the same nightly job that applies every other retention rule here. Ask us at any time and we will delete it sooner.",
  "privacy.s2.h": "Accounts",
  "privacy.s2.p": "When you create an account we hold your email address, the name you give, and a password hash kept by our authentication provider. We use them to sign you in, to send the emails the product needs (confirmation, a check that starts failing, a document access decision), and for nothing else. There is no marketing list.",
  "privacy.s3.h": "Projects and connections",
  "privacy.s3.p": "The tokens you connect are encrypted (AES-256-GCM) before they reach our database with a key that is held only in the application's runtime environment, are used only to read configuration from the provider, are never written to logs or error messages, and are deleted the moment you remove the connection. Everything travels over TLS; the database and file storage are encrypted at rest; every table is protected by row-level security so one organisation can never read another's rows; evidence files live in a private bucket and are reachable only through short-lived signed links minted for a signed-in member; and the encryption key is rotated with both the old and new key proved to work before the old one is retired. Each check stores the raw response it read as evidence, kept for the number of months your plan states and then deleted by a nightly job. Documents you attach to a control as your own evidence are stored in a private bucket for your organisation, reviewed by a fixed checklist and never by a model, kept for the life of the account, and included in your export. Evidence can contain identifiers from your own systems; it is never shared with anyone but the members of your organisation. If you confirm a statement about your organisation on a control, we record your name, the time and the words you confirmed, and show them to the members of your organisation. If you ask for written feedback on a document you attached, its text and the review lines are sent once to an AI language model provider, which returns the suggestions; nothing is sent unless you ask, and the feature stays switched off until that provider's agreement, retention and region are recorded in this notice.",
  "privacy.s4.h": "Visitors to a trust page",
  "privacy.s4.p": "If you request documents from a customer's trust page we hold the name, work email and company you give, the time you accepted the confidentiality undertaking, a keyed hash of your IP address for abuse limits, the decision, and a record of each download. The customer whose page it is sees this register; that customer, not Snoopios, decides your request. Requests are kept for 24 months and then deleted.",
  "privacy.s5.h": "Who else is involved",
  "privacy.s5.p": "Data is held in a Supabase project in London (Supabase Inc., under its data processing addendum). The application runs on Vercel and is served through Cloudflare, which see the ordinary technical data any web server sees, such as your IP address, to deliver pages and defend against abuse. Email is sent through Resend. These four are the only organisations that process data for us, and each acts only on our instructions as a processor. We do not sell personal data, do not share it with advertisers or data brokers, and do not disclose it to anyone else unless the law requires it, in which case we tell you where we lawfully can. No advertising or analytics scripts run anywhere on the site, so there is no consent banner.",
  "privacy.s8.h": "Data from Google Workspace and other connected providers",
  "privacy.s8.p": "When an administrator connects Google Workspace, Snoopios asks Google for one read-only permission, the user directory, and reads it to answer four questions: is two-step verification enforced and enrolled, how many super-administrators are there, and has any account been unused for ninety days. The fields read are the email address, administrator flags, two-step verification status, suspension state, creation time and last sign-in time. Email addresses are masked before they are shown. This data is used only to compute and display your organisation's own compliance results and the evidence behind them; it is not used for advertising, is not sold, and is not transferred to anyone except the processors named above, which host the service under contract. It is not used to build user profiles, and no artificial intelligence or machine learning model, ours or a third party's, ever receives it: every check is fixed code, and the only model-assisted feature in the product (written feedback on a document you upload yourself) is switched off in production and never reads provider data. Snoopios's use of information received from Google APIs adheres to the Google API Services User Data Policy, including the Limited Use requirements. The same rules apply to every other provider you connect. You can revoke Google's grant at any time from your Google Account permissions page or by removing the connection in Snoopios, and the stored refresh token is deleted at that moment.",
  "privacy.s6.h": "Cookies",
  "privacy.s6.p": "The application sets the cookies that keep you signed in and nothing else. The marketing pages set none.",
  "privacy.s7.h": "Your rights",
  "privacy.s7.p": "From Settings you can download everything your account participates in as one file, and you can delete the account: a 30-day grace period you can cancel, then removal of the organisation, its projects, connections, evidence and your sign-in. You can also ask us anything about your data by email; we answer within one month. If you are unhappy with our answer you can complain to us first, and then to the Information Commissioner's Office.",
  "privacy.contact": "Questions and requests:",
  "privacy.contact.email": "privacy@snoopios.com",
  // ── PWA install ───────────────────────────────────────────────────────────
  "pwa.install": "Add this to your home screen.",
  "pwa.install.cta": "Install",
  // iOS never fires beforeinstallprompt, so this is real instructions rather
  // than a button that does nothing. See the pwa-offline skill.
  "pwa.ios.hint": "Tap the share button, then Add to Home Screen.",
  "pwa.hint.title": "Install Snoopios",
  "pwa.hint.why": "It opens in its own window, keeps you signed in, and works offline for the pages you have already seen.",
  "pwa.hint.ios": "In Safari, tap the share button at the bottom of the screen, scroll down, then tap Add to Home Screen.",
  "pwa.hint.safari": "In Safari, open the File menu and choose Add to Dock. On iPhone and iPad, use the share button, then Add to Home Screen.",
  "pwa.hint.firefox": "Firefox on the desktop does not install web apps. Snoopios works normally in the browser, and Chrome, Edge or Safari will install it if you want it in its own window.",
  "pwa.hint.other": "Look for an install icon in the address bar, or an Install app item in the browser menu.",
  "pwa.hint.close": "Close",
  "check.gcp.storage.public_access_prevention.title": "No bucket can be made public, whatever its permissions say",
  "check.gcp.storage.public_access_prevention.pass": "Every bucket enforces public access prevention.",
  "check.gcp.storage.public_access_prevention.fail": "At least one bucket does not enforce public access prevention. Nothing is public today, but one permission change makes it so, and that change does not need a deployment or a review.",
  "check.gcp.storage.public_access_prevention.fix": "Open the bucket, Permissions, then Public access, and set prevention to enforced. It overrides the bucket's own permissions, so nothing can expose it later by mistake. Set it on the organisation or folder instead if you want it to cover buckets nobody has made yet.",
  "check.aws.s3.account_public_access_blocked.title": "No bucket can be made public, including the next one",
  "check.aws.s3.account_public_access_blocked.pass": "The account blocks public access to S3 for every bucket, present and future.",
  "check.aws.s3.account_public_access_blocked.fail": "The account-wide block on public S3 access is not fully on. Each bucket is then only as safe as its own settings, and the next bucket somebody creates starts without any.",
  "check.aws.s3.account_public_access_blocked.fix": "Open S3, then Block Public Access settings for this account, and turn on all four. It overrides individual buckets, so nothing can be shared publicly by mistake afterwards. Check first that you do not deliberately serve a public website from a bucket, because that will stop working.",
  "check.aws.s3.access_logging.title": "You could tell who read a file",
  "check.aws.s3.access_logging.pass": "Every bucket records who accessed it.",
  "check.aws.s3.access_logging.fail": "At least one bucket has no access logging, so there is no record of who read or wrote anything in it.",
  "check.aws.s3.access_logging.fix": "Open the bucket, Properties, then Server access logging, and point it at a logging bucket. Logs cost storage, so it is reasonable to enable it on the buckets that hold anything sensitive and note why the others are exempt in your risk register.",
  "check.aws.config.recording.title": "Changes to your AWS setup are recorded",
  "check.aws.config.recording.pass": "AWS Config is recording the configuration of this region and delivering it successfully.",
  "check.aws.config.recording.fail": "AWS Config is not recording, or is recording and failing to deliver. Either way there is no history of how the account was configured, so a question about when a setting changed cannot be answered from evidence.",
  "check.aws.config.recording.fix": "Open AWS Config and set up the recorder for this region, with a delivery bucket it can write to. If it is already on, check the last status: a delivery failure usually means the bucket policy does not allow Config to write.",
  "check.aws.accessanalyzer.enabled.title": "Something is watching for access from outside the account",
  "check.aws.accessanalyzer.enabled.pass": "An IAM Access Analyzer is active in this region.",
  "check.aws.accessanalyzer.enabled.fail": "No Access Analyzer is active, so nothing is telling you when a bucket, role, key or queue becomes reachable from outside the account.",
  "check.aws.accessanalyzer.enabled.fix": "Open IAM, Access Analyzer, and create an analyzer with the account as its zone of trust. It is free for external access findings and it is the only thing in AWS that answers the question across every resource type at once.",
  "check.aws.lambda.no_public_urls.title": "No function is answering the open internet",
  "check.aws.lambda.no_public_urls.pass": "No Lambda function URL is open without authentication.",
  "check.aws.lambda.no_public_urls.fail": "At least one Lambda function has a URL with authentication set to NONE. That is a public HTTPS endpoint with no firewall in front of it and no record of it in DNS, reachable by anybody who learns the address.",
  "check.aws.lambda.no_public_urls.fix": "Open Lambda, the function, then Configuration, Function URL, and set auth type to AWS_IAM, or remove the URL. If it is meant to be public, such as a webhook receiver, keep the finding and note what it does and what validates the caller.",
  "check.aws.regions.resources_localised.title": "Your servers and databases are all in one region",
  "check.aws.regions.resources_localised.pass": "Every EC2 instance and database in your account is in the region this connection names.",
  "check.aws.regions.resources_localised.fail": "You are running compute or databases in a region Snoopios is not reading. Two things follow: those resources are not being checked at all, and if the region is outside the jurisdiction you told your customers about, that is a data transfer you may need to be able to explain.",
  "check.aws.regions.resources_localised.fix": "Either move the resources, or add a second Snoopios connection for that region so it is checked too. If the resources are meant to be there, the finding is still worth keeping: it is the list an assessor asks for when they ask where personal data lives.",
  "check.aws.ec2.snapshots_not_public.title": "No disk snapshot is shared publicly",
  "check.aws.ec2.snapshots_not_public.pass": "No EBS snapshot in this account is shared with all AWS accounts.",
  "check.aws.ec2.snapshots_not_public.fail": "At least one disk snapshot is public. That is a whole volume, readable by anybody with an AWS account, including everything that was on it when the snapshot was taken.",
  "check.aws.ec2.snapshots_not_public.fix": "Open EC2, Snapshots, select it, then Actions, Modify permissions, and set it back to private. Then work out how long it was public and what was on it, because that is the question you will be asked.",
  "check.aws.ec2.amis_not_public.title": "No machine image is shared publicly",
  "check.aws.ec2.amis_not_public.pass": "No AMI owned by this account is public.",
  "check.aws.ec2.amis_not_public.fail": "At least one machine image is public. An AMI carries whatever was on the disk when it was made, which frequently includes keys, configuration and application code nobody meant to publish.",
  "check.aws.ec2.amis_not_public.fix": "Open EC2, AMIs, select it, then Actions, Edit AMI permissions, and set it to private. Check what the image contains before deciding whether anything needs rotating.",
  "check.aws.rds.snapshots_not_public.title": "No database snapshot is shared publicly",
  "check.aws.rds.snapshots_not_public.pass": "No database snapshot owned by this account is public.",
  "check.aws.rds.snapshots_not_public.fail": "At least one database snapshot is public. Anybody with an AWS account can restore it and read every row that was in the database when it was taken.",
  "check.aws.rds.snapshots_not_public.fix": "Open RDS, Snapshots, select it, then Actions, Share snapshot, and remove the public entry. Treat the contents as disclosed until you know how long it was open.",
  "check.aws.ec2.ebs_encryption_default.title": "New disks are encrypted without anybody remembering",
  "check.aws.ec2.ebs_encryption_default.pass": "This region encrypts new EBS volumes by default.",
  "check.aws.ec2.ebs_encryption_default.fail": "New disks are not encrypted by default, so protection depends on whoever creates the next one remembering to tick the box.",
  "check.aws.ec2.ebs_encryption_default.fix": "Open EC2, then EBS encryption in the account settings for this region, and turn on Always encrypt new EBS volumes. It applies to new volumes only, so the existing ones still need attention separately.",
  "check.aws.iam.credentials_used.title": "Every access key is actually being used",
  "check.aws.iam.credentials_used.pass": "Every active access key has been used in the last ninety days.",
  "check.aws.iam.credentials_used.fail": "At least one active access key has not been used for ninety days, or has never been used at all. An unused credential is all risk and no benefit: it can still open the door and nobody would notice it being used.",
  "check.aws.iam.credentials_used.fix": "Delete the keys nobody needs. If one belongs to something seasonal, note that beside it in your access review so the next reader knows it is deliberate rather than forgotten.",
  "conn.least_privilege": "Grant only the permissions listed above. Providers often pre-select a wider set and present it as the usual choice, and that set frequently includes the ability to write. If Snoopios needed more than this list, this screen would say so.",
  "home.checks.providers": "providers",
  "home.family.infrastructure": "What you run on",
  "home.family.infrastructure.body": "The hosting, databases, domains, monitoring and payments a small software team actually deploys to. This is the layer every compliance tool covers, and the one where being wrong is loudest.",
  "home.family.development": "How you build",
  "home.family.development.body": "Where the code lives, what your scanners found, and whether the work of fixing it has an owner and a date. Snoopios never rescans your code: it reads what your own tools found and asks how quickly anybody acted, which is the question a framework actually poses.",
  "home.family.organisation": "How you are run",
  "home.family.organisation.body": "The half of every framework that is not infrastructure at all: who has access, who joined, who left, what the laptops are doing, where the credentials live, and whether your policies have an owner and a review date. Most tools ask you to type this in. These read it.",
  "home.role.scanning": "Scanning",
  "home.role.secrets": "Secrets",
  "provider.snyk": "Snyk",
  "stack.blurb.snyk": "Runs on the CLI. Reads the issues Snyk already found: open criticals, how long they have been open, and whether the scan still runs.",
  "provider.gitguardian": "GitGuardian",
  "stack.blurb.gitguardian": "Runs on the CLI. Reads open secret incidents, and separates the ones whose credential still works from the ones that no longer do.",
  "provider.semgrep": "Semgrep",
  "stack.blurb.semgrep": "Runs on the CLI. Reads the findings Semgrep already produced, judged by the same window as every other scanner here.",
  "provider.aikido": "Aikido",
  "stack.blurb.aikido": "Runs on the CLI. Reads open issues and their age. Its own risk score is deliberately ignored, because a composite score is a judgement we cannot show the working for.",
  "provider.sonarqube": "SonarQube",
  "stack.blurb.sonarqube": "Runs on the CLI. Reads the quality gate, which is change management written as code, plus whether the project is still being analysed.",
  "provider.bitwarden": "Bitwarden",
  "stack.blurb.bitwarden": "Runs on the CLI. Reads members, their second factor and your organisation policies. Never a vault item.",
  "provider.onepassword": "1Password",
  "stack.blurb.onepassword": "Runs on the CLI. Reads the sign in log, which says whether a second factor was actually used rather than whether one is required.",
  "provider.doppler": "Doppler",
  "stack.blurb.doppler": "Runs on the CLI. Reads the names and scope of your service tokens. Never a secret value.",
  "conn.local.title": "Run on your own machine",
  "cli.local.why": "These run on your own machine because their credentials cannot be made read-only, or because handing a compliance tool a key to your password manager is an ask most companies should refuse. The token stays with you. Only the verdicts travel, and only when you ask for that with --push.",
  "check.snyk.issues.no_critical.title": "Nothing critical is open",
  "check.snyk.issues.no_critical.pass": "No critical issue is open.",
  "check.snyk.issues.no_critical.fail": "At least one critical issue is open. This is the shortest sentence an assessor wants to hear the other answer to, and it is the one your own tool is already telling you.",
  "check.snyk.issues.no_critical.fix": "Fix it, or record it as an accepted risk so the file says somebody decided rather than nobody looked. An accepted risk with a name and a date reads far better than an open critical with neither.",
  "check.snyk.issues.within_window.title": "Serious findings are closed within thirty days",
  "check.snyk.issues.within_window.pass": "Every open critical and high issue was raised within the last thirty days.",
  "check.snyk.issues.within_window.fail": "At least one critical or high issue has been open for more than thirty days. The gap between your tool finding something and somebody fixing it is the number an assessor writes down.",
  "check.snyk.issues.within_window.fix": "Work through the list, or accept the risks formally. The window runs from when the finding was first seen, so rescanning does not reset it.",
  "check.snyk.issues.no_ancient.title": "Nothing has been open for more than ninety days",
  "check.snyk.issues.no_ancient.pass": "No open issue is older than ninety days, whatever its severity.",
  "check.snyk.issues.no_ancient.fail": "At least one issue has been open for more than ninety days. A medium is never urgent enough to reach the top of the list, and that is exactly how it stays open for two years.",
  "check.snyk.issues.no_ancient.fix": "Triage the backlog. Anything genuinely not worth fixing should be marked as such in the tool, which is a decision; leaving it open is not.",
  "check.semgrep.findings.no_critical.title": "Nothing critical is open",
  "check.semgrep.findings.no_critical.pass": "No critical finding is open.",
  "check.semgrep.findings.no_critical.fail": "At least one critical finding is open. This is the shortest sentence an assessor wants to hear the other answer to, and it is the one your own tool is already telling you.",
  "check.semgrep.findings.no_critical.fix": "Fix it, or record it as an accepted risk so the file says somebody decided rather than nobody looked. An accepted risk with a name and a date reads far better than an open critical with neither.",
  "check.semgrep.findings.within_window.title": "Serious findings are closed within thirty days",
  "check.semgrep.findings.within_window.pass": "Every open critical and high finding was raised within the last thirty days.",
  "check.semgrep.findings.within_window.fail": "At least one critical or high finding has been open for more than thirty days. The gap between your tool finding something and somebody fixing it is the number an assessor writes down.",
  "check.semgrep.findings.within_window.fix": "Work through the list, or accept the risks formally. The window runs from when the finding was first seen, so rescanning does not reset it.",
  "check.semgrep.findings.no_ancient.title": "Nothing has been open for more than ninety days",
  "check.semgrep.findings.no_ancient.pass": "No open finding is older than ninety days, whatever its severity.",
  "check.semgrep.findings.no_ancient.fail": "At least one finding has been open for more than ninety days. A medium is never urgent enough to reach the top of the list, and that is exactly how it stays open for two years.",
  "check.semgrep.findings.no_ancient.fix": "Triage the backlog. Anything genuinely not worth fixing should be marked as such in the tool, which is a decision; leaving it open is not.",
  "check.aikido.issues.no_critical.title": "Nothing critical is open",
  "check.aikido.issues.no_critical.pass": "No critical issue is open.",
  "check.aikido.issues.no_critical.fail": "At least one critical issue is open. This is the shortest sentence an assessor wants to hear the other answer to, and it is the one your own tool is already telling you.",
  "check.aikido.issues.no_critical.fix": "Fix it, or record it as an accepted risk so the file says somebody decided rather than nobody looked. An accepted risk with a name and a date reads far better than an open critical with neither.",
  "check.aikido.issues.within_window.title": "Serious findings are closed within thirty days",
  "check.aikido.issues.within_window.pass": "Every open critical and high issue was raised within the last thirty days.",
  "check.aikido.issues.within_window.fail": "At least one critical or high issue has been open for more than thirty days. The gap between your tool finding something and somebody fixing it is the number an assessor writes down.",
  "check.aikido.issues.within_window.fix": "Work through the list, or accept the risks formally. The window runs from when the finding was first seen, so rescanning does not reset it.",
  "check.aikido.issues.no_ancient.title": "Nothing has been open for more than ninety days",
  "check.aikido.issues.no_ancient.pass": "No open issue is older than ninety days, whatever its severity.",
  "check.aikido.issues.no_ancient.fail": "At least one issue has been open for more than ninety days. A medium is never urgent enough to reach the top of the list, and that is exactly how it stays open for two years.",
  "check.aikido.issues.no_ancient.fix": "Triage the backlog. Anything genuinely not worth fixing should be marked as such in the tool, which is a decision; leaving it open is not.",
  "check.snyk.projects.scanned_recently.title": "Every project has been scanned in the last fortnight",
  "check.snyk.projects.scanned_recently.pass": "Every active Snyk project has been scanned within the last fourteen days.",
  "check.snyk.projects.scanned_recently.fail": "At least one project has not been scanned for over a fortnight. Until it is, the other Snyk checks are describing the code as it was, and a project nobody scans reports no issues at all.",
  "check.snyk.projects.scanned_recently.fix": "Reconnect the project or run a scan. This check exists to stop the others quietly reporting a clean bill of health for a scanner that was switched off.",
  "check.semgrep.projects.scanned_recently.title": "Every project has been scanned in the last fortnight",
  "check.semgrep.projects.scanned_recently.pass": "Every Semgrep project has been scanned within the last fourteen days.",
  "check.semgrep.projects.scanned_recently.fail": "At least one project has not been scanned for over a fortnight. Until it is, the other Semgrep checks are describing the code as it was, and a project nobody scans reports no findings at all.",
  "check.semgrep.projects.scanned_recently.fix": "Run the scan in your pipeline rather than by hand. This check exists to stop the others quietly reporting a clean bill of health for a scanner that was switched off.",
  "check.gitguardian.secrets.none_live.title": "No committed credential still works",
  "check.gitguardian.secrets.none_live.pass": "No open secret incident involves a credential GitGuardian can confirm is still valid.",
  "check.gitguardian.secrets.none_live.fail": "At least one credential found in your code still works. Whoever has a copy of that repository can use it right now, and rotating it is more urgent than anything else on this page.",
  "check.gitguardian.secrets.none_live.fix": "Rotate the credential first and remove it from the code second. Deleting the commit does not help: it is in every clone and every fork already, which is why rotation is the fix and tidying up is the follow up.",
  "check.gitguardian.secrets.no_critical.title": "No critical secret incident is open",
  "check.gitguardian.secrets.no_critical.pass": "No critical secret incident is open.",
  "check.gitguardian.secrets.no_critical.fail": "At least one critical secret incident is open. A credential in source control is a credential shared with everyone who has ever cloned the repository.",
  "check.gitguardian.secrets.no_critical.fix": "Rotate the secret, then resolve the incident in GitGuardian so the record shows when it was handled.",
  "check.gitguardian.secrets.within_window.title": "Secret incidents are closed within thirty days",
  "check.gitguardian.secrets.within_window.pass": "Every open critical and high secret incident was raised within the last thirty days.",
  "check.gitguardian.secrets.within_window.fail": "At least one serious secret incident has been open for more than thirty days. Secrets do not get safer with age: the window since it was committed is the window somebody had to find it.",
  "check.gitguardian.secrets.within_window.fix": "Rotate and resolve. If an incident is a false positive, mark it as one in GitGuardian, which is a decision the record can show.",
  "check.gitguardian.secrets.no_ancient.title": "No secret incident has been open for more than ninety days",
  "check.gitguardian.secrets.no_ancient.pass": "No open secret incident is older than ninety days, whatever its severity.",
  "check.gitguardian.secrets.no_ancient.fail": "At least one secret incident has been open for more than ninety days. An unresolved incident is one nobody has decided about, which is different from one somebody decided was harmless.",
  "check.gitguardian.secrets.no_ancient.fix": "Work through the backlog and resolve or ignore each one in GitGuardian. Either is a decision; leaving them open is not.",
  "check.bitwarden.members.two_factor.title": "Everyone with vault access has a second factor",
  "check.bitwarden.members.two_factor.pass": "Every confirmed member of the organisation has two step login enabled.",
  "check.bitwarden.members.two_factor.fail": "At least one person with access to the company's passwords signs in with a password alone. That account is the shortest path to every credential you hold.",
  "check.bitwarden.members.two_factor.fix": "Ask them to set up two step login in their account settings, then turn on the two step login policy so it cannot happen again.",
  "check.bitwarden.policy.two_factor.title": "A second factor is required, not just used",
  "check.bitwarden.policy.two_factor.pass": "The two step login policy is enabled for the organisation.",
  "check.bitwarden.policy.two_factor.fail": "Two step login is not required. Everyone having it today is true of every company right up to the day somebody joins, and this is the setting that keeps it true.",
  "check.bitwarden.policy.two_factor.fix": "Turn on the Require two step login policy in your organisation settings. Members without it are removed from the organisation until they set it up, so tell people first. Policies need the Enterprise plan: a Teams organisation has no Policies page, so there the choice is to upgrade or to record this as an accepted risk.",
  "check.bitwarden.policy.organisation_ownership.title": "Company credentials belong to the company",
  "check.bitwarden.policy.organisation_ownership.pass": "The organisation ownership policy is enabled, so items are saved to the organisation rather than to personal vaults.",
  "check.bitwarden.policy.organisation_ownership.fail": "Members can save company credentials to their own personal vault. Anything saved there walks out of the door when they leave, and no offboarding step you write can reach it.",
  "check.bitwarden.policy.organisation_ownership.fix": "Turn on the Organisation ownership policy. Ask people to move anything already in a personal vault into a collection first, because the policy applies to new items. Policies need the Enterprise plan: a Teams organisation has no Policies page, so there the choice is to upgrade or to record this as an accepted risk.",
  "check.bitwarden.members.least_privilege.title": "Nobody sees every collection by accident",
  "check.bitwarden.members.least_privilege.pass": "No member below administrator has access to every collection.",
  "check.bitwarden.members.least_privilege.fail": "At least one ordinary member can see every collection in the organisation, which makes the collection structure something that exists on paper only.",
  "check.bitwarden.members.least_privilege.fix": "Edit the member and give them the collections they need rather than all of them. Owners and administrators are expected to see everything and are not counted here.",
  "check.bitwarden.policy.master_password.title": "Master passwords have to meet a standard",
  "check.bitwarden.policy.master_password.pass": "A master password policy is enabled for the organisation.",
  "check.bitwarden.policy.master_password.fail": "No master password policy is set, so the strength of the password protecting your entire vault is whatever each person felt like typing.",
  "check.bitwarden.policy.master_password.fix": "Turn on the Master password requirements policy and set a minimum length and complexity. A long passphrase beats a short complicated one. Policies need the Enterprise plan: a Teams organisation has no Policies page, so there the choice is to upgrade or to record this as an accepted risk.",
  "check.bitwarden.policy.vault_timeout.title": "Vaults lock themselves",
  "check.bitwarden.policy.vault_timeout.pass": "A maximum vault timeout policy is enabled for the organisation.",
  "check.bitwarden.policy.vault_timeout.fail": "No vault timeout is enforced, so a vault unlocked on a laptop in a cafe stays unlocked until somebody closes it.",
  "check.bitwarden.policy.vault_timeout.fix": "Turn on the Vault timeout policy and choose a timeout and an action. Lock is usually right; log out is stricter and more annoying. Policies need the Enterprise plan: a Teams organisation has no Policies page, so there the choice is to upgrade or to record this as an accepted risk.",
  "check.bitwarden.members.no_stale_invites.title": "Nobody is stuck halfway through joining",
  "check.bitwarden.members.no_stale_invites.pass": "Every member has finished joining the organisation.",
  "check.bitwarden.members.no_stale_invites.fail": "At least one person is invited or accepted but not confirmed. An invitation nobody completed is a live route into the organisation's passwords that belongs to no one.",
  "check.bitwarden.members.no_stale_invites.fix": "Confirm the people who should be there and remove the invitations that were a mistake or are no longer needed.",
  "check.onepassword.signins.second_factor.title": "Every sign in used a second factor",
  "check.onepassword.signins.second_factor.pass": "Every successful sign in over the last thirty days completed a second factor or single sign on.",
  "check.onepassword.signins.second_factor.fail": "At least one account signed in successfully with no second factor. A settings page can say a second factor is required; this is the log saying whether one was actually used.",
  "check.onepassword.signins.second_factor.fix": "Turn on the two factor requirement for the account, then check the people named have enrolled. This reads the sign in log rather than the setting, so it will keep failing until real sign ins change.",
  "check.onepassword.signins.no_repeated_failures.title": "No account is being guessed at",
  "check.onepassword.signins.no_repeated_failures.pass": "No account had more than ten failed sign in attempts in the last thirty days.",
  "check.onepassword.signins.no_repeated_failures.fail": "At least one account failed to sign in an unusual number of times. Mistyping a password a few times is a Monday; ten failures against one account in a month is somebody trying.",
  "check.onepassword.signins.no_repeated_failures.fix": "Check with the person named. If it was not them, rotate their credentials and review the sign in locations in 1Password, which records the country and client for every attempt.",
  "check.onepassword.audit.log_available.title": "The audit log can be produced on request",
  "check.onepassword.audit.log_available.pass": "The audit log returned events for the last thirty days, each with a timestamp.",
  "check.onepassword.audit.log_available.fail": "No audit events could be read for the last thirty days. A log nobody can produce on request is not a log, and it is the first thing an assessor asks to see.",
  "check.onepassword.audit.log_available.fix": "Check the Events API token still has the audit events feature enabled. If the account genuinely had no activity, that is worth knowing too.",
  "check.doppler.tokens.read_only.title": "No service token can write secrets",
  "check.doppler.tokens.read_only.pass": "Every service token has read access only.",
  "check.doppler.tokens.read_only.fail": "At least one service token can write as well as read. A service token exists so a running application can read its configuration; one that can also write is a deployment that can rewrite its own secrets, and it is almost always a misclick.",
  "check.doppler.tokens.read_only.fix": "Delete the token and create a new one with read access, then update wherever it is used. Access cannot be changed on an existing token.",
  "check.doppler.tokens.not_root_config.title": "No service token points at a root config",
  "check.doppler.tokens.not_root_config.pass": "No service token is scoped to a root config.",
  "check.doppler.tokens.not_root_config.fail": "At least one token reads a root config. Every branch config inherits from it, so that token reads production, staging and everything anybody adds later, which is the opposite of what scoping a token is for.",
  "check.doppler.tokens.not_root_config.fix": "Create a token against the specific config the application uses, such as prd or stg, and retire the one on the root.",
  "check.doppler.tokens.rotated.title": "No service token is more than a year old",
  "check.doppler.tokens.rotated.pass": "Every service token was created within the last year.",
  "check.doppler.tokens.rotated.fail": "At least one service token is over a year old. A credential that has never been rotated has been copied into more places than anybody now remembers.",
  "check.doppler.tokens.rotated.fix": "Create a replacement, update the places that use it, then delete the old one. Doing it in that order avoids an outage.",
  "check.sonarqube.gate.passing.title": "The quality gate is passing",
  "check.sonarqube.gate.passing.pass": "The project's quality gate is passing.",
  "check.sonarqube.gate.passing.fail": "The quality gate is failing, or no gate is attached to the project. A gate is change management written as code, and it is the evidence an assessor wants instead of a document describing your process.",
  "check.sonarqube.gate.passing.fix": "Fix the failing conditions, or attach a gate if the project has none. The finding names which conditions failed and what the limits were.",
  "check.sonarqube.gate.has_conditions.title": "The quality gate actually tests something",
  "check.sonarqube.gate.has_conditions.pass": "The project's quality gate has at least one condition.",
  "check.sonarqube.gate.has_conditions.fail": "The quality gate has no conditions, so it passes every build and proves nothing. This is the compliance equivalent of a policy document nobody reads, and it is easy to end up with by accident.",
  "check.sonarqube.gate.has_conditions.fix": "Edit the gate and add conditions. The Sonar way default is a sensible starting point and takes a minute to apply.",
  "check.sonarqube.project.analysed_recently.title": "The project has been analysed in the last fortnight",
  "check.sonarqube.project.analysed_recently.pass": "The project was last analysed within the last fourteen days.",
  "check.sonarqube.project.analysed_recently.fail": "The project has not been analysed for over a fortnight. Without this, a gate that passed in March keeps passing for ever, and a green tick on a project nobody analyses is worse than no tick at all.",
  "check.sonarqube.project.analysed_recently.fix": "Run the analysis in your pipeline rather than by hand, so it happens on every change instead of when somebody remembers.",
  "check.sonarqube.project.security_rating.title": "The security rating is an A",
  "check.sonarqube.project.security_rating.pass": "The project's security rating is A, meaning Sonar found no vulnerabilities it is confident about.",
  "check.sonarqube.project.security_rating.fail": "The security rating is below A, which means Sonar found at least one issue it classes as a vulnerability rather than a smell.",
  "check.sonarqube.project.security_rating.fix": "Open the Security Hotspots and Vulnerabilities views in Sonar and work through them. The rating is set by the worst single finding, so one fix can move it.",
  "home.role.tracker": "Issue tracking",
  "home.role.documents": "Documents",
  "provider.linear": "Linear",
  "stack.blurb.linear": "Read-only checks on issue metadata: whether security work is tracked, owned and closed inside your remediation window.",
  "conn.linear.title": "Linear",
  "conn.linear.body": "Snoopios reads issue metadata only: identifiers, states, labels and dates. Never a description, never a comment. What it answers is whether security work has an owner and gets closed, which is the question every framework asks about corrective action.",
  "conn.linear.token.label": "Linear API key",
  "conn.linear.token.hint": "Create one in Linear under Settings, Security and access, and give it the Read permission only. Snoopios never sends a mutation: its GraphQL requests are parsed and refused before they leave the machine if they are anything but a query.",
  "conn.linear.cta": "Connect read-only",
  "conn.linear.error.token": "That does not look like a Linear API key. Copy the whole value from Settings, Security and access.",
  "conn.linear.error.auth": "Linear would not accept that key. Check it has not been revoked and that it was created in the workspace you want to check.",
  "provider.jira": "Jira",
  "stack.blurb.jira": "Read-only checks on issue metadata: whether security work is tracked, owned and closed inside your remediation window.",
  "conn.jira.title": "Jira",
  "conn.jira.body": "Snoopios reads issue metadata only: keys, statuses, labels and dates. Never a description, never a comment, because that is where a ticket ends up holding somebody's personal data. Jira and Linear are judged by the same code, so the two give the same verdict about the same practice.",
  "conn.jira.cloud.label": "Cloud ID",
  "conn.jira.cloud.placeholder": "11112222-3333-4444-5555-666677778888",
  "conn.jira.cloud.hint": "Not your site name. Sign in and open https://yoursite.atlassian.net/_edge/tenant_info, which prints it.",
  "conn.jira.token.label": "Scoped API token",
  "conn.jira.token.hint": "Create it at id.atlassian.com under Security, API tokens, choosing Create API token with scopes, and grant read:jira-work only. A classic token carries every permission you have, which is a write credential, and Snoopios will not hold one.",
  "conn.jira.cta": "Connect read-only",
  "conn.jira.error.cloud": "That does not look like a Cloud ID. It is a GUID, thirty six characters with hyphens, not your site name.",
  "conn.jira.error.token": "That does not look like an API token. Copy the whole value from id.atlassian.com.",
  "conn.jira.error.auth": "Atlassian would not accept that token for that Cloud ID. Check both, and that the token was created with scopes rather than as a classic one.",
  "conn.jira.error.scope": "That token cannot read issues. It needs the read:jira-work scope, and scopes cannot be changed after a token is made, so create a new one.",
  "provider.notion": "Notion",
  "stack.blurb.notion": "Read-only checks on page metadata: whether anything is published to the web, and whether your policies have an owner and a review date.",
  "conn.notion.title": "Notion",
  "conn.notion.body": "Snoopios reads page metadata only: titles, properties, dates, and whether a page is published to the web. It never reads what a page says, because there is no code here that can: the blocks endpoint is not called from anywhere in this connector. The integration also only ever sees pages you explicitly share with it.",
  "conn.notion.token.label": "Internal integration secret",
  "conn.notion.token.hint": "Create a connection at notion.so/my-integrations with the Access token method. Set its capabilities to Read content only, untick Update content and Insert content, and set user information to without email addresses: Snoopios reads a name to say who owns a page and never needs an address. Then open each page you want checked, use its Connections menu, and add the connection, or it sees an empty workspace.",
  "conn.notion.cta": "Connect read-only",
  "conn.notion.error.token": "That does not look like a Notion integration secret. Copy the whole value from your integration's Configuration tab.",
  "conn.notion.error.auth": "Notion would not accept that secret. Check it has not been rotated, and that the integration still exists.",
  "conn.notion.error.shared": "The secret works but the integration cannot see anything. Open a page you want checked, use Connections, and add the integration. Notion shows an integration nothing until you do.",
  "provider.jamf": "Jamf Pro",
  "stack.blurb.jamf": "Read-only checks on your Mac fleet: FileVault and its recovery key, System Integrity Protection, Gatekeeper, the firewall and how far behind any machine has fallen.",
  "conn.jamf.title": "Jamf Pro",
  "conn.jamf.body": "Snoopios reads your computer inventory and nothing else. The check worth connecting for is the recovery key: every device manager reports whether a disk is encrypted, and almost nobody looks at whether the key came back, which is the difference between a lost laptop and lost data.",
  "conn.jamf.host.label": "Jamf Pro address",
  "conn.jamf.host.placeholder": "yourcompany.jamfcloud.com",
  "conn.jamf.host.hint": "Just the hostname, with no https and no trailing slash.",
  "conn.jamf.client.label": "API client ID",
  "conn.jamf.secret.label": "API client secret",
  "conn.jamf.secret.hint": "In Jamf Pro, open Settings, API roles and clients. Create a role holding only Read privileges for computers, then a client that uses it. The secret is shown once.",
  "conn.jamf.cta": "Connect read-only",
  "conn.jamf.error.host": "That does not look like a Jamf Cloud address. It ends in jamfcloud.com, with no https and no path.",
  "conn.jamf.error.auth": "Jamf would not issue a token for those credentials. Check the client ID and secret, and that the client is still enabled.",
  "conn.jamf.error.scope": "The client works but cannot read the computer inventory. Give its API role the Read Computers and Read Computer Inventory Collection privileges, then connect again.",
  "provider.kandji": "Kandji",
  "stack.blurb.kandji": "Read-only checks on your Apple fleet: whether every device is still managed, in a blueprint, running the agent and reasonably up to date.",
  "conn.kandji.title": "Kandji",
  "conn.kandji.body": "Snoopios reads your device list and nothing else. It never calls the endpoint that hands over a FileVault recovery key: a compliance tool has no business holding one. Disk encryption is not yet checked here, because Kandji reports it on a per device endpoint whose shape we will not guess at.",
  "conn.kandji.host.label": "Kandji API address",
  "conn.kandji.host.placeholder": "yourcompany.api.kandji.io",
  "conn.kandji.host.hint": "Shown in Kandji under Settings, Access, API token. European tenants have a region in the middle, such as yourcompany.api.eu.kandji.io.",
  "conn.kandji.token.label": "API token",
  "conn.kandji.token.hint": "Create it in Kandji under Settings, Access, and tick the Device list permission only. Nothing else is needed and nothing else is used.",
  "conn.kandji.cta": "Connect read-only",
  "conn.kandji.error.host": "That does not look like a Kandji API address. It ends in kandji.io, with no https and no path.",
  "conn.kandji.error.auth": "Kandji would not accept that token for that address. Check both, and that the token has not been revoked.",
  "conn.kandji.error.scope": "The token works but cannot list devices. Give it the Device list permission in Kandji, then connect again.",
  "provider.rippling": "Rippling",
  "stack.blurb.rippling": "Read-only checks on your people records: who joined, who left, and whether anyone closed their access afterwards.",
  "conn.rippling.title": "Rippling",
  "conn.rippling.body": "Rippling is one of two connections that compare payroll against your roster, and it is judged by the same code as Deel so the two give the same verdict about the same practice. Snoopios reads who works here and who has left. Never pay, never benefits, never bank details.",
  "conn.rippling.token.label": "Rippling API key",
  "conn.rippling.token.hint": "Create one in Rippling under Company settings, API access, and grant the workers read scope only. Scopes cannot be changed afterwards, so a token with more than that needs replacing rather than editing.",
  "conn.rippling.cta": "Connect read-only",
  "conn.rippling.error.token": "That does not look like a Rippling API key. Copy the whole value from Company settings, API access.",
  "conn.rippling.error.auth": "Rippling would not accept that key. Check it has not been revoked and that it belongs to the company you want to check.",
  "conn.rippling.error.scope": "That key cannot read your worker list. It needs the workers read scope, then connect again.",
  "check.linear.security.within_window.title": "Security issues are closed within thirty days",
  "check.linear.security.within_window.pass": "Every open issue labelled as security work was raised within the last thirty days.",
  "check.linear.security.within_window.fail": "At least one security issue has been open for more than thirty days. The gap between raising a security problem and fixing it is the number an assessor writes down, and most companies have never measured it.",
  "check.linear.security.within_window.fix": "Work through the overdue issues, or accept the risk formally so the record says somebody decided rather than forgot. The window runs from the day the issue was opened, so commenting on it does not reset the clock.",
  "check.linear.security.labelled.title": "Security work has somewhere to go",
  "check.linear.security.labelled.pass": "At least one label marks work as security related.",
  "check.linear.security.labelled.fail": "No label marks security work, so there is no way to answer the first question an assessor asks a tracker: show me everything security related.",
  "check.linear.security.labelled.fix": "Add a label called Security and apply it to the issues that deserve it. This is about being able to find the work later, not about house style.",
  "check.linear.issues.assigned.title": "Work in progress has an owner",
  "check.linear.issues.assigned.pass": "Every issue the team has started has somebody assigned to it.",
  "check.linear.issues.assigned.fail": "At least one started issue has nobody assigned. Work in progress that belongs to no one is how a corrective action becomes a list somebody writes up afterwards.",
  "check.linear.issues.assigned.fix": "Assign the issues, or move them back to the backlog if nobody is actually working on them. The backlog is not held to this.",
  "check.linear.issues.not_stale.title": "Started work is actually moving",
  "check.linear.issues.not_stale.pass": "Every issue the team has started has been touched within the last forty five days.",
  "check.linear.issues.not_stale.fail": "At least one started issue has not been touched for over forty five days. It is neither done nor abandoned, which makes the board a poor description of what is happening.",
  "check.linear.issues.not_stale.fix": "Close it, park it back in the backlog, or pick it up again. An in progress column that has not moved in two months tells a reader nothing.",
  "check.jira.security.within_window.title": "Security issues are closed within thirty days",
  "check.jira.security.within_window.pass": "Every open issue labelled as security work was raised within the last thirty days.",
  "check.jira.security.within_window.fail": "At least one security issue has been open for more than thirty days. The gap between raising a security problem and fixing it is the number an assessor writes down, and most companies have never measured it.",
  "check.jira.security.within_window.fix": "Work through the overdue issues, or accept the risk formally so the record says somebody decided rather than forgot. The window runs from the day the issue was created, so commenting on it does not reset the clock.",
  "check.jira.security.labelled.title": "Security work has somewhere to go",
  "check.jira.security.labelled.pass": "At least one label marks work as security related.",
  "check.jira.security.labelled.fail": "No label marks security work, so there is no way to answer the first question an assessor asks a tracker: show me everything security related.",
  "check.jira.security.labelled.fix": "Add a label called security and apply it to the issues that deserve it. This is about being able to find the work later, not about house style.",
  "check.jira.issues.assigned.title": "Work in progress has an owner",
  "check.jira.issues.assigned.pass": "Every issue in an In Progress status has somebody assigned to it.",
  "check.jira.issues.assigned.fail": "At least one issue the team has started has nobody assigned. Work in progress that belongs to no one is how a corrective action becomes a list somebody writes up afterwards.",
  "check.jira.issues.assigned.fix": "Assign the issues, or move them back to To Do if nobody is actually working on them. Only statuses in the In Progress category are judged here.",
  "check.jira.issues.not_stale.title": "Started work is actually moving",
  "check.jira.issues.not_stale.pass": "Every issue in an In Progress status has been updated within the last forty five days.",
  "check.jira.issues.not_stale.fail": "At least one started issue has not been updated for over forty five days. It is neither done nor abandoned, which makes the board a poor description of what is happening.",
  "check.jira.issues.not_stale.fix": "Close it, move it back to To Do, or pick it up again. An In Progress column that has not moved in two months tells a reader nothing.",
  "check.notion.pages.not_public.title": "No page is published to the web",
  "check.notion.pages.not_public.pass": "No page in the workspace is shared publicly on the internet.",
  "check.notion.pages.not_public.fail": "At least one page is published to the web, so anybody with the link can read it without signing in. This is invisible from inside Notion: the page looks the same to the person who published it.",
  "check.notion.pages.not_public.fix": "Open each page listed, go to Share, and turn off Share to web. If a page is meant to be public, move it to a workspace that holds nothing else, because the risk is what sits beside it tomorrow.",
  "check.notion.documents.reviewed.title": "Policies in Notion have been reviewed this year",
  "check.notion.documents.reviewed.pass": "Every page whose title marks it as a policy or procedure has been edited within the last twelve months.",
  "check.notion.documents.reviewed.fail": "At least one policy or procedure has not been touched for over a year. A policy nobody has read in that time is a document an assessor will ask pointed questions about.",
  "check.notion.documents.reviewed.fix": "Review each one and edit it, even if only to confirm it is still right. A dated review note in the page is what turns an old document into a current one.",
  "check.notion.documents.owned.title": "Policies in Notion name an owner",
  "check.notion.documents.owned.pass": "Every page whose title marks it as a policy or procedure names a person in one of its properties.",
  "check.notion.documents.owned.fail": "At least one policy or procedure names nobody. A document with no owner is one nobody is accountable for reviewing, and that is what the review period depends on.",
  "check.notion.documents.owned.fix": "Add a person property to the page or the database it sits in, and put a name in it. Snoopios reads any property of type Person, so it does not matter what you call it.",
  "check.jamf.devices.encrypted.title": "Every Mac encrypts its disk",
  "check.jamf.devices.encrypted.pass": "Every Mac in Jamf reports its boot disk as encrypted with FileVault.",
  "check.jamf.devices.encrypted.fail": "At least one Mac reports an unencrypted boot disk, so a laptop left in a taxi is a data breach rather than a lost asset. A disk part way through encrypting is not yet encrypted and is counted here.",
  "check.jamf.devices.encrypted.fix": "Assign a FileVault configuration profile to the Macs listed and check they complete. Encryption starts at the next login, so a machine can sit in the encrypting state for a while before it finishes.",
  "check.jamf.devices.key_escrowed.title": "Every encrypted Mac has its recovery key escrowed",
  "check.jamf.devices.key_escrowed.pass": "Every encrypted Mac has a valid recovery key held in Jamf, either its own or an institutional one.",
  "check.jamf.devices.key_escrowed.fail": "At least one encrypted Mac has no valid recovery key in Jamf. FileVault with no way back to the key is not security, it is a way to lose the contents of a laptop the first time somebody forgets a password or leaves without warning.",
  "check.jamf.devices.key_escrowed.fix": "Reissue the recovery key from the FileVault profile. Every device manager reports encryption and almost nobody looks at the escrow, which is why this is worth fixing before anything else on this page.",
  "check.jamf.devices.sip.title": "System Integrity Protection is on",
  "check.jamf.devices.sip.pass": "Every Mac reports System Integrity Protection as enabled.",
  "check.jamf.devices.sip.fail": "At least one Mac has System Integrity Protection turned off. That is the Mac equivalent of a rooted phone: the machine can no longer be trusted to report its own state honestly, so no other check on it means anything.",
  "check.jamf.devices.sip.fix": "Boot the Mac into recovery and run csrutil enable, then restart. If it was turned off for a piece of software, that software needs replacing rather than the protection staying off.",
  "check.jamf.devices.gatekeeper.title": "Gatekeeper checks what is being opened",
  "check.jamf.devices.gatekeeper.pass": "Every Mac has Gatekeeper checking signatures before an application runs.",
  "check.jamf.devices.gatekeeper.fail": "At least one Mac has Gatekeeper off or has never reported its state, so an application from anywhere can run without its signature being checked.",
  "check.jamf.devices.gatekeeper.fix": "Turn Gatekeeper back on with a configuration profile rather than by hand, so it stays on. A Mac reporting nothing has usually not run an inventory recently.",
  "check.jamf.devices.firewall.title": "The firewall is on",
  "check.jamf.devices.firewall.pass": "Every Mac reports its firewall as enabled.",
  "check.jamf.devices.firewall.fail": "At least one Mac has its firewall off, so anything listening on that machine is reachable from whatever network it joins next.",
  "check.jamf.devices.firewall.fix": "Enable the firewall through a configuration profile so it applies to every Mac rather than the ones somebody remembered.",
  "check.jamf.devices.secure_boot.title": "Secure boot is at full security",
  "check.jamf.devices.secure_boot.pass": "Every Mac that supports secure boot has it set to full security.",
  "check.jamf.devices.secure_boot.fail": "At least one Mac that supports secure boot has it turned down, which allows an operating system Apple has not signed to start on it.",
  "check.jamf.devices.secure_boot.fix": "Set the security policy back to Full Security in recovery. Macs with no secure boot hardware are not counted here, because they cannot have it.",
  "check.jamf.devices.os_consistent.title": "No Mac is far behind the rest of the fleet",
  "check.jamf.devices.os_consistent.pass": "No Mac is more than two major macOS versions behind the newest one you run.",
  "check.jamf.devices.os_consistent.fail": "At least one Mac is more than two major versions behind the newest Mac in your fleet, so it is almost certainly missing security updates the others have.",
  "check.jamf.devices.os_consistent.fix": "Upgrade the machines listed, or retire them. This is measured against your own newest Mac rather than against a version number written into Snoopios, which would be out of date within a year.",
  "check.jamf.devices.recent_contact.title": "Every Mac has reported recently",
  "check.jamf.devices.recent_contact.pass": "Every Mac has contacted Jamf within the last thirty days.",
  "check.jamf.devices.recent_contact.fail": "At least one Mac has not contacted Jamf for over thirty days, so its last known state is frozen and may be wrong.",
  "check.jamf.devices.recent_contact.fix": "Find the machine and get it back online, or remove it from Jamf. A Mac that stopped reporting is the one an attacker would most like you to keep counting as healthy.",
  "check.kandji.devices.mdm_enabled.title": "Every device is still under management",
  "check.kandji.devices.mdm_enabled.pass": "Every device in Kandji still has its management profile installed.",
  "check.kandji.devices.mdm_enabled.fail": "At least one device has lost its management profile. It still appears in the list and enforces nothing, which is the worst of both: a row in your inventory that answers for a machine nobody controls.",
  "check.kandji.devices.mdm_enabled.fix": "Re enrol the device. A management profile does not usually disappear by accident, so it is worth asking how it went.",
  "check.kandji.devices.blueprint.title": "Every device is in a blueprint",
  "check.kandji.devices.blueprint.pass": "Every device is assigned to a blueprint.",
  "check.kandji.devices.blueprint.fail": "At least one device is in no blueprint. A blueprint is where every setting Kandji enforces actually lives, so a device outside one is configured by nobody and will look healthy because there is nothing for it to fail.",
  "check.kandji.devices.blueprint.fix": "Assign the device to a blueprint. This is the most common Kandji gap, because the device looks perfectly normal in the list.",
  "check.kandji.devices.not_missing.title": "No device is marked as missing",
  "check.kandji.devices.not_missing.pass": "No device in the fleet is flagged as missing.",
  "check.kandji.devices.not_missing.fail": "At least one device is flagged as missing and is still in the fleet. That is either a lost machine nobody has wiped or a flag nobody has cleared, and both need a decision.",
  "check.kandji.devices.not_missing.fix": "Wipe the device remotely if it is genuinely gone, or clear the flag if it came back. Leaving it flagged means the next reader cannot tell which.",
  "check.kandji.devices.agent_installed.title": "Every Mac runs the Kandji agent",
  "check.kandji.devices.agent_installed.pass": "Every Mac in the fleet has the Kandji agent installed.",
  "check.kandji.devices.agent_installed.fail": "At least one Mac has no agent, so Kandji can enrol it but cannot enforce or report most of what it should.",
  "check.kandji.devices.agent_installed.fix": "Reinstall the agent on the Macs listed. Only Macs are counted here: iPhones and iPads do not run one.",
  "check.kandji.devices.os_consistent.title": "No device is far behind the rest of its kind",
  "check.kandji.devices.os_consistent.pass": "No device is more than two major versions behind the newest one you run on the same platform.",
  "check.kandji.devices.os_consistent.fail": "At least one device is more than two major versions behind the newest device of its kind, so it is almost certainly missing security updates the others have.",
  "check.kandji.devices.os_consistent.fix": "Update the devices listed, or retire them. Macs are compared with Macs and iPhones with iPhones, because the two are not on the same version line.",
  "check.kandji.devices.recent_contact.title": "Every device has checked in recently",
  "check.kandji.devices.recent_contact.pass": "Every device has checked in with Kandji within the last thirty days.",
  "check.kandji.devices.recent_contact.fail": "At least one device has not checked in for over thirty days, so its last known state is frozen and may be wrong.",
  "check.kandji.devices.recent_contact.fix": "Find the device and get it back online, or remove it from Kandji. A device that stopped reporting is the one an attacker would most like you to keep counting as healthy.",
  "check.rippling.leavers.access_removed.title": "Everyone payroll says has left has had their access confirmed closed",
  "check.rippling.leavers.access_removed.pass": "Every person Rippling records as having left is on the roster as a leaver, with every system recorded and confirmed.",
  "check.rippling.leavers.access_removed.fail": "At least one person Rippling says has left still has no confirmation that their access was closed. This is the finding assessors look for first, because a former colleague with a working login is the most common way a small company loses control of its data.",
  "check.rippling.leavers.access_removed.fix": "Open the roster, mark the person as a leaver if they are not already, list the systems they had access to, and confirm each one as you remove it. Rippling knows the date they left; the roster is what shows somebody acted on it.",
  "check.rippling.leavers.closed_promptly.title": "Access is closed within a week of somebody leaving",
  "check.rippling.leavers.closed_promptly.pass": "Every departure recorded in Rippling more than a week ago has its access removal confirmed.",
  "check.rippling.leavers.closed_promptly.fail": "At least one person left over a week ago and their access removal is still unfinished. The gap between the leaving date and the day access was closed is the number an assessor writes down.",
  "check.rippling.leavers.closed_promptly.fix": "Finish the outstanding offboarding rows. If a system genuinely takes longer to close, record the date it was actually done rather than leaving the row open, because an honest late date reads far better than a blank one.",
  "check.rippling.leavers.recorded.title": "Payroll and the roster agree on who has left",
  "check.rippling.leavers.recorded.pass": "Everyone Rippling records as having left is marked as a leaver on the roster.",
  "check.rippling.leavers.recorded.fail": "At least one person has left according to Rippling but is still shown as working here on the roster. Every control that counts your people is now counting somebody who is gone.",
  "check.rippling.leavers.recorded.fix": "Mark them as a leaver on the roster with the date Rippling holds. This is the point of connecting payroll: the roster stops being a list somebody remembers to update.",
  "check.rippling.people.on_roster.title": "Everyone on payroll is on the roster",
  "check.rippling.people.on_roster.pass": "Everyone Rippling records as currently working here appears on the roster.",
  "check.rippling.people.on_roster.fail": "At least one person is on payroll but not on the roster, so they are missing from your training rounds, your policy acceptances and your access reviews.",
  "check.rippling.people.on_roster.fix": "Add them to the roster. Snoopios matches on name and tries the preferred name as well as the legal one, so Samuel will find a roster entry that says Sam.",
  "check.rippling.people.start_dates.title": "Every current person has a joining date",
  "check.rippling.people.start_dates.pass": "Everyone currently working here has a start date recorded in Rippling.",
  "check.rippling.people.start_dates.fail": "At least one current person has no start date recorded, so there is no way to show that their checks and their induction happened when they joined.",
  "check.rippling.people.start_dates.fix": "Add the start date in Rippling. It is the date every onboarding control is measured from, and a blank one turns a simple question into an argument.",
  "provider.deel": "Deel",
  "stack.blurb.deel": "Read-only checks on your people records: who joined, who left, and whether anyone closed their access afterwards.",
  "home.role.people": "People",
  "conn.deel.title": "Deel",
  "conn.deel.body": "Deel is the only connection that compares two things: your payroll and your roster. It reads who works here and who has left, then checks that somebody actually closed the access of everyone who has gone. Snoopios never sees pay, contracts or bank details.",
  "conn.deel.token.label": "Deel API token",
  "conn.deel.token.hint": "Create one in Deel under Settings \u2192 Developer \u2192 Tokens. Grant one scope, people:read, and nothing else. Choose Organization-level access, not the Group-level the form offers first, because a group token returns only part of your roster and the checks would then report on an incomplete list. On the Sensitive data step turn ON \u201CHide Sensitive Employment Information\u201D, which is off by default: that is what keeps salary out of reach, and without it the token can read compensation. Deel does not tell us which scopes a token carries, so this connection is shown as read-only requested rather than proved; every request Snoopios makes is a read, refused before it leaves the machine if it is not.",
  "conn.deel.cta": "Connect read-only",
  "conn.deel.error.token": "That does not look like a Deel token. Copy the whole value from the Developer Center.",
  "conn.deel.error.auth": "Deel would not accept that token. Check it has not expired and that it was created in the organisation you want to check.",
  "conn.deel.error.scope": "That token cannot read your people list. Add the people read scope to it in Deel, or create a new token with it, then connect again.",
  "check.deel.leavers.access_removed.title": "Everyone payroll says has left has had their access confirmed closed",
  "check.deel.leavers.access_removed.pass": "Every person Deel records as having left is on the roster as a leaver, with every system recorded and confirmed.",
  "check.deel.leavers.access_removed.fail": "At least one person Deel says has left still has no confirmation that their access was closed. This is the finding assessors look for first, because a former colleague with a working login is the most common way a small company loses control of its data.",
  "check.deel.leavers.access_removed.fix": "Open the roster, mark the person as a leaver if they are not already, list the systems they had access to, and confirm each one as you remove it. Deel knows the date they left; the roster is what shows somebody acted on it.",
  "check.deel.leavers.closed_promptly.title": "Access is closed within a week of somebody leaving",
  "check.deel.leavers.closed_promptly.pass": "Every departure recorded in Deel more than a week ago has its access removal confirmed.",
  "check.deel.leavers.closed_promptly.fail": "At least one person left over a week ago and their access removal is still unfinished. The gap between the leaving date and the day access was closed is the number an assessor writes down.",
  "check.deel.leavers.closed_promptly.fix": "Finish the outstanding offboarding rows. If a system genuinely takes longer to close, record the date it was actually done rather than leaving the row open, because an honest late date reads far better than a blank one.",
  "check.deel.leavers.recorded.title": "Payroll and the roster agree on who has left",
  "check.deel.leavers.recorded.pass": "Everyone Deel records as having left is marked as a leaver on the roster.",
  "check.deel.leavers.recorded.fail": "At least one person has left according to Deel but is still shown as working here on the roster. Every control that counts your people is now counting somebody who is gone.",
  "check.deel.leavers.recorded.fix": "Mark them as a leaver on the roster with the date Deel holds. This is the point of connecting payroll: the roster stops being a list somebody remembers to update.",
  "check.deel.people.on_roster.title": "Everyone on payroll is on the roster",
  "check.deel.people.on_roster.pass": "Everyone Deel records as currently working here appears on the roster.",
  "check.deel.people.on_roster.fail": "At least one person is on payroll but not on the roster, so they are missing from your training rounds, your policy acceptances and your access reviews.",
  "check.deel.people.on_roster.fix": "Add them to the roster. Anybody paid to work here is somebody an assessor expects to see accepting policies and appearing in access reviews.",
  "check.deel.people.start_dates.title": "Every current person has a joining date",
  "check.deel.people.start_dates.pass": "Everyone currently working here has a start date recorded in Deel.",
  "check.deel.people.start_dates.fail": "At least one current person has no start date recorded, so there is no way to show that their checks and their induction happened when they joined.",
  "check.deel.people.start_dates.fix": "Add the start date in Deel. It is the date every onboarding control is measured from, and a blank one turns a simple question into an argument.",
  "provider.intune": "Microsoft Intune",
  "stack.blurb.intune": "Read-only checks on the laptops and phones you manage: encryption, screen lock, patch level and compliance.",
  "home.role.devices": "Devices",
  "conn.intune.title": "Microsoft Intune",
  "conn.intune.body": "Intune uses the same Microsoft tenant as Microsoft 365, with two further read-only permissions for device management. Your administrator grants them once, and Snoopios reads back what was actually granted on every run.",
  "conn.intune.tenant.label": "Directory (tenant) ID",
  "conn.intune.tenant.hint": "The same tenant ID as your Microsoft 365 connection. Find it in Entra ID under Overview.",
  "conn.intune.enrolment.title": "If Snoopios says you have no devices",
  "conn.intune.enrolment.body": "Adding a work account under Settings, Accounts, Access work or school REGISTERS a Windows machine without enrolling it, and a registered device never appears in Intune. Automatic enrolment is the thing that turns one into the other, and Microsoft only offers it to tenants with Entra ID Premium. Without it, enrol each machine directly: on the device, press Windows+R and run ms-device-enrollment:?mode=mdm then sign in with the work account. The device appears in Intune within a few minutes. This is the single most common reason a fleet looks unmanaged when it is not.",
  "conn.intune.cta": "Connect read-only",
  "conn.intune.error.tenant": "That does not look like a tenant ID. It is a GUID, thirty-six characters with hyphens.",
  "conn.intune.error.auth": "Microsoft would not issue a token for that tenant. Check the ID, and that the Snoopios application is still consented in your directory.",
  "conn.intune.error.not_licensed": 'The permissions are granted, but that tenant has no Intune. Microsoft answers every device request with "Request not applicable to target tenant", which means no device management licence is assigned. Add Intune licences to the tenant, or connect a different tenant. Nothing has been saved.',
  "conn.intune.error.consent": "The token works but does not carry the device management permissions. Ask your administrator to grant DeviceManagementManagedDevices.Read.All and DeviceManagementConfiguration.Read.All, then connect again.",
  "check.intune.devices.encrypted.title": "Every managed device encrypts its disk",
  "check.intune.devices.encrypted.pass": "Every device Intune manages reports an encrypted disk.",
  "check.intune.devices.encrypted.fail": "At least one managed device reports an unencrypted disk, so a laptop left in a taxi is a data breach rather than a lost asset.",
  "check.intune.devices.encrypted.fix": "Assign a compliance policy that requires storage encryption, then check the devices that failed. On Windows this is BitLocker and on macOS it is FileVault, and both need the recovery key escrowed to Intune or you will be locked out of your own machine.",
  "check.intune.devices.compliant.title": "Every managed device meets your own policy",
  "check.intune.devices.compliant.pass": "Every device reports as compliant against the policies assigned to it.",
  "check.intune.devices.compliant.fail": "At least one device is not compliant. A device Intune has never evaluated reports its state as unknown, and that is counted here rather than assumed to be fine.",
  "check.intune.devices.compliant.fix": "Open Devices, filter by compliance, and work through the list. A device stuck at unknown has usually stopped checking in, which is a different problem from failing a rule.",
  "check.intune.devices.recent_sync.title": "Every device has reported recently",
  "check.intune.devices.recent_sync.pass": "Every managed device has checked in within the last thirty days.",
  "check.intune.devices.recent_sync.fail": "At least one device has not checked in for over thirty days, so its last known state is frozen and may be wrong.",
  "check.intune.devices.recent_sync.fix": "Find the device and get it back online, or retire it in Intune. A device that stopped reporting is the one an attacker would most like you to keep counting as compliant.",
  "check.intune.devices.not_jailbroken.title": "No device is jailbroken or rooted",
  "check.intune.devices.not_jailbroken.pass": "No managed device reports as jailbroken or rooted.",
  "check.intune.devices.not_jailbroken.fail": "At least one device reports as jailbroken or rooted, which removes the protections every other control on this page assumes.",
  "check.intune.devices.not_jailbroken.fix": "Retire the device from Intune and wipe it. A rooted device cannot be trusted to report its own state honestly, so no other check on it means anything.",
  "check.intune.devices.all_managed.title": "Every company device is actually managed",
  "check.intune.devices.all_managed.pass": "Every machine joined to your directory is under management.",
  "check.intune.devices.all_managed.fail": "A machine is joined to your directory and nothing manages it.",
  "check.intune.devices.all_managed.fix": "A joined device that nothing manages has your sign-in and none of your controls: no encryption requirement, no screen lock, no patch floor, and no way to wipe it. Enrol it, or remove its join if it should not have one. If the list looks wrong, note that adding a work account under Settings, Accounts, Access work or school registers a machine without enrolling it, and automatic enrolment needs Entra ID Premium. This check also counts personal devices carrying a work account, and does not fail them, because that is a legitimate arrangement.",
  "check.intune.devices.ownership_known.title": "Every device records who owns it",
  "check.intune.devices.ownership_known.pass": "Every managed device is recorded as company owned or personal.",
  "check.intune.devices.ownership_known.fail": "At least one device has no ownership recorded, so your asset inventory has a row it cannot describe.",
  "check.intune.devices.ownership_known.fix": "Set the ownership on the device in Intune. This is not a judgement on personal devices, which are a legitimate choice; it is that an unrecorded one cannot be described to an assessor.",
  "check.intune.policy.assigned.title": "A compliance policy is actually assigned to somebody",
  "check.intune.policy.assigned.pass": "At least one compliance policy is assigned to a group.",
  "check.intune.policy.assigned.fail": "No compliance policy is assigned. A policy that exists but reaches nobody protects nothing, and every device will report as compliant because there is nothing to fail.",
  "check.intune.policy.assigned.fix": "Assign your compliance policies to a group that contains your users or devices. This is the most common Intune mistake, because the policy looks finished in the list.",
  "check.intune.policy.screen_lock.title": "Every assigned policy requires a screen lock",
  "check.intune.policy.screen_lock.pass": "Every assigned compliance policy requires a password or passcode.",
  "check.intune.policy.screen_lock.fail": "At least one assigned policy does not require a screen lock, so a device left open on a train is open to whoever picks it up.",
  "check.intune.policy.screen_lock.fix": "Edit the policy and require a password or passcode. Windows and macOS call the setting a password and iOS calls it a passcode; both are read here.",
  "check.intune.policy.encryption.title": "A policy requires the disk to be encrypted",
  "check.intune.policy.encryption.pass": "At least one assigned compliance policy requires storage encryption.",
  "check.intune.policy.encryption.fail": "No assigned policy requires storage encryption, so a device that turns it off will still report as compliant.",
  "check.intune.policy.encryption.fix": "Edit the compliance policy and require storage encryption. Checking the devices is not enough on its own: without the rule, a device that stops encrypting is never marked non-compliant.",
  "check.intune.policy.os_minimum.title": "Every assigned policy sets a minimum operating system",
  "check.intune.policy.os_minimum.pass": "Every assigned compliance policy sets a minimum operating system version.",
  "check.intune.policy.os_minimum.fail": "At least one assigned policy sets no minimum version, so a machine three years behind on patches can still report itself compliant.",
  "check.intune.policy.os_minimum.fix": "Set a minimum operating system version on the policy and raise it when a vendor stops supporting a release. This is what turns patching from a hope into a rule.",
  "stack.cli.title": "Not listed here?",
  "stack.cli.body": "Thirteen more are checked by the command line rather than by a connection: Netlify, Neon, Render, Heroku, Clerk, Upstash, Better Stack, Railway, CircleCI, Checkly, Turso, WorkOS and your local repository. Run them on your own machine or in CI, and push the results in with an ingest key.",
  "home.frameworks.where": "Every guide is listed in the footer of this page, grouped by what it covers, and the full index explains each one in plain English.",
  "home.pack.d11": "Statement of Applicability: all 93 ISO Annex A controls, read from live evidence rather than typed",
  "home.pack.d12": "Internal audit and management review records, ISO clauses 9.2 and 9.3",
  "home.pack.d13": "SOC 2 system description: Section III, the part your auditor asks for first",
  "home.people.title": "The half most tools ask you to type in",
  "home.people.body": "Every framework asks two questions a server cannot answer: who has access, and did the people who work here actually do what your policies say. Snoopios keeps the register for both, so an assessor can sample it rather than take your word. Where a system does know the answer, it is read rather than retyped.",
  "home.people.p1.title": "Who works here, and who left",
  "home.people.p1.body": "For every leaver, the day access to each system was actually closed and who closed it. A confirmed line is superseded, never rewritten. Connect your payroll and the register is checked against it, so somebody who left three weeks ago with their access still open becomes a finding rather than an oversight.",
  "home.people.p2.title": "Access reviews",
  "home.people.p2.body": "Every person against every system, keep or remove, with a decision required on each before the review can be signed off. Frozen once complete.",
  "home.people.p3.title": "Training and policy acceptance",
  "home.people.p3.body": "Per person and per policy version, confirmed by them through their own link or recorded by an admin. The register says which, because an assessor treats those two differently.",
  "home.people.p4.title": "A seat for your auditor",
  "home.people.p4.body": "Read-only by construction, not by hidden buttons: the database refuses their writes. Give your assessor one instead of sharing your password.",
  "footer.blurb": "Continuous compliance for small software teams. Read-only checks on the stack you already run, and the evidence behind every answer.",
  "footer.youtube": "Snoopios on YouTube",
  "footer.facebook": "Snoopios on Facebook",
  "footer.instagram": "Snoopios on Instagram",
  "footer.linkedin": "Snoopios on LinkedIn",
  "footer.nav.product": "Snoopios",
  "footer.nav.integrations": "All integrations",
  "footer.nav.research": "Research",
  "footer.nav.blog": "Notes",
  "footer.nav.allframeworks": "All frameworks",
  "footer.nav.pricing": "Pricing",
  "footer.nav.faq": "Questions",
  "footer.nav.start": "Start free",
  "pack.doc.systemdesc.title": "SOC 2 system description",
  "pack.doc.systemdesc.body": "Section III of a SOC 2 report, the part the company writes rather than the auditor, and the first thing a firm asks for. Drafted from your live configuration: the connected providers become the infrastructure and the subservice organisations, the pack becomes the procedures, and every criterion with a running check is listed against what it collects. The parts only you can write are left blank and marked as the ones that decide whether the report says anything: what you promise customers, what changed this period, and what you expect customers to do at their end.",
  "conn.gcp.title": "Google Cloud",
  "conn.gcp.body": "Create a service account in the project, give it the Viewer and Security Reviewer roles, and paste its JSON key below. Before the key is saved, Snoopios asks Google whether it holds any permission that could change anything, and refuses it if the answer is yes. That question is asked again on every run, so a role added later stops the connection rather than going unnoticed.",
  "conn.gcp.field": "Service account key file",
  "conn.gcp.hint": "The whole JSON file, pasted. Snoopios keeps the private key encrypted with a key that is not in the database, and uses it only to mint a read-only token for each run.",
  "conn.gcp.cta": "Connect Google Cloud",
  "conn.gcp.error.key": "That is not a service account key file. Look for a JSON file whose type is service_account and whose client_email ends in iam.gserviceaccount.com. An OAuth client secret is a different file and will not work here.",
  "conn.gcp.error.auth": "Google would not accept that key. It may have been deleted or the service account disabled.",
  "conn.gcp.error.roles": "The key works, but the service account cannot read the project. Grant it Viewer and Security Reviewer, then try again.",
  "conn.gcp.error.write": "That service account can write. Snoopios asked Google which permissions it holds and Google named at least one that changes things, so the key has not been saved. Give it Viewer and Security Reviewer only, remove Editor or Owner if either is attached, and try again.",
  "conn.gcp.error.api": "The Cloud Resource Manager API is not enabled on that project. Enable it, then connect again.",
  "provider.gcp": "Google Cloud",
  "stack.blurb.gcp": "Read-only checks across IAM, Compute, Cloud Storage, Cloud SQL, KMS and Logging.",
  "check.gcp.iam.no_public_members.title": "Nothing in the project is granted to the whole internet",
  "check.gcp.iam.no_public_members.pass": "No role is granted to allUsers or allAuthenticatedUsers.",
  "check.gcp.iam.no_public_members.fail": "A role is granted to allUsers or allAuthenticatedUsers, which means anyone with a Google account, or none at all, holds it.",
  "check.gcp.iam.no_public_members.fix": "Open IAM on the project, find the binding whose member is allUsers or allAuthenticatedUsers, and remove it. This is the most serious finding Google Cloud can produce.",
  "check.gcp.iam.owners_limited.title": "Owner is held by a small number of named people",
  "check.gcp.iam.owners_limited.pass": "Between one and three human accounts hold the Owner role.",
  "check.gcp.iam.owners_limited.fail": "Either nobody holds Owner, or more than three people do. Both are findings: none means nobody can recover the project, and many means one compromised account takes the whole project with it.",
  "check.gcp.iam.owners_limited.fix": "Grant Owner to one or two named people. Everyone else gets a role that fits what they actually do, and service accounts get none.",
  "check.gcp.iam.no_sa_owners.title": "No service account holds Owner or Editor",
  "check.gcp.iam.no_sa_owners.pass": "No service account carries a primitive role.",
  "check.gcp.iam.no_sa_owners.fail": "A service account holds Owner or Editor. Those roles are broad, and a leaked key for that account is a leak of the whole project.",
  "check.gcp.iam.no_sa_owners.fix": "Replace the primitive role with the narrowest predefined role that lets the workload do its job. Google's own recommender will suggest one from observed usage. If the account named ends in compute@developer.gserviceaccount.com, that is the default Compute Engine service account and Google gave it Editor the moment you switched Compute on. Nothing is using it in most projects, so remove the binding. If something is, give that workload its own service account first.",
  "check.gcp.iam.audit_logs.title": "Data access is logged, not just administrative activity",
  "check.gcp.iam.audit_logs.pass": "Data Access audit logs are enabled for all services.",
  "check.gcp.iam.audit_logs.fail": "Data Access logging is off. Administrative activity is always recorded, but reads and writes of customer data are not, so nobody can answer who looked at what.",
  "check.gcp.iam.audit_logs.fix": "In IAM, open Audit Logs, select All services, and tick Data Read and Data Write. Expect a bill for the log volume, and set a retention that matches your evidence period.",
  "check.gcp.iam.sa_keys_absent.title": "No service account carries a downloadable key",
  "check.gcp.iam.sa_keys_absent.pass": "No enabled service account has a user-managed key.",
  "check.gcp.iam.sa_keys_absent.fail": "At least one service account has a user-managed key. That is a long-lived credential which can be copied, emailed or committed, and it does not rotate.",
  "check.gcp.iam.sa_keys_absent.fix": "Delete the key and move the workload to Workload Identity Federation or an attached service account. Where a key is unavoidable, rotate it on a schedule and record where it lives. One account in the list will usually be the one you made for Snoopios: we connect with a service account key, so this check reports us too, and that is the honest answer rather than an exemption we granted ourselves.",
  "check.gcp.compute.ssh_restricted.title": "SSH is not open to the whole internet",
  "check.gcp.compute.ssh_restricted.pass": "No enabled firewall rule allows port 22 from the whole internet.",
  "check.gcp.compute.ssh_restricted.fail": "A firewall rule allows SSH from anywhere. Every scanner on the internet finds this within hours.",
  "check.gcp.compute.ssh_restricted.fix": "Narrow the source range to your own addresses, or remove the rule and use Identity-Aware Proxy, which needs no open port at all.",
  "check.gcp.compute.rdp_restricted.title": "Remote desktop is not open to the whole internet",
  "check.gcp.compute.rdp_restricted.pass": "No enabled firewall rule allows port 3389 from the whole internet.",
  "check.gcp.compute.rdp_restricted.fail": "A firewall rule allows remote desktop from anywhere.",
  "check.gcp.compute.rdp_restricted.fix": "Narrow the source range, or remove the rule and reach the machine through Identity-Aware Proxy instead.",
  "check.gcp.compute.oslogin.title": "SSH access is tied to a Google identity",
  "check.gcp.compute.oslogin.pass": "OS Login is enabled across the project.",
  "check.gcp.compute.oslogin.fail": "OS Login is off, so SSH access lives in per-instance authorised-keys files rather than in IAM.",
  "check.gcp.compute.oslogin.fix": "Set enable-oslogin to TRUE in the project metadata. It matters most at offboarding: without it, removing somebody's Google account leaves their SSH key working.",
  "check.gcp.compute.serial_port_off.title": "The interactive serial console is disabled",
  "check.gcp.compute.serial_port_off.pass": "Serial port access is not enabled across the project.",
  "check.gcp.compute.serial_port_off.fail": "Serial port access is enabled across the project, which is a console reachable without passing the firewall.",
  "check.gcp.compute.serial_port_off.fix": "Remove serial-port-enable from the project metadata, or set it to FALSE, and enable it on one instance only while debugging.",
  "check.gcp.storage.no_public_buckets.title": "No storage bucket is readable by the public",
  "check.gcp.storage.no_public_buckets.pass": "No bucket grants access to allUsers or allAuthenticatedUsers.",
  "check.gcp.storage.no_public_buckets.fail": "At least one bucket is granted to allUsers or allAuthenticatedUsers, so its contents can be read without credentials.",
  "check.gcp.storage.no_public_buckets.fix": "Remove the public member from the bucket's policy. If the bucket genuinely serves a public website, record it in accepted risks rather than leaving it looking like a mistake.",
  "check.gcp.storage.uniform_access.title": "Buckets use uniform access, not per-object permissions",
  "check.gcp.storage.uniform_access.pass": "Every bucket has uniform bucket-level access enabled.",
  "check.gcp.storage.uniform_access.fail": "At least one bucket still allows per-object permissions, so who can read a file has two answers and only one of them appears in IAM.",
  "check.gcp.storage.uniform_access.fix": "Enable uniform bucket-level access on the bucket. Check first that nothing depends on a per-object permission, because the switch is one-way for ninety days.",
  "check.gcp.storage.versioning.title": "Buckets keep previous versions of an object",
  "check.gcp.storage.versioning.pass": "Every bucket has object versioning enabled.",
  "check.gcp.storage.versioning.fail": "At least one bucket has versioning off, so an overwrite or a delete is final.",
  "check.gcp.storage.versioning.fix": "Enable versioning on the bucket and add a lifecycle rule to expire old versions, so the protection does not become a storage bill.",
  "check.gcp.sql.not_public.title": "No database accepts connections from the whole internet",
  "check.gcp.sql.not_public.pass": "No Cloud SQL instance authorises the whole internet.",
  "check.gcp.sql.not_public.fail": "A Cloud SQL instance authorises the whole internet, so anyone who learns the address can attempt to connect.",
  "check.gcp.sql.not_public.fix": "Replace the authorised network with your own addresses, or move the instance to a private address and reach it through the Cloud SQL Auth Proxy.",
  "check.gcp.sql.require_ssl.title": "Databases refuse unencrypted connections",
  "check.gcp.sql.require_ssl.pass": "Every Cloud SQL instance requires an encrypted connection.",
  "check.gcp.sql.require_ssl.fail": "At least one instance accepts unencrypted connections, so credentials and data can cross the network in the clear.",
  "check.gcp.sql.require_ssl.fix": "Set the instance to accept encrypted connections only. Check your clients first, because an application without a certificate will stop connecting.",
  "check.gcp.sql.backups.title": "Databases are backed up automatically",
  "check.gcp.sql.backups.pass": "Every Cloud SQL instance has automated backups enabled.",
  "check.gcp.sql.backups.fail": "At least one instance has automated backups switched off.",
  "check.gcp.sql.backups.fix": "Enable automated backups on the instance, and add point-in-time recovery if losing a day of data would matter. A backup nobody has restored is a plan, not a capability.",
  "check.gcp.sql.deletion_protection.title": "Databases cannot be deleted by accident",
  "check.gcp.sql.deletion_protection.pass": "Every Cloud SQL instance has deletion protection enabled.",
  "check.gcp.sql.deletion_protection.fail": "At least one instance can be deleted without an extra confirmation.",
  "check.gcp.sql.deletion_protection.fix": "Enable deletion protection on the instance. It costs nothing and it has saved more production databases than any other setting on this page.",
  "check.gcp.kms.key_rotation.title": "Encryption keys rotate on a schedule",
  "check.gcp.kms.key_rotation.pass": "Every symmetric key has a rotation period set.",
  "check.gcp.kms.key_rotation.fail": "At least one symmetric encryption key has no rotation period, so it will be used indefinitely.",
  "check.gcp.kms.key_rotation.fix": "Set a rotation period on the key. Ninety days suits most uses, and existing data stays readable because old key versions are retained.",
  "check.gcp.logging.sink.title": "Logs are exported somewhere they outlive thirty days",
  "check.gcp.logging.sink.pass": "At least one log sink exports to storage or an analytics destination.",
  "check.gcp.logging.sink.fail": "No log sink exports anywhere. Logs sit in the default bucket for thirty days and are then gone.",
  "check.gcp.logging.sink.fix": "Create a sink to a Cloud Storage bucket or BigQuery, with a retention matching the evidence period your framework expects. An auditor asking about last quarter needs those logs to still exist.",
  "confirm.title": "Confirm",
  "confirm.training.title": "Have you completed this training?",
  "confirm.training.body": "Pressing the button records today's date against your name, and that you confirmed it yourself rather than somebody recording it for you. Only do it once you have actually finished.",
  "confirm.training.cta": "Yes, I have completed it",
  "confirm.policy.title": "Do you accept this policy?",
  "confirm.policy.body": "Pressing the button records that you have read and accepted this version of the policy, on today's date. If a new version is published later you will be asked again, because accepting an old version says nothing about the current one.",
  "confirm.policy.cta": "I have read and accept it",
  "confirm.field.course": "Course",
  "confirm.field.policy": "Policy",
  "confirm.field.you": "For",
  "confirm.field.due": "Due by",
  "confirm.thanks": "Thank you, that is recorded.",
  "confirm.already": "This is already recorded.",
  "confirm.recorded": "Recorded",
  "confirm.byadmin": "recorded by an administrator",
  "confirm.note": "This link is personal to you and works once. It records a date and your name for your employer's compliance records, and nothing else: no tracking, no account, and no other information about you.",
  "confirm.unknown.title": "This link is not valid",
  "confirm.unknown.body": "It may have been replaced by a newer one, or copied incompletely. Ask whoever sent it for a fresh link.",
  "assign.links.cta": "Get links for the outstanding",
  "assign.links.title": "Personal links, shown once",
  "assign.links.body": "One per person still to confirm, in the order they appear above. Send each to the right person. Asking again issues new links and retires these.",
  "assign.links.error.none": "Everyone on this round has already confirmed.",
  "assign.source.person": "confirmed by them",
  "assign.source.admin": "recorded by an admin",
  "team.seats.title": "Who can sign in",
  "team.seats.body": "An auditor seat is read-only by construction, not by hidden buttons: an auditor is a member and is not an admin, so every read is allowed and every write is refused by the database itself. Give your assessor one instead of sharing your password.",
  "team.seats.unknown": "Invited, not yet signed in",
  "team.seats.remove": "Remove",
  "team.role.owner": "Owner",
  "team.role.admin": "Admin",
  "team.role.member": "Member",
  "team.role.auditor": "Auditor",
  "team.invite.title": "Invite someone",
  "team.invite.hint": "The link works once, expires in seven days, and only for the address you name. Forwarding it to anyone else achieves nothing.",
  "team.invite.email": "Their work email",
  "team.invite.role": "Seat",
  "team.invite.cta": "Create the invite",
  "team.invite.once": "Copy this now. It is shown once and never again.",
  "team.invite.send": "Send it to them yourself, however you normally would. Snoopios does not email it, so the link never sits in a mailbox we control.",
  "team.invite.pending": "Invited, not yet accepted",
  "team.invite.expires": "expires",
  "team.invite.revoke": "Withdraw",
  "team.invite.error.email": "That does not look like an email address.",
  "team.invite.error.member": "That person is already in your organisation.",
  "team.invite.error.duplicate": "There is already a live invite for that address. Withdraw it first if you want to change the seat.",
  "team.invite.error.toomany": "There are already ten invites waiting. Withdraw some before sending more.",
  "team.invite.error.owner": "Only the account owner can invite people.",
  "invite.title": "You have been invited",
  "invite.body": "Accepting adds you to this organisation with the seat you were given. An auditor seat can read everything and change nothing.",
  "invite.signedin": "Signed in as",
  "invite.cta": "Accept the invitation",
  "invite.wrong": "Wrong account?",
  "invite.problem.expired": "This invitation has expired. Ask for a new one; they last seven days.",
  "invite.problem.used": "This invitation has already been used.",
  "invite.problem.withdrawn": "This invitation was withdrawn.",
  "invite.problem.address": "This invitation was sent to a different address. Sign in as the person it names.",
  "invite.problem.member": "You already belong to an organisation, and somebody can only belong to one.",
  "invite.problem.invalid": "That invitation link is not valid.",
  "app.readonly.title": "You are viewing as an auditor",
  "app.readonly.body": "You can read every check, document and register here. Nothing on any screen can be changed, and the database refuses the attempt rather than a button hiding it.",
  "assign.title": "Training and policy acceptance",
  "assign.intro": "ISO asks for awareness training and for policies that are communicated and acknowledged; SOC 2 asks the same. Neither is answerable by a check, and an assessor samples both by person rather than accepting one sentence covering the team.",
  "assign.kind.training": "Training",
  "assign.kind.policy": "Policy",
  "assign.due": "due",
  "assign.cancel": "Abandon",
  "assign.record": "Record",
  "assign.nobody": "Add people to the roster first. A round with nobody in it records nothing.",
  "assign.training.title": "Run a training round",
  "assign.training.hint": "Everyone on the roster gets a line. Record the date each person actually finished, not the date you asked them to.",
  "assign.policy.title": "Ask people to accept a policy",
  "assign.policy.hint": "Acceptance is of a version. Once you publish a new version, run another round, because everyone accepting an old one proves nothing about the current policy.",
  "assign.training.cta": "Start the round",
  "assign.policy.cta": "Ask for acceptance",
  "assign.field.course": "Course",
  "assign.field.course.placeholder": "Security awareness 2026",
  "assign.field.policy": "Policy",
  "assign.field.policy.placeholder": "Information security policy",
  "assign.field.version": "Version",
  "assign.field.due": "Due (optional)",
  "assign.field.completed": "Date completed",
  "assign.error.title": "Give the round a name.",
  "assign.error.version": "Say which version people are accepting. Acceptance of an unnamed version proves nothing later.",
  "assign.error.nobody": "There is nobody on the roster to assign this to.",
  "review.title": "Access reviews",
  "review.intro": "Offboarding proves a leaver lost access. A review proves the people still here still need what they hold. An assessor sampling a quarter asks for this one by name, and a review cannot be completed while any row is undecided.",
  "review.field.period": "What period does this cover?",
  "review.field.period.placeholder": "Q3 2026",
  "review.field.systems": "Systems to review",
  "review.field.reviewer": "Reviewed by",
  "review.field.note": "Note (optional)",
  "review.start.cta": "Start a review",
  "review.complete.cta": "Complete the review",
  "review.cancel": "Abandon",
  "review.started": "started",
  "review.completed": "completed",
  "review.rows": "rows",
  "review.removed": "to remove",
  "review.undecided": "still undecided",
  "review.nobody": "Add people to the roster first. A review with nobody in it proves nothing.",
  "review.decision.keep": "Keep",
  "review.decision.remove": "Remove",
  "review.decision.none": "No access",
  "review.error.period": "Say what period this review covers.",
  "review.error.systems": "Choose at least one system to review.",
  "review.error.open": "A review is already open. Finish or abandon it first. Two half-done reviews is how an organisation ends up with neither.",
  "review.error.nobody": "There is nobody on the roster to review.",
  "review.error.undecided": "Some rows are still undecided. A review signed off half-answered is worse than no review, because it produces a document saying access was reviewed when part of it never was.",
  "coverage.kind.record": "Register",
  "attest.internal_audit.statement": "{org} has completed an internal audit of its information security management system within the last twelve months, carried out by someone independent of the activities audited, and every finding has an owner and a due date.",
  "attest.internal_audit.reference": "The audit reference and the date it was completed",
  "attest.internal_audit.hint": "Independence is the part small teams struggle with, and a stated limitation is accepted where a pretended independence is not. A non-executive, an adviser, or a colleague who does not run the systems under review all count.",
  "attest.mgmt_review.statement": "Top management at {org} has reviewed the information security management system within the last twelve months, considering each input ISO/IEC 27001 clause 9.3.2 names, and has recorded decisions on improvement, on changes to the system, and on the resources it needs.",
  "attest.mgmt_review.reference": "The date of the review and where the record is kept",
  "attest.mgmt_review.hint": "The resources decision is the output assessors most often find missing, because it is the one that costs something. A review that records no decision is not a review.",
  "attest.isms_scope.statement": "{org} has defined and documented the scope of its information security management system, naming the products, teams, locations and information inside it and anything deliberately outside it.",
  "attest.isms_scope.reference": "Where the scope statement is recorded and when it was last revised",
  "attest.isms_scope.hint": "The scope decides what everything else is measured against, so an assessor reads it first. A scope that quietly omits a product the company sells is the finding they are looking for.",
  "pack.doc.soa.title": "Statement of Applicability",
  "pack.doc.soa.body": "Every one of the ninety-three Annex A controls, whether it applies to you, why, and what stands behind it today. Generated from the same evidence the coverage page reads, so it is a reading taken on the day you export it rather than a document that went stale the day after it was written. The scope of the management system and any exclusions are fill-ins, because only you can state those.",
  "pack.doc.audit.title": "Internal audit record",
  "pack.doc.audit.body": "Clause 9.2: that audits happen on a programme, against stated criteria, by someone independent of what they audit, and that findings are followed to closure. The scope and the evidence counts are drafted for you; the auditor, the findings and the conclusion are fill-ins, because inventing them would forge the record.",
  "pack.doc.review.title": "Management review record",
  "pack.doc.review.body": "Clause 9.3, with every input the clause names set out so none is left to memory, and the outputs it requires: improvements, changes and resources. The monitoring results are filled from your live checks; the decisions are yours.",
  "privacy.s9.h": "People your customers add to their roster",
  "privacy.s9.p": "If you use the people list, you give us the name and, if you choose, the work email, role and joining date of each person who can reach your systems, together with the date anyone left and the date each of their accounts was closed. We hold this because every security standard asks who has access and how a leaver lost it, and a list is the only honest answer. You are the controller of that information and we process it only on your instructions. It is visible to the members of your organisation and to nobody else: it never appears on your public trust page, is never sent to a model, and is never used for anything but showing it back to you and including it in your export. It is kept for the life of your account and deleted with it, because a record of a leaver whose access was closed is the evidence that it was, and deleting it early would destroy the thing it exists to prove. Tell the people on your list that you keep it; that duty is yours, not ours.",
  "team.title": "People",
  "team.lede": "Who works here, who left, and for each leaver the day access to each system was actually removed and who removed it. Every framework asks both questions; until this list existed the answer was a sentence somebody ticked.",
  "team.note": "This list is organisational rather than per project, because a person works for the company. It is never shown on your public trust page and never leaves the app except in your own account export.",
  "team.current.title": "Working here now",
  "team.current.empty": "Nobody on the list yet. Add the people who can reach your systems, including contractors.",
  "team.since": "since",
  "team.remove": "Remove from the list",
  "team.add.title": "Add someone",
  "team.add.intro": "Include anyone who can reach a system you would have to close if they left. That usually means more people than the payroll does.",
  "team.add.cta": "Add to the list",
  "team.field.name": "Full name",
  "team.field.email": "Work email",
  "team.field.title": "Role",
  "team.field.started": "Started",
  "team.field.engagement": "Engagement",
  "team.engagement.employee": "Employee",
  "team.engagement.contractor": "Contractor",
  "team.left.intro": "When someone leaves, tick every system they could reach. Each one becomes a line to close, with a date and a name.",
  "team.left.cta": "Record that they left",
  "team.field.left": "Last day",
  "team.field.systems": "Systems they could reach",
  "team.system.email": "Email and calendar",
  "team.system.laptop": "Laptop and devices",
  "team.system.passwords": "Password manager",
  "team.leavers.title": "People who have left",
  "team.leavers.intro": "This is what an auditor samples. They pick a leaver and ask to see the day each account was closed, so a line without a date is a finding rather than an oversight.",
  "team.leavers.empty": "Nobody has left yet.",
  "team.leftOn": "left",
  "team.closed": "closed",
  "team.removedOn": "removed",
  "team.outstanding": "Access still open for:",
  "team.step.removed": "Date removed from",
  "team.step.by": "Removed by",
  "team.step.cta": "Confirm",
  "team.error.name": "Enter the person's name.",
  "team.error.full": "This list holds five hundred people. Get in touch if you need more.",
  "team.error.admin": "Only an owner or admin can change this list.",
  "team.error.leftdate": "Enter the person's last day.",
  "team.error.systems": "Tick at least one system. A leaver with nothing to close is the record this list exists to prevent.",
  "team.error.beforejoin": "That last day is before the day they joined.",
  "team.error.faraway": "That last day is more than a year away.",
  "team.error.removedate": "Enter the date access was removed.",
  "team.error.future": "That date is in the future. Record it once the access is actually gone.",
  "nav.tab.team": "People",
  "conn.aws.title": "Amazon Web Services",
  "conn.aws.intro": "Snoopios reads your AWS account with an access key that carries the SecurityAudit policy and nothing wider. It never asks for ReadOnlyAccess, because that grants permission to read the contents of every bucket, which no compliance check needs.",
  "conn.aws.step1": "In IAM, create a user called snoopios-audit with no console access.",
  "conn.aws.step2": "Attach the AWS-managed SecurityAudit policy to it, and nothing else. If anything wider is attached, Snoopios will refuse the key rather than store it.",
  "conn.aws.step3": "Create an access key for that user and paste both halves below.",
  "conn.aws.key.label": "Access key ID",
  "conn.aws.key.placeholder": "AKIA...",
  "conn.aws.secret.label": "Secret access key",
  "conn.aws.secret.hint": "Encrypted before it is stored, with a key that is not in the database. It is never logged and never appears in an error message.",
  "conn.aws.region.label": "Region",
  "conn.aws.region.placeholder": "eu-west-2",
  "conn.aws.region.hint": "The region your infrastructure runs in. IAM, S3 and CloudTrail are read account-wide; EC2, RDS, KMS, GuardDuty, Config, Access Analyzer and Lambda are read in this region. One check asks every other region whether it holds servers or databases, so you are told about anything running outside this one.",
  "conn.aws.cta": "Connect AWS",
  "conn.aws.error.key": "That does not look like an AWS access key ID. It begins with AKIA and is at least sixteen characters.",
  "conn.aws.error.secret": "That does not look like an AWS secret access key.",
  "conn.aws.error.region": "Enter a region code such as eu-west-2 or us-east-1.",
  "conn.aws.error.identity": "AWS did not accept that key. Check both halves, and check the key is active in IAM.",
  "conn.aws.error.wide": "That key carries more than SecurityAudit. Snoopios will not store a credential that can change your account. Attach only the SecurityAudit policy and try again.",
  "conn.aws.error.unverified": "Snoopios could not confirm what that key is allowed to do, so it will not store it. Use an IAM user with the SecurityAudit policy attached directly, rather than a role or a group.",
  "check.aws.iam.root_mfa.title": "The root user has multi-factor authentication",
  "check.aws.iam.root_mfa.pass": "The account root has MFA enabled.",
  "check.aws.iam.root_mfa.fail": "The account root can sign in with a password alone.",
  "check.aws.iam.root_mfa.fix": "Sign in as root, open Security credentials, and assign an MFA device. The root user can do anything in the account and cannot be restricted by policy, so this is the single most important control AWS offers. Use a hardware key or an authenticator app, not SMS, and store the recovery codes somewhere the whole founding team can reach.",
  "check.aws.iam.root_no_keys.title": "The root user has no access keys",
  "check.aws.iam.root_no_keys.pass": "The account root holds no access keys.",
  "check.aws.iam.root_no_keys.fail": "The account root holds an access key.",
  "check.aws.iam.root_no_keys.fix": "Delete the root access key in Security credentials. A root key cannot be scoped, cannot be restricted by policy, and does not appear in most access reviews. Anything a script needs it for should be an IAM role instead. AWS has recommended against root keys for over a decade and auditors treat one as an automatic finding.",
  "check.aws.iam.password_policy.title": "The password policy asks for length and stops reuse",
  "check.aws.iam.password_policy.pass": "The account password policy requires at least fourteen characters and prevents reuse.",
  "check.aws.iam.password_policy.fail": "The account password policy is weaker than fourteen characters, or allows a password to be reused.",
  "check.aws.iam.password_policy.fix": "Set the IAM account password policy to a minimum of fourteen characters and remember at least five previous passwords. Length is what matters; the character-class rules are theatre by comparison and NIST stopped recommending them in 2017. An account with no policy at all is on the eight-character default.",
  "check.aws.iam.users_mfa.title": "Every IAM user with a sign-in has MFA",
  "check.aws.iam.users_mfa.pass": "Every IAM user has an MFA device.",
  "check.aws.iam.users_mfa.fail": "One or more IAM users can sign in without MFA.",
  "check.aws.iam.users_mfa.fix": "Assign an MFA device to each user listed, or delete the user if nobody is using it. Better still, move people to identity centre single sign-on and keep IAM users only for the few things that cannot use it, because a user with a password is a credential that outlives the person.",
  "check.aws.iam.keys_rotated.title": "Access keys are younger than ninety days",
  "check.aws.iam.keys_rotated.pass": "Every active access key was created within the last ninety days.",
  "check.aws.iam.keys_rotated.fail": "An active access key is older than ninety days.",
  "check.aws.iam.keys_rotated.fix": "Create a replacement key, deploy it, confirm the old one has stopped being used in its last-used record, then delete the old one. Ninety days is the benchmark auditors cite. A key that has never been rotated is one that has been in a developer's shell history, a CI variable and a laptop backup for as long as it has existed.",
  "check.aws.iam.admins_limited.title": "Nobody carries AdministratorAccess as a standing permission",
  "check.aws.iam.admins_limited.pass": "No IAM user has AdministratorAccess attached directly.",
  "check.aws.iam.admins_limited.fail": "An IAM user has AdministratorAccess attached directly.",
  "check.aws.iam.admins_limited.fix": "Detach AdministratorAccess from the users listed and give them a role to assume when they need it. Administrator through a role is at least deliberate and shows up in CloudTrail as an assumption; attached to a user it is simply how they work every day, and every review has to take it on trust.",
  "check.aws.ec2.admin_ports_restricted.title": "No security group opens an admin port to the internet",
  "check.aws.ec2.admin_ports_restricted.pass": "No security group allows the whole internet to reach an administrative port.",
  "check.aws.ec2.admin_ports_restricted.fail": "A security group allows 0.0.0.0/0 or ::/0 to an administrative port.",
  "check.aws.ec2.admin_ports_restricted.fix": "Narrow the rule to the addresses that need it, or remove it and reach the instance through Systems Manager Session Manager, which needs no inbound rule at all. SSH, RDP, and the database ports listed are scanned continuously; an open one is found in minutes, not months.",
  "check.aws.ec2.default_sg_closed.title": "The default security group carries no rules",
  "check.aws.ec2.default_sg_closed.pass": "Every default security group is empty.",
  "check.aws.ec2.default_sg_closed.fail": "A default security group has allow rules on it.",
  "check.aws.ec2.default_sg_closed.fix": "Remove every inbound and outbound rule from the default security group in each VPC. Anything launched without an explicit choice lands in it, so a rule there is one nobody meant to write and one that quietly applies to the next thing anyone starts.",
  "check.aws.vpc.flow_logs.title": "Every VPC records its network flows",
  "check.aws.vpc.flow_logs.pass": "Every VPC has an active flow log.",
  "check.aws.vpc.flow_logs.fail": "A VPC has no active flow log.",
  "check.aws.vpc.flow_logs.fix": "Turn on flow logs for the VPCs listed, to CloudWatch Logs or to S3. Without them there is no record of what talked to what, which is the first thing anyone asks for during an incident and the first thing an auditor asks for afterwards.",
  "check.aws.ec2.volumes_encrypted.title": "Every EBS volume is encrypted",
  "check.aws.ec2.volumes_encrypted.pass": "Every EBS volume is encrypted at rest.",
  "check.aws.ec2.volumes_encrypted.fail": "An EBS volume is not encrypted.",
  "check.aws.ec2.volumes_encrypted.fix": "Snapshot the volume, copy the snapshot with encryption enabled, and replace the volume from the copy. Then turn on EBS encryption by default for the region so the next one is encrypted without anyone remembering. Unencrypted disks are the finding that turns a lost laptop of a data centre into a notifiable breach.",
  "check.aws.ec2.imdsv2_required.title": "Instances require the token-based metadata service",
  "check.aws.ec2.imdsv2_required.pass": "Every running instance requires IMDSv2.",
  "check.aws.ec2.imdsv2_required.fail": "A running instance still allows the version 1 metadata service.",
  "check.aws.ec2.imdsv2_required.fix": "Set the instance metadata options to require tokens, with HttpTokens set to required. Version 1 answers any request that reaches it from the instance, so a single server-side request forgery bug in your application hands out the instance's AWS credentials. This is how the 2019 Capital One breach worked.",
  "check.aws.s3.public_access_blocked.title": "Every bucket blocks public access",
  "check.aws.s3.public_access_blocked.pass": "Every bucket has all four public access blocks on.",
  "check.aws.s3.public_access_blocked.fail": "A bucket does not have all four public access blocks on.",
  "check.aws.s3.public_access_blocked.fix": "Turn on Block Public Access for the buckets listed, and turn it on at the account level so it applies to buckets nobody has made yet. All four settings matter: two stop public ACLs, two stop public policies. A bucket with none of them is one policy edit away from being on the open internet.",
  "check.aws.s3.versioning.title": "Buckets keep previous versions",
  "check.aws.s3.versioning.pass": "Every bucket has versioning enabled.",
  "check.aws.s3.versioning.fail": "A bucket does not keep previous versions.",
  "check.aws.s3.versioning.fix": "Enable versioning on the buckets listed. Without it a deletion is final, which makes accidental loss unrecoverable and makes ransomware trivial. Add a lifecycle rule to expire old versions if the storage cost worries you, rather than leaving versioning off.",
  "check.aws.s3.policy_not_public.title": "No bucket policy makes a bucket public",
  "check.aws.s3.policy_not_public.pass": "No bucket policy grants public access.",
  "check.aws.s3.policy_not_public.fail": "A bucket policy grants access to the whole internet.",
  "check.aws.s3.policy_not_public.fix": "Read the policy on the buckets listed and remove the statement whose principal is a bare asterisk, or whose condition matches everyone. If the bucket is genuinely meant to be public, serve it through CloudFront with origin access control instead, so the bucket itself stays closed.",
  "check.aws.rds.not_public.title": "No database is reachable from the internet",
  "check.aws.rds.not_public.pass": "No RDS instance is publicly accessible.",
  "check.aws.rds.not_public.fail": "An RDS instance is publicly accessible.",
  "check.aws.rds.not_public.fix": "Set PubliclyAccessible to false on the instances listed and reach them from inside the VPC, through a bastion or through Session Manager port forwarding. A public database endpoint is scanned within hours of being created and is the shortest path anyone will find to your data.",
  "check.aws.rds.encrypted.title": "Every database is encrypted at rest",
  "check.aws.rds.encrypted.pass": "Every RDS instance is encrypted at rest.",
  "check.aws.rds.encrypted.fail": "An RDS instance is not encrypted at rest.",
  "check.aws.rds.encrypted.fix": "Encryption cannot be turned on in place: take a snapshot, copy it with encryption enabled, and restore a new instance from the copy. Plan the cutover, because this one needs downtime. Then set the region default so the next database is encrypted without anyone deciding.",
  "check.aws.rds.backups.title": "Databases keep at least a week of backups",
  "check.aws.rds.backups.pass": "Every RDS instance keeps at least seven days of automated backups.",
  "check.aws.rds.backups.fail": "An RDS instance keeps fewer than seven days of backups, or none at all.",
  "check.aws.rds.backups.fix": "Set the backup retention period to seven days or more on the instances listed. A retention of zero means automated backups are switched off entirely, which is a different and worse thing than a short window. Then restore one, because a backup nobody has restored is a hypothesis.",
  "check.aws.rds.deletion_protection.title": "Databases cannot be deleted by accident",
  "check.aws.rds.deletion_protection.pass": "Every RDS instance has deletion protection on.",
  "check.aws.rds.deletion_protection.fail": "An RDS instance can be deleted without an extra step.",
  "check.aws.rds.deletion_protection.fix": "Turn on deletion protection for the instances listed. It costs nothing and it stops the console click and the stray terraform destroy that has ended more than one company's afternoon. Turning it off is a deliberate act, which is exactly the point.",
  "check.aws.cloudtrail.enabled.title": "A multi-region trail is recording API activity",
  "check.aws.cloudtrail.enabled.pass": "A multi-region CloudTrail trail is logging.",
  "check.aws.cloudtrail.enabled.fail": "No multi-region trail is logging.",
  "check.aws.cloudtrail.enabled.fix": "Create a trail that applies to all regions and confirm it is logging, not merely present. A trail in one region leaves every other region unrecorded, which is exactly where someone holding a stolen key would work. Without CloudTrail there is no answer to what happened, and no SOC 2 or ISO audit will pass without one.",
  "check.aws.cloudtrail.log_validation.title": "Trail log files can be proved unaltered",
  "check.aws.cloudtrail.log_validation.pass": "Every trail has log file validation enabled.",
  "check.aws.cloudtrail.log_validation.fail": "A trail does not have log file validation enabled.",
  "check.aws.cloudtrail.log_validation.fix": "Enable log file validation on the trails listed. It has AWS sign a digest of each log file, so you can show an investigator that the record was not edited after the fact. Evidence nobody can prove is intact is evidence an auditor can decline.",
  "check.aws.kms.key_rotation.title": "Customer-managed keys rotate",
  "check.aws.kms.key_rotation.pass": "Every enabled customer-managed key has automatic rotation on.",
  "check.aws.kms.key_rotation.fail": "An enabled customer-managed key does not rotate.",
  "check.aws.kms.key_rotation.fix": "Turn on automatic annual rotation for the keys listed. AWS keeps the old key material so nothing you encrypted before becomes unreadable. Keys AWS manages for you rotate on their own schedule and are left out of this check, because nobody can act on them.",
  "check.aws.guardduty.enabled.title": "GuardDuty is watching the account",
  "check.aws.guardduty.enabled.pass": "GuardDuty has an enabled detector in this region.",
  "check.aws.guardduty.enabled.fail": "GuardDuty is not enabled in this region.",
  "check.aws.guardduty.enabled.fix": "Enable GuardDuty. It reads CloudTrail, VPC flow logs and DNS logs you are already producing and looks for the patterns that mean a credential has been stolen or an instance is mining cryptocurrency. It needs no agent and it is the cheapest detection you will buy.",
  "provider.aws": "AWS",
  "stack.blurb.aws": "Read-only checks across IAM, S3, EC2, RDS, CloudTrail, KMS and GuardDuty.",
  "app.regimes.title": "Tell us which regimes apply to you",
  "app.regimes.body": "Four questions about the business, and we will say which frameworks apply to you, which are worth having, and which you can leave alone. Until you answer, we have assumed the United Kingdom.",
  "app.regimes.cta": "Answer four questions",
  "baseline.count.paper": "statements confirmed",
  "baseline.count.paper.of": "of",
  "baseline.title": "Baseline",
  "baseline.lede": "One reading of the stack, before anyone has named a framework. It is computed from the checks already running and the statements you have already confirmed, so it needs nothing new from you. The framework percentages underneath are the specific answers.",
  "baseline.domains.title": "Six ways of looking at it",
  "baseline.domain.identity": "Identity",
  "baseline.domain.identity.blurb": "Who can get in, and what happens to the accounts of people who left.",
  "baseline.domain.application": "Application",
  "baseline.domain.application.blurb": "The code, the pipeline, and what the running app hands to a browser.",
  "baseline.domain.infrastructure": "Infrastructure",
  "baseline.domain.infrastructure.blurb": "The machines, the network edge, the certificates and the DNS in front of them.",
  "baseline.domain.data": "Data",
  "baseline.domain.data.blurb": "Where personal data sits, who can reach it, and whether it can be restored.",
  "baseline.domain.governance": "Governance",
  "baseline.domain.governance.blurb": "The two things a machine can check, plus every statement a person has confirmed in writing.",
  "baseline.domain.operations": "Operations",
  "baseline.domain.operations.blurb": "Whether anyone finds out when it breaks, and whether someone is on the end of it.",
  "baseline.band.strong": "Strong",
  "baseline.band.fair": "Fair",
  "baseline.band.weak": "Needs work",
  "baseline.band.none": "Nothing yet",
  "baseline.method": "The average of the areas that have something behind them. It is an average rather than a straight tally so that one provider with forty checks cannot outweigh one with three. Covering",
  "baseline.method.of": "of",
  "baseline.nodata": "Nothing has run yet. Connect a provider, or add a domain, and this fills in on the first run.",
  "baseline.nodata.dash": "\u2014",
  "baseline.domain.empty": "nothing connected here yet",
  "baseline.count.pass": "passing",
  "baseline.count.fail": "failing",
  "baseline.count.unknown": "could not run",
  "baseline.unknown.note": "A check that could not run counts as neither a pass nor a fail. It is left out of the percentage and shown on its own, because a check that saw nothing tells you nothing.",
  "baseline.frameworks.title": "What that means for each framework",
  "baseline.frameworks.body": "The same evidence, read against the regimes you hold. A percentage here counts every control with something behind it: an automated check, a document, a report from your host, or a statement you confirmed.",
  "app.project.baseline": "Baseline",
  "packs.allowance.region.one": "region",
  "packs.allowance.region.many": "regions",
  "packs.allowance.specialist.one": "specialist pack",
  "packs.allowance.specialist.many": "specialist packs",
  "coverage.locked.swap": "Swap to it free",
  "coverage.locked.upgrade": "On a higher plan",
  "coverage.locked.choose": "Choose your regimes",
  "regimes.title": "Regimes",
  "regimes.q1": "Where is the company registered?",
  "regimes.q1.hint": "The seat of the business. Its own law applies to you whether or not you sell there.",
  "regimes.q2": "Where are your customers?",
  "regimes.q2.hint": "Pick every market you sell into. A customer's law reaches you through them, which is the part most founders are surprised by.",
  "regimes.q3": "Do you handle any of these?",
  "regimes.q3.hint": "Each one carries a regime of its own, on top of wherever you are.",
  "regimes.q3.children": "Data about children",
  "regimes.q3.ai": "AI systems, ours or a provider's",
  "regimes.q3.health": "NHS or health data",
  "regimes.q4": "Has anyone asked you to prove it?",
  "regimes.q4.hint": "This decides how urgent the security standards are, not whether they are worth having.",
  "regimes.q4.none": "Not yet",
  "regimes.q4.asked": "A buyer asked for ISO 27001 or SOC 2",
  "regimes.q4.audited": "We are in an audit now",
  "regimes.cta": "Show me what applies",
  "regimes.cta.hint": "Nothing is saved until you press Save below.",
  "regimes.missed.title": "Your plan does not cover everything that applies to you",
  "regimes.missed.body": "We would rather say so than quietly leave it off the list. These obligations exist whether or not you buy them from us, and the free guides at /frameworks explain each one in full.",
  "regimes.missed.cta": "See what each plan holds",
  "rec.verdict.required": "Required",
  "rec.verdict.recommended": "Recommended",
  "rec.verdict.useful": "Worth having",
  "rec.verdict.later": "Not yet",
  "rec.reason.registered": "You are registered here, so this law applies to you directly.",
  "rec.reason.customers": "You sell here. The law follows your customers, not your office.",
  "rec.reason.noregion": "Nothing you told us puts you in this regime. Come back when that changes.",
  "rec.reason.audited": "You are in an audit. This is the pack the auditor is working from.",
  "rec.reason.asked": "A buyer has asked. This is what they are asking for by name.",
  "rec.reason.nobuyer": "Nobody has asked yet, but the first enterprise buyer will, and the evidence takes months to accumulate rather than days.",
  "rec.reason.ai": "You run or resell AI systems, so the AI regimes apply. One system inventory answers the first control of all three.",
  "rec.reason.noai": "You told us you do not run AI systems. Nothing here applies yet.",
  "rec.reason.children": "You handle children's data, which carries its own standards on top of the privacy law wherever you are.",
  "rec.reason.nochildren": "No children's data, so these do not apply. Worth revisiting if you ever drop the age limit.",
  "rec.reason.health": "You sell into the NHS, and a trust runs both of these before it buys.",
  "rec.reason.nohealth": "Not selling into the NHS, so these do not apply.",
  "packs.error.empty": "Choose at least one region.",
  "packs.error.owner": "Only the account owner can change this.",
  "plan.regimes.title": "Which regimes apply to you",
  "plan.regimes.body": "Answer four questions about the business and we will say which frameworks apply, which are worth having, and which you can leave alone.",
  "plan.regimes.cta": "Choose your regimes",
  "plan.regimes.current": "Currently held",
  "tier.studio.f6": "Evidence vault extended to twenty-four months",
  "pack.uk.name": "United Kingdom",
  "pack.uk.blurb": "UK GDPR, Cyber Essentials, and the Software Security Code of Practice that government buyers now ask suppliers to sign up to.",
  "pack.eu.name": "European Union",
  "pack.eu.blurb": "The EU GDPR as the regulation itself rather than the UK's version of it, and NIS 2 for the entities the directive brings into scope.",
  "pack.uae.name": "United Arab Emirates",
  "pack.uae.blurb": "The federal data protection law, the DIFC and ADGM regimes that free zone companies answer to instead, Dubai's information security regulation, and the federal assurance standards underneath them.",
  "pack.saudi.name": "Saudi Arabia",
  "pack.saudi.blurb": "The Saudi data protection law with the National Cybersecurity Authority's Essential Cybersecurity Controls and the cloud controls that extend them.",
  "pack.gulf.name": "The wider Gulf",
  "pack.gulf.blurb": "Qatar's data protection law and national information assurance policy, with the Bahraini and Omani data protection laws.",
  "pack.na.name": "North America",
  "pack.na.blurb": "California's privacy act, Canada's federal law, and Quebec's Law 25, which asks for more than the federal one and catches companies that assumed otherwise.",
  "pack.asia.name": "Asia Pacific",
  "pack.asia.blurb": "Singapore's data protection act and India's digital personal data protection act.",
  "pack.security.name": "Security standards",
  "pack.security.blurb": "The certifications a buyer asks for by name. ISO 27001 and SOC 2, extended by ISO 27701 for privacy management, 27017 and 27018 for the cloud, 22301 for continuity, and the NIST framework where an American buyer uses its language.",
  "pack.ai.name": "AI governance",
  "pack.ai.blurb": "ISO 42001, the EU AI Act and the NIST AI risk management framework. One AI system inventory answers the first control of all three.",
  "pack.children.name": "Children's data",
  "pack.children.blurb": "The UK Children's Code and the American pair, COPPA and FERPA. Required of anything a child can sign up to, which is more services than expect it.",
  "pack.health.name": "NHS supply",
  "pack.health.blurb": "The Digital Technology Assessment Criteria a trust runs before buying, and the Data Security and Protection Toolkit it expects you to have submitted.",
  "packs.title": "Which regimes apply to you",
  "packs.lede": "You do not pick frameworks, you pick regimes. A pack is every framework that follows from where you are registered, where your customers are, and what you sell into.",
  "packs.note": "Adding a pack does not change what Snoopios looks at. All thirty-six frameworks read the same one hundred and eighty-five checks, so the evidence is the same evidence. What a pack adds is the ability to answer for that regime: its coverage view, the control wording an assessor recognises, the attestations it asks for that no other does, and the questionnaire answers in its language.",
  "packs.region.title": "Where you operate",
  "packs.assurance.title": "What buyers ask for",
  "packs.specialist.title": "What you handle",
  "packs.locked": "On a higher tier",
  "packs.save": "Save selection",
  "packs.saved": "Selection saved.",
  "packs.error": "That selection does not fit your plan. Deselect one first.",
  "packs.included": "Included",
  "attest.ai_inventory.statement": "{org} keeps an inventory of the AI systems it builds or uses, recording for each one its purpose, the data it sees, the provider behind it and who owns the outcome.",
  "attest.ai_inventory.reference": "Where the inventory is kept and when it was last reviewed",
  "attest.ai_inventory.hint": "Every AI obligation in every regime hangs from this list. A system nobody wrote down is a system nobody assessed, and the first question an assessor asks is how you know the list is complete.",
  "attest.ai_risk_tier.statement": "{org} has classified each of its AI systems under the EU AI Act as prohibited, high-risk, limited-risk or minimal-risk, and has recorded the reasoning for each classification.",
  "attest.ai_risk_tier.reference": "Where the classification and its reasoning are recorded",
  "attest.ai_risk_tier.hint": "Almost everything else in the Act follows from the tier. Most business software lands in limited or minimal risk, but the reasoning is what you will be asked for, not the answer.",
  "attest.ai_human.statement": "A named person at {org} can review, override or stop each AI system's output before it affects anyone, and that person has the means and the authority to do it.",
  "attest.ai_human.reference": "Who holds that responsibility for each system",
  "attest.age_assurance.statement": "{org} establishes the age of its users with a level of certainty proportionate to the risks its service presents to children, or applies the standards of the Children's Code to all users.",
  "attest.age_assurance.reference": "The method used, and the risk assessment that justifies it",
  "attest.age_assurance.hint": "The Code allows either route. Applying children's protections to everyone is a legitimate answer and is often the cheaper one for a small service.",
  "attest.child_dpia.statement": "{org} has assessed how its service affects children, treating their best interests as a primary consideration, and has recorded the conclusions by age range.",
  "attest.child_dpia.reference": "Where the assessment is recorded and when it was last revised",
  "attest.child_dpia.hint": "The regulator expects the assessment to distinguish a five-year-old from a fifteen-year-old rather than treating everyone under eighteen as one group.",
  "attest.ferpa_school.statement": "Where {org} handles education records, it does so as a school official under the direct control of the educational institution, uses the records only for the authorised purpose, and does not redisclose them without authorisation.",
  "attest.ferpa_school.reference": "The agreement that establishes the school official relationship",
  "attest.ferpa_school.hint": "This is the exception most education software relies on. Without a written agreement placing you under the school's control, the exception does not apply and the parental consent route does.",
  "home.stats.method": "The first four are counted from the product itself, not written by hand: providers and checks from the check registry, frameworks from the control catalogue, and the percentage is the mean across every framework of the controls a connected stack evidences before you answer a single question. A check is one rule. Platforms that advertise thousands of tests are usually counting a rule again for every kind of resource it touches, which is a fair way to count and a different one. See them",
  "home.stats.method.link": "framework by framework",
  "attest.bc_test.statement": "{org} has exercised its business continuity and disaster recovery plans within the last twelve months, and the result, including anything that did not work, is written down.",
  "attest.bc_test.reference": "The date of the last exercise and where the result is recorded",
  "attest.bc_test.hint": "A restore that has never been attempted is a plan, not a capability. Auditors ask for the date and the findings, not the document.",
  "attest.desc_scope.statement": "{org} has carried out the applicability review the Information Security Regulation requires, recording which of the thirteen domains and which controls apply to it and why.",
  "attest.desc_scope.reference": "Where the applicability review is recorded and when it was last revised",
  "attest.desc_scope.hint": "The regulation expects a right-fit implementation sized to the risk, so the review is the document that justifies everything you did not do.",
  "fw.iso27017.name": "ISO/IEC 27017",
  "fw.iso27017.tagline": "The cloud extension to ISO 27001. Where the provider's job ends and yours begins.",
  "fw.iso27017.summary": "ISO/IEC 27017 extends ISO/IEC 27002 with guidance for cloud services, addressed to both providers and customers. It adds seven cloud-specific controls and cloud-specific guidance on many existing ones. Its subject is the seam: who is responsible for what, how tenants are kept apart in a virtual environment, how virtual machines are hardened, how administrator operations are performed and recorded, what monitoring data the customer can actually get, and what happens to the customer's assets when the contract ends. For a company running on someone else's infrastructure it is the standard that forces the shared responsibility model out of a diagram and into a document.",
  "fw.iso27017.who": "Anyone certified to ISO 27001 who runs on public cloud, and anyone whose customer asks how the responsibility is divided. It is certified as an extension of 27001 rather than on its own.",
  "fw.iso27017.needs": "A documented shared responsibility split \xB7 Removal and return of your assets at the end of the contract \xB7 Segregation between tenants in a virtual environment \xB7 Virtual machine hardening to a known baseline \xB7 Documented administrator operations \xB7 Monitoring, with the logs you need available to you \xB7 Alignment of virtual and physical network security \xB7 Agreed cryptographic controls, including who holds the keys \xB7 Separated cloud administration access \xB7 Agreed incident responsibilities and notification",
  "fw.iso27017.snoopios": "Ten controls, all inherited from the ISO 27001 evidence already running, because 27017 is guidance layered on 27002 rather than a separate control set.",
  "fw.iso27017.youdo": "Write the responsibility split down and get your provider's half in the contract. Check you can actually export the logs you would need in an investigation, because most customers discover the gap during one.",
  "fw.iso27017.source": "https://www.iso.org/standard/43757.html",
  "fw.iso27018.name": "ISO/IEC 27018",
  "fw.iso27018.tagline": "For a processor holding other people's personal data in a public cloud.",
  "fw.iso27018.summary": "ISO/IEC 27018 is the code of practice for protecting personally identifiable information in a public cloud when you act as a processor. It sits on ISO 27001 and 27002 and adds obligations that map closely onto what a controller must contractually require of you: process only on documented instructions, never use the data for your own purposes including marketing, disclose your sub-processors and the countries the data may reach, tell the controller about a breach, encrypt personal data over public networks and on portable media, keep records of who accessed it, and put confidentiality obligations on everyone who can. It is the certificate a European or Gulf buyer asks for when they want assurance about their customers' data rather than your security generally.",
  "fw.iso27018.who": "Any software business that holds personal data on behalf of its customers, which is most of them. It is the processor-side counterpart to ISO 27701's controller clauses.",
  "fw.iso27018.needs": "Processing only on the controller's documented instructions \xB7 No use for your own purposes, including marketing \xB7 Collection limitation and secure disposal of temporary files \xB7 A schedule for return, transfer and disposal \xB7 Disclosure of sub-processors and of the countries involved \xB7 Breach notification to the controller, and records of disclosures \xB7 Encryption over public networks and on portable media \xB7 Unique identifiers and access records \xB7 Subcontracting disclosed before it begins \xB7 Confidentiality obligations on anyone with access",
  "fw.iso27018.snoopios": "Ten controls, all inherited from the ISO 27001 and UK GDPR evidence, since the obligations are the ones a data processing agreement already imposes.",
  "fw.iso27018.youdo": "Make sure the sub-processor register is current and public, because this standard turns it from good practice into a control. Confirm nothing in the product uses customer personal data for your own analytics or model training.",
  "fw.iso27018.source": "https://www.iso.org/standard/76559.html",
  "fw.iso22301.name": "ISO 22301",
  "fw.iso22301.tagline": "Business continuity as a management system, and the exercise is the point.",
  "fw.iso22301.summary": "ISO 22301 specifies a business continuity management system: the same clause structure as ISO 27001, applied to keeping the business running. Clause 8 is where the substance lives. A business impact analysis identifies the activities that must not stop and how long they can be interrupted, a risk assessment says what would stop them, strategies and solutions set recovery objectives, plans say what people actually do, and an exercise programme tests whether any of it works. That last part is what separates certification from a document: an untested plan is a hypothesis, and an auditor asks for the date of the last exercise and what it found rather than for the plan itself.",
  "fw.iso22301.who": "Software companies whose customers depend on availability, which increasingly means anyone selling to enterprise or the public sector. It is often asked for alongside ISO 27001 rather than instead of it, and the two share a management system.",
  "fw.iso22301.needs": "A defined scope and the interested parties \xB7 A policy and assigned responsibilities \xB7 Continuity objectives \xB7 Competence, awareness and documented information \xB7 A business impact analysis and risk assessment \xB7 Strategies and solutions with recovery objectives \xB7 Plans and an incident response structure \xB7 An exercise programme, with results recorded \xB7 Internal audit and management review \xB7 Correction of nonconformities",
  "fw.iso22301.snoopios": "Ten controls at clause level. Eight inherit from the ISO 27001 evidence and the continuity plan the pack already generates. Two are attestations with a date: the exercise, and the management review.",
  "fw.iso22301.youdo": "Run the exercise and write down what failed, because the finding is worth more to an auditor than a clean report. Set recovery time and recovery point objectives that your architecture can actually meet, and check them against what your hosting provider commits to.",
  "fw.iso22301.source": "https://www.iso.org/standard/75106.html",
  "fw.uaeia.name": "UAE Information Assurance Standards",
  "fw.uaeia.tagline": "The federal baseline, and the one with named cryptographic minimums.",
  "fw.uaeia.summary": "The UAE Information Assurance Standards are the federal baseline for protecting information systems, originally issued by the National Electronic Security Authority and now maintained under the country's cyber security authority. They divide into management controls, covering strategy, risk, awareness, human resources, compliance and performance, and technical controls, covering assets, access, cryptography, networks, operations, third parties, development, incidents and continuity. They are more prescriptive than most equivalents in one respect: they name cryptographic minimums, expecting AES-256 for data at rest and TLS 1.2 or better in transit, where the Qatari and Saudi authorities accept weaker with documented justification. Entities in the critical sectors are expected to comply, and the requirements reach their suppliers by contract.",
  "fw.uaeia.who": "Suppliers to UAE federal entities and to critical sector operators. It sits underneath the emirate-level regimes: a Dubai government buyer will ask about DESC's regulation, an Abu Dhabi one about its own, and both sit on this federal baseline.",
  "fw.uaeia.needs": "Strategy and planning, approved and owned \xB7 Risk assessment, treatment and acceptance \xB7 Awareness and training \xB7 Human resources security across the employment lifecycle \xB7 Legal and regulatory compliance \xB7 Performance evaluation and improvement \xB7 Asset management and classification \xB7 Access control including privileged and remote \xB7 Cryptography: AES-256 at rest, TLS 1.2 or better in transit \xB7 Communications and network security \xB7 Operations security, change and capacity \xB7 Third-party security \xB7 Secure acquisition, development and maintenance \xB7 Incident management with reporting to the authority \xB7 Business continuity",
  "fw.uaeia.snoopios": "Fifteen controls. Fourteen inherit from the ISO 27001 evidence, and the cryptographic minimums are read directly by the TLS and header checks already running against your domain. Performance evaluation is an attestation with a date.",
  "fw.uaeia.youdo": "Check your cipher configuration against the named minimums rather than assuming a modern default passes: this is one of the few standards that states the numbers. Find out which emirate-level regime your buyer also applies.",
  "fw.uaeia.source": "https://tdra.gov.ae/",
  "attest.clinical_safety.statement": "{org} has appointed a clinical safety officer who is a suitably qualified and experienced clinician, and maintains a hazard log and a clinical safety case report under DCB0129.",
  "attest.clinical_safety.reference": "The officer's name and registration, and where the hazard log lives",
  "attest.clinical_safety.hint": "Required for any health IT system placed into service in the NHS, whatever its size. The officer must be a registered clinician; the role cannot be filled by an engineer.",
  "attest.dspt_submission.statement": "{org} has submitted this year's NHS Data Security and Protection Toolkit at Standards Met, and where its supplier category requires one, has completed the independent Cyber Assessment Framework audit.",
  "attest.dspt_submission.reference": "The ODS code and the date of the submission",
  "attest.dspt_submission.hint": "The submission closes on 30 June each year. Standards Met is a contractual requirement under NHS Standard Contract clause 21.2, so without it the trust using your software is in breach.",
  "attest.accessibility.statement": "{org} has tested the product against WCAG 2.2 level AA and publishes an accessibility statement saying what conforms, what does not, and when the gaps will close.",
  "attest.accessibility.reference": "Where the accessibility statement is published, and the date it was last tested",
  "attest.accessibility.hint": "A statement claiming full conformance without a test behind it is the failure an NHS assessor finds most often.",
  "attest.cloud_location.statement": "{org} has agreed with its cloud provider where each class of data is hosted and processed, and where Saudi rules require it, that data stays inside the Kingdom.",
  "attest.cloud_location.reference": "The regions in use, and the contract clause that fixes them",
  "attest.cloud_location.hint": "The Cloud Cybersecurity Controls treat location as a control, not a preference. Get it into the contract rather than the console.",
  "fw.dtac.name": "NHS DTAC",
  "fw.dtac.tagline": "The assessment every NHS buyer runs before it can buy your software.",
  "fw.dtac.summary": "The Digital Technology Assessment Criteria is the standard set of questions an NHS organisation asks a supplier before procuring digital technology. It covers five areas: clinical safety, data protection, technical security, interoperability, and usability and accessibility. It is not a certification and there is no DTAC badge; it is a form the buyer sends and the supplier completes, and a weak answer stops the sale. Two sections catch software companies out. Clinical safety requires a nominated clinical safety officer who is a registered clinician, plus a hazard log and safety case under DCB0129, which is a discipline most product teams have never met. And the data protection section asks for the Data Security and Protection Toolkit at Standards Met, so DTAC and DSPT are answered together or not at all.",
  "fw.dtac.who": "Any company selling software into the NHS, from a trust pilot upwards. It arrives as a spreadsheet early in procurement, and the answers are reused across every trust you sell to, so it is worth answering once and well.",
  "fw.dtac.needs": "A clinical safety officer, a hazard log and a safety case under DCB0129 \xB7 A lawful basis, privacy notice, record of processing and DPIA \xB7 The DSPT at Standards Met \xB7 Encryption in transit and at rest, access control and patching \xB7 An annual penetration test with findings closed \xB7 Business continuity and disaster recovery with stated recovery objectives \xB7 Recognised interoperability standards and a documented API \xB7 WCAG 2.2 AA and a published accessibility statement",
  "fw.dtac.snoopios": "Eight controls. Four inherit the checks and documents already running for UK GDPR and ISO 27001. Four are attestations with a reference, because a clinical safety officer, a DSPT submission, a penetration test and an accessibility test are all things only you can hold.",
  "fw.dtac.youdo": "Find a clinical safety officer early; it is the longest lead time on this list and cannot be delegated to an engineer. Submit the DSPT, since DTAC asks for it directly. Get the accessibility statement tested rather than asserted.",
  "fw.dtac.source": "https://digital.nhs.uk/services/digital-technology-assessment-criteria-dtac",
  "fw.dspt.name": "NHS Data Security and Protection Toolkit",
  "fw.dspt.tagline": "Annual, contractual, and now audited. Without it your NHS customer is in breach.",
  "fw.dspt.summary": "The Data Security and Protection Toolkit is an annual self-assessment against the National Data Guardian's ten data security standards, and from 2025/26 it is aligned to the National Cyber Security Centre's Cyber Assessment Framework, which makes it outcome-based rather than a checklist. Submission closes on 30 June each year. Its force comes from contract, not regulation: Standards Met is a requirement of NHS Standard Contract clause 21.2, so an NHS organisation continuing to use a supplier without it is itself in breach. Larger IT suppliers, meaning fifty or more staff or ten million pounds of turnover, are treated as operators of essential services and must additionally complete an independent audit across eleven assertions. Together with Cyber Essentials and DTAC it forms the complete set an NHS supplier is asked for.",
  "fw.dspt.who": "Any organisation that accesses NHS patient data or provides IT to an NHS body. If you hold a trust contract you almost certainly need it, and the trust will chase you for it because their own compliance depends on yours.",
  "fw.dspt.needs": "Staff understand their responsibilities for personal confidential data \xB7 Confidentiality in contracts, with consequences \xB7 Annual data security training, recorded \xB7 Access granted on need, reviewed and removed \xB7 Incidents and near misses reviewed and acted on \xB7 Incidents reported and managed \xB7 A tested continuity plan for a data or cyber incident \xB7 No unsupported operating systems, software or browsers \xB7 A tested IT protection strategy \xB7 IT suppliers held to account \xB7 This year's submission at Standards Met, with the independent CAF audit where required",
  "fw.dspt.snoopios": "Eleven controls. Ten inherit the checks and documents already running, since the ten standards map onto ISO 27001 and UK GDPR almost line for line, and the unsupported-systems standard is answered by the same checks as Cyber Essentials patching. The submission itself is an attestation with your ODS code and date.",
  "fw.dspt.youdo": "Diarise 30 June, because a lapsed submission is a contractual breach for your customer rather than a tidy-up for you. Work out whether you are a category two supplier and therefore need the independent audit, since that has a long lead time. Keep the training records with dates: the CAF alignment made the toolkit ask for evidence rather than assertions.",
  "fw.dspt.source": "https://www.dsptoolkit.nhs.uk/",
  "fw.ccc.name": "Saudi NCA Cloud Cybersecurity Controls",
  "fw.ccc.tagline": "CCC-2:2024. Written as an extension of the ECC, and it binds the tenant as well as the provider.",
  "fw.ccc.summary": "The Cloud Cybersecurity Controls are the National Cybersecurity Authority's minimum requirements for cloud computing in Saudi Arabia, issued as an extension to the Essential Cybersecurity Controls and updated on 31 July 2025. What makes them unusual is that they bind two parties: cloud service providers and cloud service tenants. A company running its product on someone else's cloud is a tenant and carries its own set of controls, which is precisely the position of most software businesses. The controls follow the ECC's structure, adding cloud-specific requirements for shared responsibility, tenant segregation, cryptography, backup and the return of data in a usable format at the end of service. Data location is treated as a control rather than a preference, and for some classes of data and some sectors it must remain inside the Kingdom.",
  "fw.ccc.who": "Any organisation using cloud services in Saudi Arabia, and anyone selling cloud-delivered software to a Saudi government entity or critical infrastructure operator. If your customer is bound by the ECC, their contract will push these controls onto you.",
  "fw.ccc.needs": "A cloud cybersecurity strategy and policy aligned to the ECC \xB7 Roles split explicitly between provider and tenant \xB7 Cloud risk assessment before adoption and periodically after \xB7 Compliance with the applicable law \xB7 Identity and privileged access management \xB7 Protection of cloud systems and processing facilities \xB7 Network security including tenant segregation \xB7 Cryptography in transit and at rest \xB7 Backup, recovery and return of data in a usable format \xB7 Vulnerability management and penetration testing \xB7 Event logs and monitoring \xB7 Incident management with the provider's notification route agreed \xB7 Continuity for cloud services \xB7 Third-party requirements in the contract, including data removal at the end of service \xB7 Hosting location agreed, in-Kingdom where required",
  "fw.ccc.snoopios": "Fifteen controls. Fourteen inherit from the ISO 27001 evidence already running, which works because the CCC extends the ECC and the ECC was written from the same material. The hosting location is an attestation, since it is a contract term rather than a configuration.",
  "fw.ccc.youdo": "Write the shared responsibility split down: the controls assume you know which half is yours and most tenants do not. Get the data location and the end-of-service return into the contract. Check whether your sector requires in-Kingdom hosting before you choose a region.",
  "fw.ccc.source": "https://nca.gov.sa/en/regulatory-documents/controls-list/ccc/",
  "fw.nia.name": "Qatar National Information Assurance Policy",
  "fw.nia.tagline": "Qatar's security standard, and the other half of the pair with its privacy law.",
  "fw.nia.summary": "The National Information Assurance Policy is Qatar's baseline standard for protecting information, issued under the National Cyber Security Agency and applying to government agencies and to the organisations that serve them and operate critical sectors. It is built around data labelling and classification, from which the handling rules for everything else follow, then works through asset management, risk management, change management, personnel security, access control, cryptography, network security, systems acquisition and development, incident management, business continuity, third-party security and compliance audit. Its shape will be familiar to anyone who has read ISO 27001, which is deliberate. It pairs with the Personal Data Privacy Protection Law: the privacy law governs personal data, the assurance policy governs how the systems holding it are run.",
  "fw.nia.who": "Suppliers to Qatari government entities and to operators in the critical sectors, plus anyone whose Qatari customer flows the requirements down. Neither Vanta nor Drata carries it, and the enterprise buyers who ask for it tend to be substantial.",
  "fw.nia.needs": "Data labelling and classification with handling rules \xB7 Asset inventory and owners \xB7 Risk assessment and treatment \xB7 Change management \xB7 Personnel security: screening, terms and awareness \xB7 Access control with privilege management \xB7 Cryptography for stored and transmitted information \xB7 Network security and boundary protection \xB7 Secure acquisition, development and maintenance \xB7 Incident management with reporting to the authority \xB7 Business continuity \xB7 Third-party security requirements, monitored \xB7 Periodic compliance review and audit",
  "fw.nia.snoopios": "Thirteen controls. Twelve inherit from the ISO 27001 evidence already running, because the policy follows the same structure. The periodic compliance review is an attestation with a date.",
  "fw.nia.youdo": "Start with the classification scheme, because in this policy everything else hangs off it and it is the part nobody else can write for you. Keep the review dated: the compliance domain asks when, not whether.",
  "fw.nia.source": "https://www.ncsa.gov.qa/",
  "attest.sg_dpo.statement": "{org} has appointed a data protection officer as the PDPA requires and has made their business contact information publicly available.",
  "attest.sg_dpo.reference": "The DPO's business contact and where it is published",
  "attest.sg_dpo.hint": "The role can be held alongside another job and can be outsourced, but every organisation must have one and the contact must be findable.",
  "attest.in_significant.statement": "{org} has determined whether it is a Significant Data Fiduciary and, if it is, has appointed an India-based data protection officer, commissioned an independent data auditor and carried out a data protection impact assessment.",
  "attest.in_significant.reference": "The determination, and the DPO and auditor if one applies",
  "attest.in_significant.hint": "The Central Government designates significant fiduciaries on volume and sensitivity of data and risk to sovereignty and public order. Most software companies are not one, but the determination should be written down.",
  "attest.qc_officer.statement": "{org} has designated a person in charge of the protection of personal information and published their title and contact details. By default this is the person with the highest authority in the organisation unless the role has been delegated in writing.",
  "attest.qc_officer.reference": "The title and contact published, and the written delegation if any",
  "attest.qc_officer.hint": "Quebec is unusual: if you appoint nobody, the law appoints your chief executive.",
  "attest.ccpa_optout.statement": "{org} either does not sell or share personal information as California defines it, or provides a Do Not Sell or Share My Personal Information link and honours the Global Privacy Control browser signal.",
  "attest.ccpa_optout.reference": "Where the link is, or a note that nothing is sold or shared",
  "attest.ccpa_optout.hint": "Sharing includes cross-context behavioural advertising, so most analytics and advertising pixels count even where no money changes hands.",
  "fw.sgpdpa.name": "Singapore PDPA",
  "fw.sgpdpa.tagline": "Consent-based, with a named officer everyone can find and a three-day breach clock.",
  "fw.sgpdpa.summary": "Singapore's Personal Data Protection Act has applied since 2012 and was substantially amended in 2020. It is built on consent with a set of obligations around it: notification of purposes, purpose limitation, access and correction, accuracy, protection, retention limitation and transfer limitation. Two features stand out for a foreign company. Every organisation must appoint a data protection officer and publish their business contact, which is enforced and easy for the regulator to check. And since February 2021 breach notification is mandatory: the Personal Data Protection Commission within three calendar days of assessing a breach as notifiable, and affected individuals at the same time. The 2020 amendments also added exceptions for legitimate interests and business improvement, so it is no longer consent alone, and raised the financial penalty ceiling.",
  "fw.sgpdpa.who": "Any organisation collecting personal data in Singapore, including from outside it. Singapore is the usual first Asian market for a UK software business, and the DPO requirement catches people out because there is no size threshold.",
  "fw.sgpdpa.needs": "Notification of purposes at or before collection \xB7 Consent per purpose, with a withdrawal route \xB7 Purpose limitation \xB7 Access and correction requests answered \xB7 Accuracy \xB7 Reasonable security arrangements \xB7 Retention limitation \xB7 Transfer limitation with a comparable standard abroad \xB7 Breach notification to the PDPC within three days and to individuals \xB7 Written policies made available on request \xB7 A data protection officer with published contact details",
  "fw.sgpdpa.snoopios": "Eleven controls. Ten inherit the checks and documents that already evidence UK GDPR, because the obligations overlap almost completely. The data protection officer is an attestation with their published contact.",
  "fw.sgpdpa.youdo": "Appoint the officer and publish the contact, because that is the most visible failure. Tighten the breach runbook: three calendar days is shorter than seventy-two hours once a weekend is involved. Check the Do Not Call provisions separately if you send marketing messages to Singapore numbers.",
  "fw.sgpdpa.source": "https://www.pdpc.gov.sg/overview-of-pdpa/the-legislation/personal-data-protection-act",
  "fw.indpdp.name": "India DPDP Act",
  "fw.indpdp.tagline": "Act 22 of 2023 with the 2025 Rules. Consent-first, and strict about children.",
  "fw.indpdp.summary": "India's Digital Personal Data Protection Act was passed in 2023 and given effect by the DPDP Rules in 2025. It applies to digital personal data processed in India, and to processing outside India connected with offering goods or services to people in India. Consent must be free, specific, informed, unconditional and unambiguous, with a notice in English or any language in the Eighth Schedule, and it introduces the Consent Manager as a registered intermediary. Data principals get access, correction, erasure, grievance redressal and, unusually, nomination: the right to name someone to exercise their rights if they die or become incapacitated. Two duties bite hardest on software companies. Anyone under eighteen is a child, requiring verifiable parental consent, with tracking and targeted advertising to children prohibited outright. And an entity the government designates a Significant Data Fiduciary must appoint a data protection officer based in India, commission an independent audit and carry out impact assessments.",
  "fw.indpdp.who": "Any company with Indian users or customers. The under-eighteen rule makes it particularly sharp for education, gaming and consumer products, where the rest of the world draws the line at thirteen or sixteen.",
  "fw.indpdp.needs": "A notice in English or a scheduled language \xB7 Free, specific, informed, unconditional and unambiguous consent, or a legitimate use \xB7 Purpose limitation and data minimisation \xB7 Access, correction, erasure, nomination and grievance redressal \xB7 A published grievance contact \xB7 Reasonable security safeguards \xB7 Breach notification to the Data Protection Board and every affected person \xB7 Erasure when consent is withdrawn or the purpose is served \xB7 Processor contracts \xB7 Verifiable parental consent for under-eighteens, with no tracking or targeted advertising to them \xB7 Significant Data Fiduciary duties where designated",
  "fw.indpdp.snoopios": "Eleven controls. Nine inherit from the UK GDPR evidence. Two are attestations with a reference: guardian consent for under-eighteens, and whether you have been designated a Significant Data Fiduciary along with the duties that follow.",
  "fw.indpdp.youdo": "Decide how you verify parental consent, because India means under eighteen and that is a product decision rather than a policy one. Write down your Significant Data Fiduciary determination even when the answer is no. Note that breach notification has no harm threshold: every personal data breach is notifiable.",
  "fw.indpdp.source": "https://www.meity.gov.in/data-protection-framework",
  "fw.pipeda.name": "Canada PIPEDA",
  "fw.pipeda.tagline": "Ten principles rather than articles, and a breach register you must keep for two years.",
  "fw.pipeda.summary": "The Personal Information Protection and Electronic Documents Act governs personal information in the course of commercial activity across Canada, except where a province has substantially similar legislation of its own, which Quebec, Alberta and British Columbia do. Rather than numbered articles it sets ten fair information principles in Schedule 1: accountability, identifying purposes, consent, limiting collection, limiting use and disclosure and retention, accuracy, safeguards, openness, individual access, and challenging compliance. Since 2018 a breach of security safeguards must be reported to the Office of the Privacy Commissioner and to affected individuals where it creates a real risk of significant harm, and separately every breach must be recorded and the record kept for twenty-four months whether or not it was reportable. That record-keeping duty is the one most often missed.",
  "fw.pipeda.who": "Any organisation handling personal information commercially in Canada, including from abroad where there is a real and substantial connection. Reform has been discussed for years but PIPEDA remains the federal law in force.",
  "fw.pipeda.needs": "A designated accountable individual \xB7 Purposes identified at or before collection \xB7 Knowledge and consent \xB7 Collection limited to what is necessary \xB7 Limits on use, disclosure and retention \xB7 Accuracy \xB7 Safeguards proportionate to sensitivity \xB7 Openness about policies and practices \xB7 Individual access and the ability to challenge accuracy \xB7 A complaints procedure to the accountable individual \xB7 Breach reporting to the Privacy Commissioner and individuals on real risk of significant harm, and a register of every breach kept for 24 months",
  "fw.pipeda.snoopios": "Eleven controls, one for each principle plus breach. Every one inherits from the UK GDPR evidence, since the principles are the same obligations under older names.",
  "fw.pipeda.youdo": "Keep the breach register even for incidents you decide are not reportable, because the register is a separate duty from the report and is what an investigation asks for first. Check whether Quebec, Alberta or British Columbia law applies to you instead of, or as well as, the federal act.",
  "fw.pipeda.source": "https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/",
  "fw.law25.name": "Quebec Law 25",
  "fw.law25.tagline": "The strictest regime in North America, and it appoints your chief executive if you do not.",
  "fw.law25.summary": "Quebec's Law 25, originally Bill 64, came into force in stages between 2022 and September 2024 and is the most demanding privacy law in North America. It requires a designated person in charge of the protection of personal information whose title and contact are published, and if you designate nobody the role falls by default to the person with the highest authority in the organisation. It requires published governance policies, privacy by default at the highest level of confidentiality with no action by the user, a privacy impact assessment for any acquisition or overhaul of an information system and before any transfer outside Quebec, and since September 2024 a right to portability in a structured, commonly used technological format. Confidentiality incidents must be reported to the Commission d'acc\xE8s \xE0 l'information and to affected people where there is a risk of serious injury, and a register of every incident must be kept. Penalties reach twenty-five million Canadian dollars or four per cent of worldwide turnover.",
  "fw.law25.who": "Anyone doing business in Quebec, which for a software company means any Quebec customer. It applies regardless of where you are established, and the transfer assessment means hosting outside Quebec is itself a documented decision.",
  "fw.law25.needs": "A published person in charge of personal information \xB7 Published governance policies in clear language \xB7 Information at collection, including where technology identifies or profiles \xB7 Manifest, free and enlightened consent for specific purposes \xB7 Privacy by default at the highest confidentiality \xB7 Impact assessments for new systems and for transfers outside Quebec \xB7 Access, rectification, de-indexing and portability \xB7 Transparency and the right to submit observations on automated decisions \xB7 Confidentiality incident notification and a register of every incident \xB7 Assessment before transferring outside Quebec \xB7 Destruction or anonymisation when the purpose is achieved",
  "fw.law25.snoopios": "Eleven controls. Ten inherit from the UK GDPR evidence, since Law 25 was written with the GDPR open on the desk. The person in charge is an attestation, because the default rule makes it consequential: name someone, or the law has already named your chief executive.",
  "fw.law25.youdo": "Designate the person in charge and publish the title, first. Write the transfer assessment for wherever you host, since that is a Quebec-specific document with no GDPR equivalent. Check that any automated decision affecting a person can be explained and that they can reach a human.",
  "fw.law25.source": "https://www.cai.gouv.qc.ca/",
  "fw.ccpa.name": "California CCPA and CPRA",
  "fw.ccpa.tagline": "Opt-out rather than opt-in, and sharing counts even when no money changes hands.",
  "fw.ccpa.summary": "The California Consumer Privacy Act, as amended by the Privacy Rights Act, applies to for-profit businesses that do business in California and meet one of three thresholds: gross annual revenue above twenty-five million dollars, buying or selling the personal information of a hundred thousand or more consumers or households, or deriving half or more of revenue from selling or sharing personal information. It is opt-out rather than opt-in: you may collect, but a consumer can tell you to stop selling or sharing. Sharing is defined to include cross-context behavioural advertising, which catches most analytics and advertising pixels even where nothing is paid. Rights cover knowing, deleting, correcting, opting out and limiting the use of sensitive personal information, with no discrimination for exercising them. Businesses must honour the Global Privacy Control signal, contract properly with service providers, and hold personal information no longer than the disclosed purpose requires.",
  "fw.ccpa.who": "Businesses meeting one of the three thresholds. Below them the act does not apply, but American enterprise buyers routinely ask about it anyway, and other states have copied the structure closely enough that answering California answers most of them.",
  "fw.ccpa.needs": "Notice at collection with categories, purposes, sale or sharing and retention \xB7 A privacy policy refreshed at least annually \xB7 The right to know, with a twelve-month lookback \xB7 The right to delete, passed on to service providers \xB7 The right to correct \xB7 An opt-out of sale and sharing, with a link and the Global Privacy Control honoured \xB7 The right to limit use of sensitive personal information \xB7 No discrimination \xB7 Service provider and contractor contracts with the required terms \xB7 Reasonable security \xB7 Retention limited to the disclosed purpose",
  "fw.ccpa.snoopios": "Eleven controls. Ten inherit from the UK GDPR evidence, because the underlying obligations are close cousins even where the vocabulary differs. The opt-out is an attestation, since only you know whether you sell or share as California defines it.",
  "fw.ccpa.youdo": "Work out honestly whether you share for cross-context behavioural advertising, because most companies that say no are running a pixel that says yes. Honour the Global Privacy Control, which is a technical change rather than a policy one. Check the thresholds before assuming the act applies at all.",
  "fw.ccpa.source": "https://cppa.ca.gov/regulations/",
  "attest.eu_rep.statement": "{org} has appointed a representative in the Union under Article 27, or is established in the Union, or falls within the exemption for occasional processing that is not large-scale and involves no special-category data.",
  "attest.eu_rep.reference": "The representative's name and member state, or the reason none is required",
  "attest.eu_rep.hint": "A UK company offering goods or services to people in the EU, or monitoring their behaviour, usually needs one. It must be named in the privacy notice.",
  "attest.nis2_entity.statement": "{org} has determined whether it is an essential or an important entity under NIS 2, in which member state it is registered, and has registered with that state's competent authority where required.",
  "attest.nis2_entity.reference": "Essential or important, the member state, and the registration reference",
  "attest.nis2_entity.hint": "Managed service providers, cloud providers and data centre services are named in Annex I. Registration deadlines are set by each member state, not by the directive.",
  "attest.nis2_management.statement": "The management body of {org} has approved the cybersecurity risk-management measures, oversees their implementation, and has taken training sufficient to identify risks and assess management practices, as Article 20 requires.",
  "attest.nis2_management.reference": "Date of the approval and of the most recent training",
  "fw.eugdpr.name": "EU GDPR",
  "fw.eugdpr.tagline": "Regulation 2016/679. The same law as the UK's, minus the British additions, plus a representative.",
  "fw.eugdpr.summary": "The EU General Data Protection Regulation applies to any organisation established in the Union, and to any organisation outside it that offers goods or services to people in the Union or monitors their behaviour. Since Brexit the UK and EU regimes have diverged slightly but the articles are the same and so is the evidence: a lawful basis per purpose, a privacy notice, records of processing, processor contracts, security proportionate to risk, breach notification within seventy-two hours, impact assessments for high-risk processing, a data protection officer where required, and transfers on a lawful mechanism. Two things differ for a British company. There is no ICO registration fee and no Data (Use and Access) Act complaints duty, and instead Article 27 requires a representative inside the Union unless you are established there. Cookies are governed by the ePrivacy Directive as each member state implemented it, rather than by PECR.",
  "fw.eugdpr.who": "Any company selling into the EU, which for most UK software businesses means from the first Irish, German or Dutch customer. If you already evidence UK GDPR you are almost entirely there.",
  "fw.eugdpr.needs": "A lawful basis per purpose \xB7 A privacy notice naming the controller and, where required, the EU representative \xB7 Records of processing \xB7 Processor contracts and a sub-processor register \xB7 Security appropriate to the risk \xB7 Breach notification to the supervisory authority within 72 hours \xB7 A DPIA for high-risk processing \xB7 A data protection officer where required \xB7 Transfers on a lawful mechanism \xB7 Cookie consent under the local ePrivacy implementation \xB7 A representative in the Union under Article 27",
  "fw.eugdpr.snoopios": "Fifteen controls. Fourteen inherit the checks and documents that already evidence UK GDPR, because the articles are the same law. The Article 27 representative is an attestation with a reference, since only you know whether you are established in the Union or exempt.",
  "fw.eugdpr.youdo": "Decide whether you need an Article 27 representative and name them in the privacy notice. Identify your lead supervisory authority if you are established in more than one member state. Check how the country you sell into implemented the ePrivacy rules, because consent requirements are not uniform.",
  "fw.eugdpr.source": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
  "fw.nis2.name": "NIS 2 Directive",
  "fw.nis2.tagline": "Directive 2022/2555. Security duties with personal liability for management, transposed country by country.",
  "fw.nis2.summary": "NIS 2 replaced the original network and information security directive and widened it considerably. It divides organisations into essential and important entities across eighteen sectors, and Annex I names managed service providers, managed security service providers, cloud computing services, data centre services and content delivery networks, which is how a software company finds itself in scope. Article 21 sets ten minimum measures, from risk analysis and incident handling to supply chain security, cryptography and multi-factor authentication. Article 20 makes the management body approve and oversee those measures and requires them to be trained, with member states able to hold them personally liable. Article 23 requires an early warning within twenty-four hours of a significant incident and a full notification within seventy-two. Because it is a directive rather than a regulation, the detail, the registration process and the penalties come from each member state's transposition, and those differ.",
  "fw.nis2.who": "Managed service providers, cloud and hosting providers and data centre operators above the size thresholds, plus anyone in the eighteen listed sectors. Also, in practice, their suppliers: the supply chain measure pushes the requirements down a tier, so a smaller software vendor meets NIS 2 through its customer's contract long before it meets it directly.",
  "fw.nis2.needs": "Risk analysis and information system security policies \xB7 Incident handling \xB7 Business continuity, backup and crisis management \xB7 Supply chain security \xB7 Security in acquisition, development and maintenance, with vulnerability handling and disclosure \xB7 Assessment of the measures' effectiveness \xB7 Cyber hygiene and security training \xB7 Cryptography and encryption policies \xB7 Human resources security, access control and asset management \xB7 Multi-factor authentication and secured communications \xB7 Management approval, oversight and training \xB7 Early warning within 24 hours and notification within 72 \xB7 Registration with the competent authority of your member state",
  "fw.nis2.snoopios": "Thirteen controls. Ten of the eleven technical ones inherit the checks and documents that already evidence ISO 27001, because Article 21 was written from the same material. Three are attestations: whether you are essential or important and where you are registered, that your management body approved and was trained on the measures, and the periodic assessment of effectiveness.",
  "fw.nis2.youdo": "Work out which member state you register in and whether you are essential or important, because the directive does not tell you and the transpositions differ. Get the management approval and training recorded with dates, since Article 20 is the clause with personal liability attached. Build the twenty-four hour early warning into the breach runbook: it is much tighter than GDPR's seventy-two.",
  "fw.nis2.source": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
  "fw.iso27701.name": "ISO/IEC 27701",
  "fw.iso27701.tagline": "The privacy extension to ISO 27001. One certificate that covers security and personal data together.",
  "fw.iso27701.summary": "ISO/IEC 27701 extends an ISO 27001 information security management system into a privacy information management system. You cannot hold it alone: it is certified alongside or after 27001, and it adds privacy-specific requirements to the management system in clause 5, privacy-specific guidance on the Annex A controls in clause 6, and then two separate sets of obligations, clause 7 for when you act as a controller and clause 8 for when you act as a processor. Most software companies are both, depending on the data. Its value is translation: it maps its controls to GDPR articles, so an auditor and a customer can see one certificate rather than a certificate plus a separate privacy argument. It is the standard a European or Gulf enterprise buyer asks for when they want assurance about personal data specifically rather than security generally.",
  "fw.iso27701.who": "Anyone already going for ISO 27001 who processes personal data on behalf of customers, which is most software businesses. It is the cheapest way to turn a security certificate into a privacy one, because the management system is already there.",
  "fw.iso27701.needs": "An ISO 27001 management system to extend \xB7 The controller and processor roles identified, with the applicable law \xB7 Privacy risk assessment and impact assessment \xB7 Accountability for privacy, and a point of contact \xB7 Awareness and training covering personal data \xB7 Classification and handling of personal data \xB7 Access control over systems holding it \xB7 Logging and monitoring \xB7 Secure transfer \xB7 Supplier arrangements where a supplier processes it \xB7 Privacy incident management and notification \xB7 Controller duties: lawful basis, data subject rights, privacy by design, transfers \xB7 Processor duties: acting on instructions, sub-processors, assisting the controller",
  "fw.iso27701.snoopios": "Sixteen controls at clause level. Every one inherits from the ISO 27001 and GDPR evidence you already have, because that is precisely what the standard is: the same management system with the privacy requirements named. Nothing new to connect.",
  "fw.iso27701.youdo": "Get ISO 27001 first, or at the same time; 27701 cannot stand alone. Decide control and processor scope for each kind of data you hold, because clauses 7 and 8 apply differently. The certification body must be accredited for 27701 specifically, not only for 27001.",
  "fw.iso27701.source": "https://www.iso.org/standard/71670.html",
  "fw.nistcsf.name": "NIST Cybersecurity Framework 2.0",
  "fw.nistcsf.tagline": "The American vocabulary for security posture. Not certifiable, frequently demanded by name.",
  "fw.nistcsf.summary": "The NIST Cybersecurity Framework is a voluntary structure published by the United States National Institute of Standards and Technology. Version 2.0, released in February 2024, added Govern as a sixth function alongside Identify, Protect, Detect, Respond and Recover, and widened the audience from critical infrastructure to organisations of any size. Under the six functions sit categories such as asset management, identity and access control, continuous monitoring and incident recovery. There is no certification and no auditor: you assess yourself against the categories and describe your current and target profiles. Its value is as a shared language. US enterprise procurement and cyber insurers ask for a CSF profile by name, and it maps cleanly onto ISO 27001 and SOC 2, so the same evidence answers all three.",
  "fw.nistcsf.who": "Anyone selling to a US enterprise or public body, and increasingly anyone renewing cyber insurance. Also useful internally as the plain-English frame for a security programme, because its six functions are easier to explain to a board than an Annex A control list.",
  "fw.nistcsf.needs": "Govern: strategy, expectations and policy, including supply chain risk \xB7 Identify: asset inventory and risk assessment \xB7 Protect: identity and access control, data security, platform security, infrastructure resilience \xB7 Detect: continuous monitoring and adverse event analysis \xB7 Respond: incident management and reporting \xB7 Recover: recovery plan execution and communication \xB7 A current and a target profile, and the gap between them",
  "fw.nistcsf.snoopios": "Fourteen controls, shown at category level rather than across all the subcategories, because that is the level at which a buyer's questionnaire asks. Every one inherits from the ISO 27001 evidence already running, since the two map closely.",
  "fw.nistcsf.youdo": "Write the current and target profiles, which are the part of the framework nobody can generate for you: they say what your risk appetite is and where you intend to be. Nothing here is certified, so treat it as a way to structure and explain the programme rather than a badge to earn.",
  "fw.nistcsf.source": "https://www.nist.gov/cyberframework",
  "coverage.locked.title": "Not on this plan",
  "coverage.locked.body": "These regimes are not the ones you selected. They read the same checks and the same documents you already have, so switching to one costs you no setup. The pack decides which questions get answered, not what Snoopios looks at.",
  "coverage.locked.cta": "See what each plan includes",
  "settings.password.title": "Password",
  "settings.password.body": "Changing it signs out nothing else, because a session is per browser. If you think someone else has one, change the password and then delete the account's other sessions by signing out everywhere from each device.",
  "settings.password.current": "Current password",
  "settings.password.new": "New password",
  "settings.password.confirm": "Confirm new password",
  "settings.password.submit": "Change password",
  "settings.password.saved": "Password changed.",
  "settings.password.error": "The password could not be changed. Try again.",
  "settings.password.error.current": "That current password is not right.",
  "settings.password.forgot": "Forgotten it? Sign out and use the reset link on the sign-in page.",
  "settings.rights.title": "Your data and your rights",
  "settings.rights.body": "Snoopios holds your name, your email address, the organisation and projects you created, the evidence your checks collected, and the documents you uploaded. What each connected service is read for is listed in the privacy notice.",
  "settings.rights.list": "Get a copy of everything, using the download above \xB7 Correct your name here, or ask us to correct anything else \xB7 Delete the account and everything in it, below \xB7 Object to a use, or ask us to restrict one, by email \xB7 Ask a question about any of it and get an answer within one month",
  "settings.rights.notice": "Read the privacy notice",
  "settings.rights.contact": "Ask about your data",
  "settings.complaints.title": "If you are unhappy with how we handle it",
  "settings.complaints.body": "Write to us first at the address above and we will answer within 30 days, telling you what we did and why. If our answer does not satisfy you, you can complain to the Information Commissioner's Office, the UK regulator, at ico.org.uk, and complaining to us first does not affect that right.",
  "settings.complaints.ico": "Complain to the ICO",
  "tier.free.f5": "Documents are drafted but cannot be exported",
  "tier.solo.f6": "Ingest keys for `npx snoopios run --push` from your own machine or CI",
  "tier.studio.f5": "Provider reports page for the controls your hosts hold, not you",
  "tier.scale.f6": "Priority support",
  "home.nav.install": "Install app",
  "home.screens.pick": "Choose a screen",
  "home.screens.screen": "Screen",
  "home.screens.prev": "Previous screen",
  "home.screens.next": "Next screen",
  "home.screens.pause": "Pause the show",
  "home.screens.play": "Play the show",
  "home.stats.baseline": "of controls evidenced before you answer a question",
  "home.nav.label": "Site",
  "home.nav.menu": "Open menu",
  "home.nav.close": "Close menu",
  "home.nav.cli": "CLI",
  "home.stats.providers": "providers, from hosting to payroll",
  "home.stats.checks": "checks, one rule each, never a model",
  "home.stats.frameworks": "frameworks, UK, EU, US and Gulf",
  "home.stats.readonly": "reachable to full coverage, from one place",
  "home.checks.body": "Every provider a small software team actually runs on, grouped by what it does in your business rather than by where it sits in a diagram. Product connectors run hourly from our side with a read-only credential. CLI providers run on your own machine with npx snoopios and never send a token anywhere.",
  "home.checks.cli": "Runs on the CLI",
  "home.checks.count": "checks",
  "home.role.hosting": "Hosting and edge",
  "home.role.database": "Databases and storage",
  "home.role.code": "Code and CI",
  "home.role.identity": "Identity and workspace",
  "home.role.monitoring": "Monitoring and on-call",
  "home.role.payments": "Payments",
  "home.role.domain": "Domain and email",
  "home.frameworks.body": "Thirty-six frameworks evidenced control by control from the same checks and documents, from UK GDPR to the seven Gulf data protection laws, the security standards, the AI regimes and the children's codes. Grouped into regimes, so you buy the one that applies to you rather than picking standards off a list.",
  "vault.title": "Documents",
  "vault.intro": "Everything you hold that no check can read: signed policies, certificates, penetration test reports, contracts, training records, insurance. Upload each once and link it to every control it evidences, across every framework. A dated document reminds you thirty days before it lapses and stops counting the day after.",
  "vault.count.documents": "documents",
  "vault.count.expiring": "expiring within thirty days",
  "vault.count.expired": "expired",
  "vault.upload.title": "Add a document",
  "vault.upload.body": "Give it a title, a kind and its dates, then tick the controls it evidences. Each link gets the same deterministic review as the locker: dated, owned, approved, names your organisation, mentions the control's topics. No model decides.",
  "vault.upload.submit": "Upload and link",
  "vault.field.file": "File",
  "vault.field.title": "Title",
  "vault.field.title.placeholder": "Penetration test report 2026",
  "vault.field.kind": "Kind",
  "vault.field.issued": "Issued on",
  "vault.field.expires": "Expires on",
  "vault.field.expires.hint": "Leave blank for a document that does not lapse. Certificates, insurance and test reports usually do.",
  "vault.kind.policy": "Policy or procedure",
  "vault.kind.certificate": "Certificate",
  "vault.kind.report": "Report or assessment",
  "vault.kind.contract": "Contract or agreement",
  "vault.kind.register": "Register or record",
  "vault.kind.training": "Training record",
  "vault.kind.insurance": "Insurance",
  "vault.kind.other": "Other",
  "vault.state.undated": "No expiry",
  "vault.state.current": "Valid until",
  "vault.state.expiring": "Expires in",
  "vault.state.days": "days",
  "vault.state.expired": "Expired",
  "vault.links.title": "Controls this document evidences",
  "vault.links.hint": "Open a framework and tick its controls. One document can back the same duty in several frameworks.",
  "vault.links.already": "linked",
  "vault.links.none": "Not linked to any control yet, so it evidences nothing.",
  "vault.link.title": "Link more controls to",
  "vault.link.submit": "Link the ticked controls",
  "vault.link.cancel": "Cancel",
  "vault.link.more": "Link controls",
  "vault.unlink": "Unlink",
  "vault.list.title": "Your documents",
  "vault.empty": "No documents yet. The first is usually a signed information security policy or a penetration test report.",
  "vault.uploaded": "uploaded",
  "vault.issued": "issued",
  "vault.footer": "Files are stored encrypted in the same private bucket as check evidence, under your organisation, and leave with your account. The review reads the file once at upload and once per later link; the text is never stored.",
  "vault.notice.added": "Document added.",
  "vault.notice.linked": "controls linked",
  "vault.notice.passed": "reviewed as pass",
  "vault.notice.unlinked": "Link removed.",
  "vault.notice.removed": "Document removed, with its links.",
  "vault.notice.dates": "The expiry date is before the issue date.",
  "vault.notice.nolinks": "Tick at least one control to link.",
  "vault.open": "Documents",
  "coverage.group.other": "Other frameworks",
  "coverage.to100.title": "What gets this to 100%",
  "coverage.to100.none": "Everything is evidenced.",
  "coverage.to100.attest": "Confirm the statement",
  "coverage.to100.attach": "Attach a document",
  "coverage.to100.reports": "Attach your hosts' reports",
  "coverage.to100.more": "more",
  "coverage.documents.hint": "Upload once, link to every control it evidences:",
  "notify.documents.subject": "Documents expiring soon:",
  "notify.documents.body": "These documents in the vault lapse within thirty days, or already have, for",
  "notify.documents.in": "in",
  "notify.documents.days": "days",
  "notify.documents.expired": "expired",
  "notify.documents.footer": "An expired document stops evidencing its controls. Upload the renewed one at",
  "attest.pentest.statement": "{org} has its internet-facing services penetration tested by an independent party at least once a year, and every finding is tracked to closure.",
  "attest.pentest.reference": "Date of the last test and who ran it",
  "attest.pentest.hint": "A scan is not a test. Name the firm or the individual and the month.",
  "attest.support.statement": "{org} publishes, for every supported version of its software, what support and maintenance the customer gets and for how long, including how security updates reach them.",
  "attest.support.reference": "Where the support statement is published",
  "attest.eol.statement": "{org} gives customers at least a year's notice before a version of its software stops receiving security updates.",
  "attest.eol.reference": "Where the support lifecycle is published, or the words 'no version has been retired yet'",
  "attest.eol.hint": "A continuously deployed SaaS with one live version still needs the statement: it says what happens if the service is withdrawn.",
  "fw.ecc.name": "Saudi NCA Essential Cybersecurity Controls",
  "fw.ecc.tagline": "ECC-2:2024. The baseline your Saudi government and critical-infrastructure customers must impose on you.",
  "fw.ecc.summary": "The Essential Cybersecurity Controls are the National Cybersecurity Authority's minimum requirements for cybersecurity in Saudi Arabia. ECC-2:2024 replaces ECC-1:2018 and has four domains (governance, defence, resilience, and third-party and cloud), 28 subdomains, 108 main controls and 92 subcontrols; the old industrial control systems domain moved to the separate OTCC. It binds government agencies and their affiliated companies inside and outside the Kingdom, and private entities that own, operate or host critical national infrastructure. The NCA strongly encourages every other entity in the Kingdom to adopt it. Compliance is evaluated by self-assessment, periodic reports from the NCA's assessment and compliance tool, and field audits. Subdomain 4-1 requires those entities to write cybersecurity requirements into every third-party contract, including incident communication, secure data removal at the end of service, and an obligation on the supplier to follow the entity's policies, and subdomain 4-2 does the same for cloud and hosting, which is how the ECC reaches a SaaS vendor.",
  "fw.ecc.who": "Directly: Saudi government entities, their subsidiaries and critical infrastructure operators. In practice: any software company selling to them, because the ECC obliges the buyer to flow its requirements down to you and to review them periodically. Sector regulators build on it: SAMA for finance, the NCA's CCC for critical systems, and the CST for telecoms.",
  "fw.ecc.needs": "A cybersecurity strategy, policies, defined roles and a periodic review \xB7 Risk management and security in projects \xB7 HR security, awareness and training \xB7 Asset management, identity and access, system hardening \xB7 Email, network, mobile device, data and cryptographic protection \xB7 Backup, vulnerability management and annual penetration testing \xB7 Event logging and monitoring, incident and threat management \xB7 Physical security \xB7 Web application security \xB7 Business continuity with cybersecurity resilience \xB7 Third-party contract requirements and cloud and hosting requirements, with the data returned or removed at the end of service",
  "fw.ecc.snoopios": "The 28 subdomains as controls. Twelve carry automated checks inherited from the ISO 27001 controls they were written from: access, hardening, email and network, cryptography, backups, vulnerability management, logging, incidents, continuity and supplier controls all read your connected stack hourly. Thirteen are covered by the pack's documents. Physical security is a provider-held control answered by your hosts' reports. Periodic review and penetration testing are attestations with a reference. The full 108 controls are not enumerated: a vendor answers a buyer's ECC questionnaire at subdomain level, and the questionnaire answer bank gives you the wording.",
  "fw.ecc.youdo": "Book the annual penetration test. Keep the strategy and review cadence real, because the NCA's tool asks for dates. Expect Saudi buyers to require managed security operations located in the Kingdom and data returned in a usable format when a contract ends: put both in your contract template before they ask.",
  "fw.ecc.source": "https://cdn.nca.gov.sa/api/files/public/upload/86e09090-44e4-481f-bc28-355673607654_ECC--2024-EN.pdf",
  "fw.sscop.name": "UK Software Security Code of Practice",
  "fw.sscop.tagline": "DSIT and NCSC, May 2025. Fourteen principles for anyone who sells software.",
  "fw.sscop.summary": "The Software Security Code of Practice is a voluntary code published by the Department for Science, Innovation and Technology on 7 May 2025, co-designed with the National Cyber Security Centre, and updated in January 2026. It sets fourteen principles in four themes for organisations that develop or sell software to businesses: secure design and development, build environment security, secure deployment and maintenance, and communication with customers. A self-assessment form accompanies it using principles-based assurance, and the government is developing a certification scheme on top of it. It is the successor to the thinking behind the Cyber Security and Resilience Bill's supply-chain duties, and the document UK buyers will increasingly attach to a software procurement.",
  "fw.sscop.who": "Every software vendor selling into the UK, from a two-person SaaS to an enterprise supplier. It is voluntary today; buyers, insurers and the coming certification scheme are what make it matter. If you sell to the public sector or to a regulated company, expect the self-assessment in the next security questionnaire.",
  "fw.sscop.needs": "Follow an established secure development framework \xB7 Know what third-party components you ship and assess their risk \xB7 Test software and updates before release \xB7 Secure by design and by default \xB7 Protect the build environment against unauthorised access \xB7 Control and log build changes \xB7 Distribute software securely \xB7 Publish a vulnerability disclosure process \xB7 Detect, prioritise and manage vulnerabilities \xB7 Report vulnerabilities to relevant parties \xB7 Ship timely security updates and notifications \xB7 Tell customers what support and maintenance they get \xB7 Give a year's notice of end of support \xB7 Tell customers about notable incidents",
  "fw.sscop.snoopios": "Fourteen controls. Ten carry automated checks inherited from the ISO 27001 and Cyber Essentials controls that cover the same ground: branch protection and reviews, dependency updates and vulnerability alerts, secret scanning, build access, TLS, security.txt and on-call coverage. Two are covered by the secure development document. The two customer-communication principles about support levels and end-of-support notice are attestations with a reference to where you publish them.",
  "fw.sscop.youdo": "Publish a support statement and a lifecycle policy, even for a single continuously deployed version. Keep the disclosure process answered. Fill in the government's self-assessment form; Snoopios gives you the evidence for each principle, not the form.",
  "fw.sscop.source": "https://www.gov.uk/government/publications/software-security-code-of-practice/software-security-code-of-practice",
  "fw.isr.name": "Dubai Information Security Regulation (DESC ISR)",
  "fw.isr.tagline": "Dubai government's security standard. Reaches suppliers through the entities it binds.",
  "fw.isr.summary": "The Information Security Regulation is the Dubai Electronic Security Center's standard for all Dubai Government entities, formalised under Resolution No. 13 of 2012 and maintained by DESC under Dubai Law No. 11 of 2014. It covers thirteen domains grouped into governance, operation and assurance, sets minimum requirements for information security controls, and is technology neutral. It applies to every Dubai Government entity and to the consultants, contractors and visitors engaged with it, and to government information in any medium. Entities run an applicability review, size the controls to the risk assessment, and keep the cost of controls below the value of the information protected. DESC also publishes an IoT Security Standard, an ICS standard, a biomedical devices standard, a connected vehicle standard and web security policies, and runs a Cloud Service Provider Security Standard for providers hosting government data. The regulation itself is issued to entities on request rather than posted publicly, so this guide is written from DESC's own description.",
  "fw.isr.who": "Dubai Government and semi-government entities directly. Suppliers, cloud providers and contractors indirectly: a Dubai government customer will send you its ISR-derived requirements, and a cloud provider hosting government data needs DESC's CSP certification. A UK or GCC SaaS selling to Dubai government should expect an ISO 27001-shaped questionnaire with Dubai specifics on data location and incident reporting.",
  "fw.isr.needs": "Governance: information security management, information asset management, risk management \xB7 Operation: incident and problem management, access management, operations and communications security, system acquisition and development, cryptography, business continuity \xB7 Assurance: human resources security, physical and environmental security, third-party and supplier management, compliance and audit \xB7 An applicability review against the thirteen domains \xB7 Alignment with the DESC CSP Security Standard for anyone hosting government data",
  "fw.isr.snoopios": "Not evidenced as its own framework: the regulation is distributed on request and versioned by DESC, and its thirteen domains follow ISO 27001, which Snoopios already evidences control by control. Use the ISO 27001 coverage and the questionnaire answer bank for a Dubai government supplier assessment, and the UAE PDPL framework for the personal data side.",
  "fw.isr.youdo": "Ask the customer for the ISR-derived supplier requirements rather than guessing at the regulation. Decide early whether government data will be hosted in the UAE. If you are a hosting provider, DESC's CSP Security Standard certification is the badge the buyer will ask for.",
  "fw.isr.source": "https://www.desc.gov.ae/regulations/standards-policies/",
  "attest.regulations_watch.statement": "{org} checks the UAE Data Office for the Executive Regulations, the penalty schedule and the adequacy list at least every quarter, and will update its breach deadline and transfer basis when they are issued.",
  "attest.regulations_watch.reference": "Date last checked",
  "attest.autonomous.statement": "{org} keeps a record of every autonomous or semi-autonomous system, including generative AI, that it uses to process personal data, with the purpose, the human oversight and the data involved, as DIFC Regulation 10 asks, or uses none.",
  "attest.autonomous.reference": "Where the record lives, or the words 'none used'",
  "attest.autonomous.hint": "The AI inventory on the roadmap will generate this record from your connected providers.",
  "attest.qfc_regime.statement": "{org} is not established in the Qatar Financial Centre, or it follows the QFC Data Protection Regulations 2021 and has notified the QFC Data Protection Office.",
  "attest.qfc_regime.reference": "QFC licence number, or the words 'not in the QFC'",
  "attest.ksa_register.statement": "{org} is registered on the Saudi National Register of Controllers because the law requires it, or has recorded why registration is not required for its processing.",
  "attest.ksa_register.reference": "Registration certificate number, or the reason registration is not required",
  "attest.ksa_register.hint": "Registration is mandatory for public entities, businesses whose main activity is processing personal data, and anyone processing sensitive data. Certificates run up to five years.",
  "attest.difc_notify.statement": "{org} has filed this year's notification of processing with the DIFC Commissioner of Data Protection and paid the fee.",
  "attest.difc_notify.reference": "DIFC registration number",
  "attest.adgm_register.statement": "{org} is registered as a controller with the ADGM Registration Authority and has renewed the registration for the current year.",
  "attest.adgm_register.reference": "ADGM registration number",
  "attest.bahrain_notify.statement": "{org} has notified the Bahrain Personal Data Protection Authority of its automated processing, holds prior authorisation for any sensitive, biometric, genetic or monitoring processing, and has appointed a representative in Bahrain if it is established elsewhere.",
  "attest.bahrain_notify.reference": "Notification or authorisation reference",
  "attest.bahrain_notify.hint": "Notification may be waived where an accredited Data Protection Guardian is appointed; record the Guardian's registration instead.",
  "attest.oman_permit.statement": "{org} holds a permit from the Ministry of Transport, Communications and Information Technology for every category of sensitive personal data it processes in Oman, or processes none.",
  "attest.oman_permit.reference": "Permit reference, or the words 'none processed'",
  "attest.oman_permit.hint": "The Ministry decides within 45 days; silence is a refusal.",
  "attest.qatar_permit.statement": "{org} holds a permit from the National Cyber Governance and Assurance Affairs for any personal data of special nature it processes in Qatar, or processes none.",
  "attest.qatar_permit.reference": "Permit reference, or the words 'none processed'",
  "attest.qatar_permit.hint": "Data of special nature includes children's data, health, ethnic origin, religion, marital status and criminal record.",
  "attest.guardian_consent.statement": "{org} obtains a parent's or legal guardian's consent before processing a child's personal data, and uses that data only in the child's best interest.",
  "attest.guardian_consent.reference": "Where the consent flow lives (a screen, a form, a school agreement)",
  "attest.guardian_consent.hint": "If no children use the product, say so here and the control is answered.",
  "fw.uae.name": "UAE Personal Data Protection Law",
  "fw.uae.tagline": "Federal Decree-Law 45 of 2021. In force since 2022, still waiting for its regulations.",
  "fw.uae.summary": "The UAE's federal data protection law took effect on 2 January 2022 and created the UAE Data Office as regulator. It follows the GDPR's shape: notices, a lawful basis per purpose with consent as the default, records of processing, processor contracts, security, breach notification, impact assessments, a data protection officer for high-risk processing, and rights answered within a month. Two things make it unusual. Its Executive Regulations, which set the breach deadline, the penalties and the adequacy list, had still not been issued as of September 2026, so the law's six-month compliance clock has never formally started. And it does not apply inside the DIFC and ADGM free zones, which have their own laws, nor to health and banking data covered by sector rules.",
  "fw.uae.who": "Any company established in the UAE mainland that processes personal data, and any company outside the UAE processing data about people in the UAE. If your entity sits in the DIFC or ADGM, read those guides instead; if you are a UK company selling into Dubai or Abu Dhabi, this law reaches you.",
  "fw.uae.needs": "A notice before collection covering purposes, recipients, retention, rights and transfers \xB7 Consent per purpose unless a listed exception applies; there is no general legitimate-interests basis \xB7 A record of processing activities \xB7 Written contracts with processors \xB7 Security proportionate to the risk \xB7 Breach notification to the Data Office immediately on becoming aware, and to affected people \xB7 A DPIA for high-risk processing and new technologies \xB7 A DPO where processing is high-risk or large-scale sensitive \xB7 Rights answered within a month, extendable \xB7 Transfers only to adequate countries, under contract, or with explicit consent \xB7 Explicit consent and a DPIA for sensitive data",
  "fw.uae.snoopios": "Thirteen controls. Twelve are evidenced by the same hourly checks that evidence UK GDPR security and access, and by the privacy notice, record of processing, sub-processor register, retention schedule, breach runbook, requests procedure and DPIA draft generated from your connected stack. One is an attestation with a date: that you are watching the Data Office for the Executive Regulations, penalties and adequacy list, so the framework says they are pending rather than pretending they exist.",
  "fw.uae.youdo": "Choose a lawful basis per purpose knowing that consent is the default and legitimate interests is not available. Decide whether your processing triggers the DPO duty. Keep a UAE-specific eye on the Data Office: when the regulations land, the deadlines in your breach runbook may need changing.",
  "fw.uae.source": "https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws",
  "fw.difc.name": "DIFC Data Protection Law",
  "fw.difc.tagline": "Law No. 5 of 2020, amended 2022 and 2025. The Gulf's closest cousin to the GDPR.",
  "fw.difc.summary": "The Dubai International Financial Centre has its own data protection law, regulator (the Commissioner of Data Protection) and courts. It has six lawful bases including legitimate interests, GDPR-style rights, a record of processing, breach notification as soon as practicable, DPIAs, a UAE-resident DPO for high-risk processing with an annual assessment filed, and transfers under an adequacy list or safeguards, with a documented assessment of remedies in the recipient country since the 2025 amendment. Every controller and processor files an annual notification of processing with the Commissioner. Since 15 July 2025 individuals can sue directly in the DIFC Courts, and Regulation 10 covers the ethical use of autonomous and generative AI systems.",
  "fw.difc.who": "Any company established in the DIFC, and any company processing personal data within the DIFC as part of a stable arrangement, wherever it is based. Many Dubai tech companies and their UK parents are here without realising the free zone has its own law.",
  "fw.difc.needs": "Annual notification of processing to the Commissioner, with the fee \xB7 A lawful basis per purpose from the six \xB7 A privacy notice naming the Commissioner as the complaints route \xB7 Record of processing, available for inspection \xB7 Processor contracts \xB7 Security measures \xB7 Breach notification to the Commissioner as soon as practicable \xB7 DPIAs for high-risk processing \xB7 A UAE-resident DPO where required, with an annual assessment \xB7 Transfers under the adequacy list or safeguards plus a remedies assessment \xB7 Rights within a month \xB7 Regulation 10 documentation for autonomous and AI systems",
  "fw.difc.snoopios": "Thirteen controls. Eleven are evidenced by the same checks and documents as UK GDPR, because the law was written on the same pattern. Two are attestations with a reference: the annual notification with your DIFC registration number, and the Regulation 10 record of autonomous and AI systems, which the AI inventory on the roadmap will generate.",
  "fw.difc.youdo": "File the notification every year and diarise it. Appoint the DPO if your processing is high-risk. Document the remedies assessment for each transfer destination, including back to a UK parent.",
  "fw.difc.source": "https://www.difc.com/business/laws-and-regulations/data-protection",
  "fw.adgm.name": "ADGM Data Protection Regulations 2021",
  "fw.adgm.tagline": "Abu Dhabi Global Market's law. GDPR-shaped, with paid annual registration.",
  "fw.adgm.summary": "Abu Dhabi Global Market's Data Protection Regulations 2021 apply to every ADGM-established controller and processor, and to others processing within the ADGM. They mirror the GDPR: six lawful bases, rights, records of processing, processor contracts, security, breach notification within 72 hours where feasible, DPIAs with prior consultation of the Commissioner where residual risk stays high, a UAE-resident DPO for large-scale monitoring or special-category processing, and transfers under the Commissioner's adequacy list, ADGM standard contractual clauses or binding corporate rules. Every entity registers as a controller with the Registration Authority and renews yearly, with a USD 300 fee from 2025. Fines reach USD 28 million and individuals can claim compensation.",
  "fw.adgm.who": "Any company licensed in the ADGM, from a two-person fintech to a fund. UK founders setting up in Abu Dhabi usually land here.",
  "fw.adgm.needs": "Annual registration with the Registration Authority \xB7 A lawful basis per purpose \xB7 A privacy notice \xB7 Record of processing \xB7 Processor contracts \xB7 Security measures \xB7 Breach notification within 72 hours \xB7 DPIAs and Commissioner consultation for high residual risk \xB7 A UAE-resident DPO where required \xB7 Transfers under the adequacy list or ADGM clauses \xB7 Rights within the statutory period",
  "fw.adgm.snoopios": "Twelve controls. Eleven are evidenced by the same checks and documents as UK GDPR. Registration is an attestation with your ADGM registration number.",
  "fw.adgm.youdo": "Register and renew every year. Decide whether you need the DPO. Use the ADGM's own clauses for transfers rather than EU ones.",
  "fw.adgm.source": "https://www.adgm.com/operating-in-adgm/office-of-data-protection",
  "fw.ksa.name": "Saudi Personal Data Protection Law",
  "fw.ksa.tagline": "Royal Decree M/19, enforced since September 2024. The region's most demanding regime.",
  "fw.ksa.summary": "Saudi Arabia's PDPL, regulated by SDAIA, has been enforced since 14 September 2024 with Implementing Regulations and Transfer Regulations behind it. It reaches any processing in the Kingdom and any processing of Saudi residents' data from outside. Consent is the default basis, with a documented legitimate-interests basis added in 2023 for non-sensitive data. Sensitive data includes location and credit data, needs explicit consent and can never be used for marketing. A privacy policy with prescribed content is mandatory. Breaches go to SDAIA within 72 hours through the National Data Governance Platform. Rights are answered within 30 days. Certain controllers must register on the National Register of Controllers and register their DPO. Transfers need an adequacy decision, standard clauses, binding common rules or certification, plus a documented transfer risk assessment; sector localisation for banking, telecoms, health and government overrides it. Fines reach SAR 5 million, doubled for repeat, and decisions are published.",
  "fw.ksa.who": "Any company selling to people or businesses in Saudi Arabia, and any Saudi-established company. Startups launching in Riyadh under a foreign licence are in scope from day one, and the Kingdom's cloud rules may also decide where the database has to live.",
  "fw.ksa.needs": "A privacy policy with the prescribed content, before collection \xB7 Consent per purpose, or a documented legitimate interest for non-sensitive data \xB7 Explicit consent for sensitive data, never for marketing \xB7 Guardian consent for children \xB7 A record of processing kept five years \xB7 Processor contracts \xB7 Security to NCA and SDAIA standards \xB7 Breach notification to SDAIA within 72 hours \xB7 A DPIA for new products and sensitive data \xB7 A DPO where the 2024 rules require, registered on the platform \xB7 Registration on the National Register of Controllers where required \xB7 Rights answered within 30 days \xB7 Transfers with a lawful mechanism and a transfer risk assessment \xB7 Data destroyed when its purpose ends",
  "fw.ksa.snoopios": "Fifteen controls. Thirteen are evidenced by the same checks and documents as UK GDPR, with the sensitive-data and destruction controls carried by the DPIA draft, the privacy notice and the retention schedule the pack generates. Two are attestations with a reference: registration on the National Register, and guardian consent for children.",
  "fw.ksa.youdo": "Decide whether you must register on the National Register and do it before you launch. Check whether your sector or customers require in-Kingdom hosting, because that decides your database region. Write the transfer risk assessment for data flowing back to the UK or EU. Make sure your privacy policy has every item the regulations list.",
  "fw.ksa.source": "https://sdaia.gov.sa/en/SDAIA/about/Pages/RegulationsAndPolicies.aspx",
  "fw.qatar.name": "Qatar Personal Data Privacy Protection Law",
  "fw.qatar.tagline": "Law No. 13 of 2016. The Gulf's first, with a permit system for sensitive data.",
  "fw.qatar.summary": "Qatar's law has applied since February 2017 and is regulated by the National Cyber Governance and Assurance Affairs within the National Cyber Security Agency, which issued fourteen guidelines in 2020 and 2021 in place of regulations. Consent is the default basis with exceptions including a legitimate-purposes basis. Data of special nature, which expressly includes children's data alongside health, ethnic origin, religion, marital status and criminal record, needs a prior permit from the regulator and explicit consent. The guidelines expect breach notification to the regulator and affected people within 72 hours where serious harm is possible, an impact assessment for special-nature data, and an internal complaints channel. Fines reach QAR 1 million, or QAR 5 million for special-nature data, transfers and children. The Qatar Financial Centre has its own GDPR-style regulations with a Data Protection Office, 72-hour breach notice, 30-day rights and fines to USD 1.5 million.",
  "fw.qatar.who": "Any company processing personal data electronically in Qatar. Education and family products are squarely in scope because children's data is data of special nature and needs a permit. Companies in the Qatar Financial Centre follow the QFC regulations instead.",
  "fw.qatar.needs": "A notice before processing and an internal complaints channel \xB7 Consent per purpose or a listed exception \xB7 A permit from the regulator before processing any data of special nature, including children's \xB7 Express guardian approval for children \xB7 Security precautions per the guidelines \xB7 Processor contracts \xB7 Breach notification within 72 hours where serious harm is possible \xB7 An impact assessment for special-nature and high-risk processing \xB7 A privacy contact \xB7 Transfers that cause no serious harm, with the regulator involved for special-nature data \xB7 A retention schedule",
  "fw.qatar.snoopios": "Fourteen controls. Eleven are evidenced by the same checks and documents as UK GDPR. Three are attestations with a reference: the special-nature permit, guardian consent, and whether the separate QFC regime applies to your entity.",
  "fw.qatar.youdo": "If you process children's data or any other special-nature data in Qatar, apply for the permit before launch. Set up the complaints channel. Decide whether the QFC regime applies to your entity.",
  "fw.qatar.source": "https://www.ncsa.gov.qa/",
  "fw.bahrain.name": "Bahrain Personal Data Protection Law",
  "fw.bahrain.tagline": "Law No. 30 of 2018 with the 2022 resolutions. Notify the Authority before you process.",
  "fw.bahrain.summary": "Bahrain's law has applied since August 2019 with the Personal Data Protection Authority as regulator and ten ministerial resolutions of 2022 filling in the detail. It is GDPR-like in its bases, rights and records, and unusual in two ways: automated processing must be notified to the Authority before it starts, and sensitive, biometric or genetic data, monitoring, and transfers to non-listed countries need prior authorisation. Foreign controllers using means in Bahrain must appoint a local representative. Breaches go to the Authority within 72 hours. Transfers are free to a list of about 83 adequate jurisdictions including the EU, UK, US and GCC. A Data Protection Guardian is mandatory where the Authority prescribes, which now includes financial institutions. Individuals can face criminal liability, and companies fines of BHD 20,000 and more.",
  "fw.bahrain.who": "Any company established in Bahrain, and any foreign company processing personal data with means in Bahrain. Manama's fintech scene and any SaaS with Bahraini customers whose processing runs there.",
  "fw.bahrain.needs": "Notification to the Authority before automated processing starts \xB7 Prior authorisation for sensitive, biometric or genetic data, monitoring and non-listed transfers \xB7 A representative in Bahrain for foreign controllers \xB7 A lawful basis per purpose \xB7 A notice before processing \xB7 A register of processing operations \xB7 Processor contracts \xB7 Security measures per Resolution 43 \xB7 Breach notification within 72 hours \xB7 A Guardian where prescribed \xB7 Rights answered within the resolution's period \xB7 Transfers to listed jurisdictions or with approval \xB7 Retention limits",
  "fw.bahrain.snoopios": "Fourteen controls. Thirteen are evidenced by the same checks and documents as UK GDPR. The notification, authorisation and representative duty are one attestation with a reference.",
  "fw.bahrain.youdo": "Notify the Authority before you switch anything on, and apply for authorisation if you touch sensitive data or monitoring. Appoint a representative if you are established abroad. Check the adequacy list before each transfer destination.",
  "fw.bahrain.source": "https://www.pdp.gov.bh/",
  "fw.oman.name": "Oman Personal Data Protection Law",
  "fw.oman.tagline": "Royal Decree 6/2022, fully enforceable since February 2026. Consent first, permits for sensitive data.",
  "fw.oman.summary": "Oman's law took effect in February 2023 and its Executive Regulation became fully enforceable on 5 February 2026 after an extended grace period. The regulator is the Ministry of Transport, Communications and Information Technology. Explicit, informed consent is the basis for processing, with only narrow statutory exclusions. Sensitive data (genetic, biometric, health, race, sexual life, beliefs, criminal record) may not be processed without a Ministry permit, decided within 45 days with silence meaning refusal. Children under 18 need guardian approval unless the processing is in their best interest. Controllers designate a data protection officer with published contact details, keep records, report breaches to the Ministry and affected people within 72 hours, and answer rights within 45 days. Transfers need equivalent protection and explicit consent, with Cyber Defence Centre approval for sensitive data. Fines run to OMR 500,000 for unlawful transfers.",
  "fw.oman.who": "Any company processing personal data in Oman. Education, health-adjacent and family products need the permit conversation before launch.",
  "fw.oman.needs": "Explicit, informed consent per purpose \xB7 A notice with the DPO's contact details \xB7 A Ministry permit before any sensitive data \xB7 Guardian approval for children under 18 \xB7 A designated DPO \xB7 A record of processing \xB7 Processor contracts \xB7 Security measures per the Regulation \xB7 Breach notification within 72 hours to the Ministry and affected people \xB7 An impact assessment before high-risk processing \xB7 Rights answered within 45 days \xB7 Transfers only with equivalent protection and consent \xB7 Data deleted when its purpose ends",
  "fw.oman.snoopios": "Fourteen controls. Twelve are evidenced by the same checks and documents as UK GDPR. The sensitive-data permit and guardian consent are attestations with a reference.",
  "fw.oman.youdo": "Apply for the permit before processing any sensitive data, and allow 45 days. Name the DPO and publish the contact. Build the consent flow as the primary basis rather than relying on contract or interests.",
  "fw.oman.source": "https://www.mtcit.gov.om/",
  "fw.kuwait.name": "Kuwait data privacy (CITRA Decision 26 of 2024)",
  "fw.kuwait.tagline": "No general data protection law yet. The CITRA regulation binds licensed telecom and internet providers.",
  "fw.kuwait.summary": "Kuwait has no comprehensive personal data protection statute as of September 2026 and no data protection authority. The Communication and Information Technology Regulatory Authority issued a Data Privacy Protection Regulation in 2021 covering any provider of communications or IT services in Kuwait, and replaced it in February 2024 with Decision 26 of 2024, which narrows the scope to CITRA-licensed telecom and internet service providers. That regulation requires explicit consent with Arabic and English disclosures, breach notification to CITRA and affected users within 24 hours, deletion after a contract ends, and disclosure of transfers outside Kuwait. The 2021 Data Classification Policy that imposed localisation was repealed in 2024. For everyone else the Electronic Transactions Law of 2014 and the Cybercrime Law of 2015 set the baseline: penalties for unlawful disclosure, up to three years' imprisonment under the former.",
  "fw.kuwait.who": "Licensed telecom and internet providers for the CITRA regulation. Other companies with Kuwaiti customers have no data protection statute to comply with yet, but the Electronic Transactions Law, customer contracts and the expectations of Kuwaiti enterprise buyers, which usually mean ISO 27001 and a GDPR-grade privacy programme, still apply.",
  "fw.kuwait.needs": "For licensed providers: explicit consent with bilingual disclosures, 24-hour breach notification, deletion at contract end, transfer disclosure \xB7 For everyone: the Electronic Transactions Law's confidentiality duties, contract terms on data, and whatever the buyer's own policy demands \xB7 A watching brief for a comprehensive law, which has been discussed but not published",
  "fw.kuwait.snoopios": "Not evidenced as a framework because there is no general law to evidence. Your UK GDPR coverage is the programme Kuwaiti buyers actually ask to see, and the residency guide covers the transfer disclosure.",
  "fw.kuwait.youdo": "Run the GDPR-grade programme you already have, state where data lives in your Kuwaiti contracts, and revisit this guide if a law is published.",
  "fw.kuwait.source": "https://citra.gov.kw/",
  "home.nav.integrations": "Integrations",
  "home.nav.stack": "Your stack",
  "home.nav.research": "Research",
  "home.nav.blog": "Notes",
  "home.nav.frameworks": "Frameworks",
  "home.frameworks.title": "Know what each framework actually asks for",
  "home.frameworks.cta": "Read the guides",
  "home.screens.body": "Real screens from a real project, not mock-ups. Every check is code, every result is pass, fail or unknown, and every document cites the checks behind it.",
  "home.screens.s1": "One project, every platform, every check, with the date it was last observed.",
  "home.screens.s2": "A check page: what was read, the evidence file and its hash, the fix, and the history.",
  "home.screens.s3": "A generated document: a live claim badge on every line a check can back, and a plain note where one cannot.",
  "home.screens.s4": "The public trust page: the same results, without the evidence, for customers to see.",
  "fw.index.title": "Frameworks, explained",
  "fw.index.seoTitle": "Compliance frameworks, explained \xB7 Snoopios",
  "fw.index.body": "What each standard or law asks of a small software team, what Snoopios evidences automatically, and what stays yours to do. Guides, not legal advice.",
  "fw.index.checked": "Snoopios evidences these",
  "fw.index.guides": "Guides to what is coming",
  // ── /integrations and /integrations/<provider> ───────────────────────────
  // Fifty-five pages generated from lib/provider-pages.ts. The chrome is here;
  // everything specific to a provider — its checks, the frameworks they
  // answer, whether the token stays on the customer's machine — is read from
  // the registry at render, so no sentence here can describe the software
  // wrongly. {provider} is the provider's display name.
  // The markdown rendering of the public pages (lib/markdown.ts). One line,
  // because everything else in those documents is the same deck the HTML uses.
  "md.canonical": "Canonical HTML version:",
  "md.framework": "Framework",
  "md.controls": "Controls evidenced",
  // ── /stack, the PUBLIC picker ────────────────────────────────────────────
  // Not the in-app one above (stack.* / "Which platforms does this project run
  // on?"), which is onboarding and shows connection cards. This one runs before
  // anyone signs up and shows the checks themselves.
  "stackpage.title": "What would Snoopios check on your stack?",
  "stackpage.body": "Pick what you actually run. You will see every check that would run against it, in the wording the product uses, and how much of each framework those checks reach. No sign-up, and nothing here is a score.",
  "stackpage.meta": "Choose the providers you run and see exactly which checks Snoopios would run against them, and which framework controls those checks evidence.",
  "stackpage.pick": "Your stack",
  "stackpage.pick.body": "Choose as many as apply. Your selection lives in the address bar, so the link is shareable.",
  "stackpage.empty": "Nothing picked yet. Choose a provider above and the checks appear here.",
  "stackpage.clear": "Clear selection",
  "stackpage.checks": "Checks that would run",
  "stackpage.checks.body": "One rule each, with a pass, a fail and a fix, run read-only against your live configuration.",
  "stackpage.frameworks": "How far that gets you",
  "stackpage.frameworks.body": "Controls evidenced by these checks, out of each framework\u2019s total. Where two providers answer the same control it is counted once. No framework is finished by checks alone: the rest is documents and attestations, and that is the part that starts once you connect.",
  "stackpage.providers": "providers",
  "stackpage.checkcount": "checks",
  "stackpage.frameworkcount": "frameworks touched",
  "stackpage.cta": "Run these on your stack",
  "stackpage.text": "Take this away",
  "stackpage.text.body": "The same answer as plain text, for a colleague or an agent to read.",
  "stackpage.nojs": "Works without JavaScript; the selection is held in the URL.",
  // ── /research ────────────────────────────────────────────────────────────
  // Measurement we publish. The numbers live in lib/research/*.ts, frozen as
  // measured; the prose is here so it is reviewed like every other sentence.
  // ── /blog ────────────────────────────────────────────────────────────────
  // Chrome only. The posts themselves are in lib/blog/, exempt from the deck
  // for the same reason the generated documents are.
  "blog.index.title": "Notes",
  "blog.index.seoTitle": "Compliance notes, one check at a time \xB7 Snoopios",
  "blog.index.body": "What we find while building the checks, and what the measurements say. Written when there is something to report rather than to a schedule.",
  "blog.index.meta": "Notes from Snoopios on email authentication, compliance evidence and what measuring real infrastructure turns up.",
  "blog.published": "Published",
  "blog.source": "Draws on",
  "blog.back": "All notes",
  "blog.cta": "Check your own domain",
  "research.index.title": "Research",
  "research.index.body": "Measurements of public infrastructure, published in full. No organisation is named, because the finding is the distribution and the individual result belongs to the individual.",
  "research.index.meta": "Original measurement from Snoopios: what public records show about the security posture of defined populations of organisations.",
  "research.scanned": "Scanned",
  "research.population": "Population",
  "research.method": "How this was measured",
  "research.limits": "What this does not show",
  "research.ethics": "Why no one is named",
  "research.reproduce": "Check your own",
  "research.md.measure": "Measurement",
  "research.md.result": "Result",
  "research.cta": "Check your own domain",
  "research.gcloud.title": "Two in five UK government cloud suppliers cannot stop their email being spoofed",
  "research.gcloud.standfirst": "Every organisation on G-Cloud 15 publishes an email address for public-sector buyers to contact them on. We looked up what the public DNS says about those addresses. 42.1% of them have no enforcing DMARC policy, and most of that number is not absence but abandonment.",
  "research.gcloud.headline": "941 of 2,237 suppliers publish no enforcing DMARC policy on the address they give government buyers. A message claiming to come from them can be delivered to a buyer\u2019s inbox, and nothing in the mail system will stop it.",
  "research.gcloud.finding": "The interesting half is not the suppliers with nothing. It is the 679 who published a DMARC record and left it set to p=none, which does not mean \u201Cnot configured\u201D. It is an instruction: deliver messages that fail authentication anyway. 1,976 suppliers have a DMARC record of some kind; only 1,296 of them enforce it. The work was started and then not finished, which is a harder problem than never having begun, because the record makes it look done.",
  "research.gcloud.spf": "The same shape appears in the gap between the two records. 2,111 suppliers publish SPF with a fail policy, a record most registrars have offered by default for a decade. 865 of those suppliers publish SPF and still do not enforce DMARC \u2014 and SPF alone stops very little, because it authenticates the envelope rather than the address a person reads.",
  "research.gcloud.tail": "The remaining measurements are thin across the board, and that is less surprising: CAA, MTA-STS and TLS-RPT are newer, none is required by Cyber Essentials, and none is visible to a buyer. 21 suppliers pass all six. 51 pass none.",
  "research.gcloud.m.dmarc": "DMARC policy is quarantine or reject",
  "research.gcloud.m.dmarc.note": "Tells receiving mail servers what to do with a message that fails authentication. Anything other than quarantine or reject means deliver it.",
  "research.gcloud.m.spf": "SPF record with a fail policy",
  "research.gcloud.m.spf.note": "Names the servers allowed to send for the domain. Authenticates the envelope, not the address the reader sees.",
  "research.gcloud.m.rua": "DMARC reports go somewhere",
  "research.gcloud.m.rua.note": "An address to receive aggregate reports. Without one nobody finds out they are being impersonated.",
  "research.gcloud.m.tlsrpt": "TLS reporting configured",
  "research.gcloud.m.tlsrpt.note": "Reports on mail delivered to the domain over an unencrypted connection.",
  "research.gcloud.m.caa": "CAA record limits certificate issuance",
  "research.gcloud.m.caa.note": "Names which certificate authorities may issue for the domain. Limits who can impersonate the website.",
  "research.gcloud.m.mtasts": "MTA-STS in enforce mode",
  "research.gcloud.m.mtasts.note": "Requires TLS on mail delivered to the domain. Testing mode is not counted: it reports and then delivers anyway.",
  "research.gcloud.d.monitor": "Publish a record set to p=none, which instructs receivers to deliver failing mail",
  "research.gcloud.d.absent": "Publish no DMARC record at all",
  "research.gcloud.d.malformed": "Publish a record a receiver discards as malformed",
  "research.gcloud.method": "The population is every organisation listed on G-Cloud 15, the current iteration of the UK government\u2019s cloud purchasing framework, enumerated from the public Digital Marketplace listing on 15 September 2026: 2,270 suppliers. Each supplier publishes a contact address for buyers; all 2,270 yielded one, which is why this is a census rather than a sample. Deduplicating gives 2,242 domains, of which 5 are at a mail provider the supplier does not control and are excluded, leaving 2,237. Every record was read from Cloudflare\u2019s public resolver rather than from the suppliers, so the organisations measured carried no load from being measured. Every result that was not a pass was looked up a second time and counted on the second answer: 7,929 rechecks, 2 of which changed, a rate of 0.03%. Twenty-four passes and failures drawn at random were confirmed against a raw DNS lookup, and all twenty-four agreed.",
  "research.gcloud.limits": "This measures what the public DNS says, which is not the same as whether an organisation is secure. A supplier can enforce DMARC and still be breached, and can lack it and never be impersonated. It says nothing about the systems behind the domain, and nothing about any supplier\u2019s handling of the data it holds. Twenty-three domains could not be resolved for MTA-STS and are excluded from that row rather than counted as failures. The contact address is the one given for public-sector buyers and may not be the domain a supplier sends most of its mail from. Every figure is a snapshot of one day; DNS changes.",
  "research.gcloud.ethics": "No supplier is named here, and the per-organisation results are not published, kept in this repository, or shared. Every check ran against records any member of the public can look up, and the individual answer belongs to the individual, who can get it for themselves in one command. A distribution tells a buyer and a policymaker something true about a market. A list of names would only tell an attacker where to start.",
  "research.gcloud.reproduce": "Every check behind these numbers is one the product runs, and you can run the same ones against your own domain without an account, a sign-up or a credential.",
  "int.index.title": "Integrations",
  "int.index.seoTitle": "Integrations: every tool Snoopios checks",
  "int.index.body": "Everything Snoopios can read, grouped by the part of a stack it is. Connect what you already run. Every check is read-only, every answer keeps the provider's own response behind it, and nothing here is a model's opinion.",
  "int.index.providers": "providers",
  "int.index.checks": "checks",
  "int.index.meta": "Every provider Snoopios connects to, from hosting and databases to identity, devices and secrets. Read-only checks, with the evidence behind each answer.",
  "int.page.back": "All integrations",
  "int.page.strap": "What Snoopios reads from {provider}, what it proves, and how to connect it.",
  "int.page.meta": "The read-only checks Snoopios runs on {provider}, and the frameworks they help answer. Evidence behind every result.",
  "int.page.titlesuffix": "compliance checks and framework coverage",
  "int.page.chip.checks": "checks",
  "int.page.chip.frameworks": "frameworks",
  "int.page.checks": "What Snoopios checks",
  "int.page.checks.body": "One rule each, with a pass, a fail and a fix. The wording below is the wording the product uses, because both are read from the same deck.",
  "int.page.frameworks": "Frameworks these checks answer",
  "int.page.frameworks.body": "The figure beside each name is how many of that framework's controls these checks evidence, out of the total it has. Most providers answer a few controls in many frameworks rather than most of one, and the ratio is there so you can tell which is which. Nothing here is a certification, and no framework is answered by one provider alone.",
  "int.page.connect": "How to connect",
  "int.page.readonly": "Read-only, always",
  "int.page.readonly.body": "Snoopios asks for the narrowest credential {provider} offers, and its own requests are limited to reads in code. Where a provider gives no way to read a token's permissions back, the connection says so rather than claiming otherwise.",
  "int.page.local": "Runs on your machine",
  "int.page.local.body": "{provider} issues only all-or-nothing credentials, so Snoopios never holds one. These checks run through the CLI on your own machine, and it is the result that is pushed, never the token.",
  "int.page.evidence": "Evidence, not a tick",
  "int.page.evidence.body": "Every answer keeps the raw response it was read from, so a finding can be shown to a customer or an auditor rather than asserted.",
  "int.page.cta": "Check this on your stack",
  "fw.index.checked.note": "Every control listed, ticked automatically, by a document, by an attestation, or left to you.",
  "fw.index.guides.note": "Explained so you can plan; Snoopios does not evidence these yet.",
  "fw.page.back": "All frameworks",
  "fw.page.summary": "What it is",
  "fw.page.who": "Who needs it",
  "fw.page.needs": "What it requires",
  "fw.page.snoopios": "What Snoopios does",
  "fw.page.youdo": "What stays with you",
  "fw.page.source": "Official source",
  "fw.page.controls": "Every control, and how it is evidenced",
  "fw.page.control": "Control",
  "fw.page.how": "How it is evidenced",
  "fw.page.by.automated": "Checked automatically",
  "fw.page.by.document": "Pack document",
  "fw.page.by.attested": "Attestation",
  "fw.page.by.provider": "Hosting provider's report",
  "fw.page.by.manual": "You answer",
  "fw.page.by.none": "Not yet",
  "fw.page.disclaimer": "These guides explain what a framework asks for as of the date on this page. They are not legal advice and do not replace an auditor, a certification body or a solicitor.",
  "fw.page.updated": "Reviewed 8 September 2026",
  "fw.page.cta": "Start checking your stack",
  "fw.group.security": "Security standards",
  "fw.group.privacy": "Privacy law",
  "fw.group.gulf": "Gulf data protection laws",
  "fw.group.ai": "AI governance",
  "fw.group.children": "Children's data",
  "fw.group.residency": "Where data lives",
  "fw.gdpr.name": "UK GDPR and the Data Protection Act 2018",
  "fw.gdpr.tagline": "The law that applies from your first user in the UK.",
  "fw.gdpr.summary": "UK GDPR is the UK's version of the EU General Data Protection Regulation, kept after Brexit and read alongside the Data Protection Act 2018. It governs any processing of personal data about people in the UK: what you may collect, on what legal basis, how long you keep it, who you share it with, how you protect it, and what people can ask you to do with it. The Data (Use and Access) Act 2025 amended parts of it, including the complaints procedure every controller now needs. The regulator is the ICO, and fines run to \xA317.5 million or 4% of worldwide turnover.",
  "fw.gdpr.who": "Every organisation that processes personal data about people in the UK, whatever its size, from the day it has one user, one customer or one employee. Most software companies must also register with the ICO and pay the data protection fee.",
  "fw.gdpr.needs": "A lawful basis for each processing purpose, written down \xB7 A privacy notice that says what you collect, why, for how long and who else sees it \xB7 A record of processing activities (Article 30) \xB7 Contracts with every processor and a list of them \xB7 Appropriate security: encryption, access control, backups, tested restores \xB7 Breach detection and a way to tell the ICO within 72 hours \xB7 A way to answer subject access, erasure and complaint requests within a month \xB7 A transfer mechanism for data leaving the UK \xB7 ICO registration where required",
  "fw.gdpr.snoopios": "Sixteen controls. Four are checked automatically every hour from your connected stack (encryption in transit, access control, backups, retention). Eleven are evidenced by the documents the pack generates from what is connected: the privacy notice, the Article 30 record, the sub-processor register, the retention schedule, the breach runbook and the requests procedure. One is an attestation: your ICO registration number, recorded with your name and the date.",
  "fw.gdpr.youdo": "Confirm the ICO registration. Fill in the parts of each document only you know: the purposes, the legal bases you rely on, who your DPO or contact is. Answer requests within a month when they come. Keep the transfer mechanism current if your hosting moves.",
  "fw.gdpr.source": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/",
  "fw.ce.name": "Cyber Essentials",
  "fw.ce.tagline": "The UK government's baseline. Often required to sell to the public sector.",
  "fw.ce.summary": "Cyber Essentials is a UK government scheme run by the NCSC through IASME. It is a self-assessment against five technical controls, verified by a certification body, and renewed yearly. Cyber Essentials Plus adds an independent technical test. It does not cover policies, people or privacy: it is about whether the common attacks are blocked. Public-sector contracts that involve personal data or IT services usually require it, and some insurers ask for it.",
  "fw.ce.who": "Any organisation, but in practice anyone bidding for UK public-sector or NHS work, agencies whose clients ask for it, and small companies that want the cheapest credible security badge. The self-assessment costs a few hundred pounds.",
  "fw.ce.needs": "Firewalls: every device and cloud service behind a boundary firewall with no open admin ports \xB7 Secure configuration: default passwords changed, unnecessary services off, auto-run disabled \xB7 User access control: named accounts, least privilege, MFA on every cloud service that offers it \xB7 Malware protection: anti-malware or application allow-listing on every device \xB7 Security update management: supported software only, critical patches within 14 days \xB7 A signed declaration covering every device that touches company data, including staff laptops and phones",
  "fw.ce.snoopios": "Four of the five controls have automated checks from your connected stack: firewalls and open ports, secure configuration of hosting and DNS, MFA and access on every identity and code provider, and unsupported versions. Malware protection on devices is an attestation, because no cloud API can see a laptop.",
  "fw.ce.youdo": "Keep the device list honest: laptops, phones and the software on them are in scope. Attest to malware protection. Complete the IASME questionnaire yourself; Snoopios gives you the evidence and the wording for each answer, not the certificate.",
  "fw.ce.source": "https://www.ncsc.gov.uk/cyberessentials/overview",
  "fw.soc2.name": "SOC 2",
  "fw.soc2.tagline": "The report American and enterprise buyers ask for.",
  "fw.soc2.summary": "SOC 2 is an attestation report written by a licensed CPA firm against the AICPA Trust Services Criteria: security always, plus availability, confidentiality, processing integrity and privacy if you choose them. Type I describes your controls at a point in time; Type II tests that they operated over a period, usually six or twelve months. It is not a certificate and there is no pass mark: the auditor reports exceptions and the reader decides. It costs from around \xA310,000 for a small company, before software.",
  "fw.soc2.who": "Software companies selling to US enterprises, or to anyone whose procurement team asks for it. A young company rarely needs a full SOC 2 in its first two years; it needs to answer the questionnaire and show evidence. When a deal genuinely blocks on the report, the evidence Snoopios has been collecting is what the auditor asks for first.",
  "fw.soc2.needs": "Common criteria CC1 to CC9: governance, communication, risk assessment, monitoring, control activities, logical access, system operations, change management, risk mitigation \xB7 Availability: monitoring, incident response, backups and recovery \xB7 Written policies that match what actually happens \xB7 Evidence that controls operated throughout the period: access reviews, change approvals, incident records, vendor reviews \xB7 A description of the system and its boundaries \xB7 An auditor",
  "fw.soc2.snoopios": "Thirty-eight controls mapped across the security, availability and confidentiality categories. Fifteen are checked automatically against your own accounts: access and multi-factor authentication, change management through reviewed branches, monitoring, backups, encryption in transit, and the vendor inventory. Twenty are evidenced by generated documents with a live claim on every sentence a check can back. Two are statements you confirm, and one is held by your hosting provider and evidenced by their report. The result is an evidence trail with dates and hashes, which is what an auditor samples. Snoopios also drafts the system description an auditor asks for before anything else, Section III of the report, from the same facts.",
  "fw.soc2.youdo": "Choose an auditor and a period. Run the quarterly access review and record it. Keep incident and change records real. Decide which criteria beyond security you include. Snoopios is the evidence collector and the drafts, not the audit.",
  "fw.soc2.source": "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2",
  "fw.iso.name": "ISO/IEC 27001:2022",
  "fw.iso.tagline": "The international information security certificate.",
  "fw.iso.summary": "ISO/IEC 27001 is the international standard for an information security management system (ISMS). Certification means an accredited body has audited that you run a management system: scope, risk assessment, a statement of applicability across the 93 controls in Annex A, internal audits, management review and continual improvement. The 2022 edition regrouped the controls into organisational, people, physical and technological themes. It is more about running the system than about any single technical setting, and it is renewed on a three-year cycle with yearly surveillance audits.",
  "fw.iso.who": "Companies selling into the UK public sector, Europe, the Middle East or regulated industries, where the certificate is a tender requirement. It is heavier than SOC 2 for a tiny team and rarely the right first step; it is the right step when a contract names it.",
  "fw.iso.needs": "A defined scope and an information security policy \xB7 A risk assessment and a risk treatment plan \xB7 A statement of applicability covering all 93 Annex A controls \xB7 Asset inventory, access control, cryptography, backups, logging, vulnerability management \xB7 Supplier relationships, incident management, business continuity \xB7 Awareness and training records \xB7 Internal audit and management review \xB7 An accredited certification body",
  "fw.iso.snoopios": "Ninety-three controls mapped. Twenty-four are checked automatically from your stack. Forty-eight are evidenced by the generated policy set and registers. Nine are attestations. Twelve are held by the hosting provider and evidenced by their report, so the percentage never pretends we checked a door we have never seen.",
  "fw.iso.youdo": "Run the management system: the risk assessment, the internal audit, the management review, the training. Choose the certification body. Snoopios gives you the technical evidence and the document set that the auditor reads first.",
  "fw.iso.source": "https://www.iso.org/standard/27001",
  "fw.iso42001.name": "ISO/IEC 42001:2023",
  "fw.iso42001.tagline": "The management-system standard for AI. The AI equivalent of 27001.",
  "fw.iso42001.summary": "ISO/IEC 42001 is the first certifiable international standard for an AI management system (AIMS). It follows the same shape as ISO 27001: context and scope, leadership, an AI policy, risk assessment, an AI system impact assessment, objectives, operational controls from Annex A, monitoring, internal audit and improvement. It applies whether you build models, fine-tune them or simply deploy a third-party model inside your product. Large buyers have started asking for it from AI-heavy suppliers in place of a bespoke AI questionnaire.",
  "fw.iso42001.who": "Companies whose product makes or shapes decisions with AI: generating content for users, scoring, recommending, classifying people. If your product calls a model provider's API, you are in scope as a deployer. A small team can be certified; the work is proportionate to the number and risk of AI systems.",
  "fw.iso42001.needs": "An AI policy and a named person accountable for AI \xB7 An inventory of AI systems with their purpose, data and model provider \xB7 An AI risk assessment and an AI system impact assessment for each system (affected people, harms, bias, safety) \xB7 Data governance: provenance, quality, rights to use the data, retention \xB7 Transparency: users told when they interact with AI and what it is for \xB7 Human oversight and a way to override or turn off \xB7 Incident handling for AI failures \xB7 Supplier controls for model providers: their terms, retention, training on your data \xB7 Internal audit and management review",
  "fw.iso42001.snoopios": "Twelve controls at clause and annex level. Ten inherit from the ISO 27001 and UK GDPR evidence already running, because an AI management system is the same management system with a different subject. Two are attestations: the AI system inventory, and the person accountable for each system's output.",
  "fw.iso42001.youdo": "Write the AI inventory now, even on one page: every place a model is used, which provider, what data it sees, whether the provider trains on it. Everything else in the standard builds on that list.",
  "fw.iso42001.source": "https://www.iso.org/standard/42001",
  "fw.euaiact.name": "EU AI Act",
  "fw.euaiact.tagline": "The first AI law. Education is named as a high-risk area.",
  "fw.euaiact.summary": "Regulation (EU) 2024/1689 sorts AI systems by risk. Prohibited practices (social scoring, manipulative systems, some biometric uses) have applied since 2 February 2025. Obligations for general-purpose AI model providers applied from 2 August 2025. Most high-risk obligations apply from 2 August 2026, with the remainder for AI embedded in already-regulated products from 2 August 2027. Annex III lists high-risk uses and includes education and vocational training: systems that decide access or admission, evaluate learning outcomes, steer a person's learning, or monitor prohibited behaviour during tests. Transparency duties apply to chatbots and generated content whatever the risk tier. It applies to providers placing systems on the EU market and to deployers in the EU, wherever the company sits.",
  "fw.euaiact.who": "Anyone selling AI-enabled software into the EU, including UK companies. Education products that grade, score, recommend a level or proctor are the clearest small-company case of high-risk use. A chatbot or content generator that is not high-risk still owes transparency: tell users it is AI and mark generated content where required.",
  "fw.euaiact.needs": "Classify each AI system: prohibited, high-risk, limited-risk (transparency), minimal \xB7 High-risk providers: a risk management system, data governance, technical documentation, logging, instructions for deployers, human oversight, accuracy and robustness, a quality management system, conformity assessment and CE marking, registration in the EU database \xB7 High-risk deployers: use per instructions, human oversight by trained people, log keeping, informing affected people, and in some cases a fundamental rights impact assessment \xB7 Transparency for chatbots, deepfakes and generated text \xB7 AI literacy for staff (Article 4, since February 2025) \xB7 Serious incident reporting",
  "fw.euaiact.snoopios": "Eleven controls covering the high-risk obligations and the transparency duties. Nine inherit from the ISO 27001 and UK GDPR evidence, since logging, accuracy, cybersecurity and data governance are the same controls the Act renames. Two are attestations: the risk classification with its reasoning, and human oversight.",
  "fw.euaiact.youdo": "Decide the risk tier of each AI feature with the Annex III list open. If any is high-risk, decide whether you are the provider or the deployer, because the obligations differ, and start the technical documentation early. Train the team on AI basics and record it.",
  "fw.euaiact.source": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
  "fw.nistai.name": "NIST AI Risk Management Framework",
  "fw.nistai.tagline": "The voluntary US framework buyers cite. Four functions: govern, map, measure, manage.",
  "fw.nistai.summary": "NIST AI RMF 1.0 (January 2023) is a voluntary framework from the US National Institute of Standards and Technology for managing the risks of AI systems, with a 2024 profile for generative AI. It is organised into four functions: Govern (policies, roles, culture), Map (context, intended use, affected people), Measure (test, evaluate, track metrics for trustworthiness characteristics such as safety, fairness, explainability and privacy), and Manage (prioritise and act on risks, monitor, respond). It is not certifiable; it is a vocabulary US customers and procurement questionnaires use.",
  "fw.nistai.who": "Companies selling AI features to US customers, and anyone who wants a structured way to think about AI risk without the weight of a management-system standard. It maps well onto ISO 42001, so work done for one serves the other.",
  "fw.nistai.needs": "Govern: an accountable owner, an AI policy, staff who know their role \xB7 Map: for each system, its purpose, users, affected people, data and known limitations \xB7 Measure: tests for accuracy, bias, safety and privacy, repeated over time, with results recorded \xB7 Manage: a risk register with decisions, monitoring in production, an incident and rollback plan \xB7 Documentation good enough that a customer can read how a system was assessed",
  "fw.nistai.snoopios": "Nine controls across Govern, Map, Measure and Manage. Eight inherit from the risk assessment, monitoring and incident evidence already running. The AI system inventory is an attestation, and it is the same one ISO 42001 and the EU AI Act ask for, so you write it once.",
  "fw.nistai.youdo": "Use the four functions as headings for a two-page AI risk note per system. That document answers most US questionnaire sections on AI.",
  "fw.nistai.source": "https://www.nist.gov/itl/ai-risk-management-framework",
  "fw.childrens.name": "UK Children's Code (Age Appropriate Design Code) and UK GDPR Article 8",
  "fw.childrens.tagline": "For any online service likely to be used by under-18s in the UK.",
  "fw.childrens.summary": "The Children's Code is a statutory code of practice from the ICO under the Data Protection Act 2018. It applies to information society services likely to be accessed by children under 18 in the UK: apps, websites, games, connected toys, learning platforms sold to families or directly to pupils. It sets fifteen standards, among them high privacy by default, data minimisation, no profiling or nudging by default, geolocation off, parental controls made visible to the child, no detrimental use of data, and a data protection impact assessment for the service. Schools themselves are not information society services, but the education technology they buy usually is. Separately, UK GDPR Article 8 sets the age at which a child can consent to online services at 13; below that, a parent must.",
  "fw.childrens.who": "Any education, family, gaming or creative product used by children in the UK, including business-to-school products where pupils are the users. If a school is the controller and you are its processor, the school's obligations flow to you by contract, and the Code still shapes how the product must behave.",
  "fw.childrens.needs": "A data protection impact assessment specific to children \xB7 Privacy settings high by default, with off-by-default profiling, geolocation and behavioural advertising \xB7 Only the data needed for the feature the child is using \xB7 Age assurance proportionate to the risk, or treating every user as a child \xB7 Transparency written for the child's age \xB7 Parental controls that the child can see are in use \xB7 No nudges towards weaker privacy \xB7 A lawful basis and, for under-13s, parental consent where consent is the basis \xB7 Retention limits and a way for children or parents to exercise rights",
  "fw.childrens.snoopios": "Fifteen controls, one for each standard. Thirteen inherit from the UK GDPR evidence, because the Code is the GDPR applied to children rather than a separate law. Two are attestations: how you establish age, and the assessment of how the service affects children by age range.",
  "fw.childrens.youdo": "Write the DPIA before launch, not after. Decide the age model: everyone treated as a child, or age assurance. Turn off anything that profiles or locates by default. Check every third-party SDK for what it collects from a child's device.",
  "fw.childrens.source": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/",
  "fw.coppa.name": "COPPA and FERPA (United States)",
  "fw.coppa.tagline": "Federal rules for children under 13 and for student records.",
  "fw.coppa.summary": "COPPA, the Children's Online Privacy Protection Act, is enforced by the FTC and applies to online services directed at children under 13, or that knowingly collect their data, wherever the company is based. It requires a clear children's privacy policy, verifiable parental consent before collection, limits on retention and disclosure, and reasonable security. The FTC's 2025 amendments to the COPPA Rule added separate consent for third-party disclosure and a written security programme, with compliance required by April 2026. Schools may consent on parents' behalf for purely educational use. FERPA is the Family Educational Rights and Privacy Act: it governs student education records held by schools that receive federal funds, and reaches vendors through the school-official exception, which requires the vendor to act under the school's direct control, use records only for the authorised purpose and not redisclose. Most US states add their own student privacy laws, such as California's SOPIPA and New York's Education Law 2-d, which often require a signed data privacy agreement per district.",
  "fw.coppa.who": "Any education or family product with users in the United States. Selling to US schools means FERPA and state agreements; selling to US families means COPPA from the first user under 13.",
  "fw.coppa.needs": "COPPA: a children's privacy policy, verifiable parental consent (or school consent for education-only use), separate consent for sharing with third parties, data minimisation, retention only as long as needed, a written security programme, and a way for parents to review and delete \xB7 FERPA: a written agreement with each school placing you under its direct control, use of records only for the contracted purpose, no redisclosure, deletion when the contract ends, and breach notification to the school \xB7 State laws: a signed data privacy agreement per district (New York, California and others), a published list of sub-processors, and in some states in-country or in-state hosting expectations for student data",
  "fw.coppa.snoopios": "Ten controls covering both regimes. Eight inherit from the UK GDPR evidence, since notice, minimisation, access, retention, security and vendor control are the same obligations under different names. Two are attestations: verifiable parental consent, and the school official agreement that FERPA turns on.",
  "fw.coppa.youdo": "Keep a signed agreement per school or district and know which state's law each falls under. Build the parental-consent flow before the first under-13 user. Log every disclosure to a third party.",
  "fw.coppa.source": "https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa",
  "fw.residency.name": "Data residency and international transfers",
  "fw.residency.tagline": "Which countries want data kept at home, and what to have in place when it is not.",
  "fw.residency.summary": "Two different questions get mixed up. Data residency is where data is stored and processed; a few laws require certain data to stay in the country. Transfer rules are about moving personal data across borders; most laws allow it with a mechanism in place. For a small team on hosted infrastructure the practical facts are: the UK and EU allow transfers with an adequacy decision or standard contractual clauses (the UK's IDTA or Addendum) plus a transfer risk assessment; the United States has no federal residency rule but state student-privacy laws and district contracts sometimes require US hosting; the UAE's federal law restricts transfers to approved countries or contract-based safeguards, and its financial free zones have their own regimes; Saudi Arabia's PDPL allows transfers under conditions after the 2023 amendments but expects sensitive data, including children's, to be handled with care and has sector rules that require in-Kingdom hosting; India's DPDP Act allows transfers except to countries on a government blocklist, with sector regulators stricter; China and Russia require localisation of much personal data; Canadian provinces such as British Columbia and Nova Scotia require public bodies, including schools, to keep personal data in Canada; Australia allows transfers where the recipient is bound to equivalent protection. Education regulators in several countries (for example the UAE's school regulators) add their own expectations for pupil data.",
  "fw.residency.who": "Any team with users in more than one country, and every education product, because a school's pupils are almost always in one country and the school's regulator will ask where their data is. If your database is in London and your customers are in Dubai, Riyadh or Toronto, this is your question before it is theirs.",
  "fw.residency.needs": "A map of where each system holds data: database region, file storage, backups, logs, email provider, model providers \xB7 A sub-processor list with the country of each \xB7 For every cross-border flow, the mechanism: adequacy, standard contractual clauses or the UK IDTA, binding corporate rules, or the local equivalent \xB7 A transfer risk assessment where the destination law is weaker \xB7 For markets that require residency, a region or a separate deployment in that country, or a contract that makes the host the controller's approved location \xB7 Contract wording that names the storage location and forbids moving it without notice \xB7 A way to answer a school or regulator in a day",
  "fw.residency.snoopios": "Partly evidenced. The sub-processor register is generated from your connected providers with the region each one runs in, and the checks record the region of your database and hosting. A transfer register that pairs each flow with its mechanism, and a residency check that flags a resource outside the region you declared for a market, are on the roadmap.",
  "fw.residency.youdo": "Declare your target markets and pick regions to match before you have customers there. Put the storage location in your customer contract. For pupil data, ask the school's regulator what it expects rather than guessing.",
  "fw.residency.source": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/",
  "conn.datadog.site.placeholder": "datadoghq.com, datadoghq.eu, us3.datadoghq.com, us5.datadoghq.com, ap1.datadoghq.com, ap2.datadoghq.com or uk1.datadoghq.com",
  "conn.local.label": "Run on your machine with the CLI",
  "ingest.title": "Run locally and push",
  "ingest.intro": "For the platforms whose tokens Snoopios will not hold, run the checks yourself with the CLI and push the results here with a project key. The key can only post results: it reads nothing and cannot touch connections or tokens. Every result it posts is labelled as run by you, on the check page, in every document and on the trust page.",
  "ingest.label": "Key label",
  "ingest.label.placeholder": "ci, laptop, release runner\u2026",
  "ingest.create": "Create key",
  "ingest.created": "Copy the key now. It is shown once; Snoopios keeps only a hash.",
  "ingest.snippet": "Then, on the machine or in CI, with the provider's token beside it:",
  "ingest.snippet.command": "npx snoopios run <provider> --push",
  "ingest.hourly": "To keep it hourly, schedule it in CI. The CLI README has a GitHub Actions workflow and a cron line.",
  "ingest.none": "No keys yet.",
  "ingest.prefix": "snpi_\u2026",
  "ingest.lastused": "last used",
  "ingest.neverused": "never used",
  "ingest.revoke": "Revoke",
  "ingest.error.label": "Give the key a short label (up to 40 characters).",
  "ingest.error.limit": "Five active keys per project. Revoke one first.",
  "run.source.tag": "Run by you",
  "run.source.cli": "Run by you with the Snoopios CLI",
  "run.source.ci": "Run in your CI with the Snoopios CLI",
  "run.source.link": "CI run"
};

// ../lib/checks/ingest-key.ts
var KEY = /^snpi_([0-9a-f]{32})_([A-Za-z0-9_-]{32,})$/;
function parseIngestKey(key) {
  const m = KEY.exec(key.trim());
  if (!m) return null;
  const h = m[1];
  return { projectId: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}` };
}

// src/index.ts
import { hostname } from "node:os";
var ESPS = ["resend", "postmark", "mailgun", "ses", "other"];
var LOCAL = {
  netlify: { env: "NETLIFY_AUTH_TOKEN", label: "Netlify", run: (t) => runNetlifyChecks({ api: netlifyApi(t) }) },
  neon: { env: "NEON_API_KEY", label: "Neon", run: (t) => runNeonChecks({ api: neonApi(t) }) },
  render: { env: "RENDER_API_KEY", label: "Render", run: (t) => runRenderChecks({ api: renderApi(t) }) },
  heroku: { env: "HEROKU_API_KEY", label: "Heroku", run: (t) => runHerokuChecks({ api: herokuApi(t) }) },
  clerk: { env: "CLERK_SECRET_KEY", label: "Clerk", run: (t) => runClerkChecks({ api: clerkApi(t) }) },
  upstash: { env: "UPSTASH_API_KEY", extra: "UPSTASH_EMAIL", label: "Upstash", run: (t, email) => runUpstashChecks({ api: upstashApi(email, t) }) },
  betterstack: { env: "BETTERSTACK_API_TOKEN", label: "Better Stack", run: (t) => runBetterStackChecks({ api: betterStackApi(t) }) },
  railway: { env: "RAILWAY_TOKEN", label: "Railway", run: (t) => runRailwayChecks({ api: railwayApi(t) }) },
  circleci: {
    env: "CIRCLECI_TOKEN",
    extra: "CIRCLECI_PROJECT",
    label: "CircleCI",
    run: (t, project2) => {
      if (!CIRCLECI_PROJECT.test(project2)) throw new Error("CIRCLECI_PROJECT must be a project slug such as gh/acme/api.");
      return runCircleCiChecks({ project: project2, api: circleCiApi(t) });
    }
  },
  checkly: { env: "CHECKLY_API_KEY", extra: "CHECKLY_ACCOUNT_ID", label: "Checkly", run: (t, account) => runChecklyChecks({ api: checklyApi(t, account) }) },
  turso: {
    env: "TURSO_API_TOKEN",
    extra: "TURSO_ORG",
    label: "Turso",
    run: (t, org) => {
      if (!TURSO_ORG.test(org)) throw new Error("TURSO_ORG must be the organisation slug.");
      return runTursoChecks({ org, api: tursoApi(t) });
    }
  },
  workos: { env: "WORKOS_API_KEY", label: "WorkOS", run: (t) => runWorkOsChecks({ api: workOsApi(t) }) },
  // The scanners. Snoopios does not rescan: it reads what the customer's own
  // tool already found and asks whether anybody fixed it, and how fast.
  snyk: {
    env: "SNYK_TOKEN",
    extra: "SNYK_ORG_ID",
    label: "Snyk",
    run: (t, org) => {
      if (!SNYK_ORG.test(org)) throw new Error("SNYK_ORG_ID must be the organisation id, which is a GUID rather than the org's name.");
      return runSnykChecks({ api: snykApi(t), orgId: org });
    }
  },
  gitguardian: { env: "GITGUARDIAN_API_KEY", label: "GitGuardian", run: (t) => runGitGuardianChecks({ api: gitGuardianApi(t) }) },
  semgrep: {
    env: "SEMGREP_APP_TOKEN",
    extra: "SEMGREP_DEPLOYMENT",
    label: "Semgrep",
    run: (t, slug) => {
      if (!SEMGREP_SLUG.test(slug)) throw new Error("SEMGREP_DEPLOYMENT must be the deployment slug.");
      return runSemgrepChecks({ api: semgrepApi(t), slug });
    }
  },
  // Aikido and Bitwarden exchange a client pair for a short-lived token, so
  // the secret half is the one in the environment and the id is the extra.
  aikido: {
    env: "AIKIDO_CLIENT_SECRET",
    extra: "AIKIDO_CLIENT_ID",
    label: "Aikido",
    run: async (secret, id) => runAikidoChecks(await aikidoContext(id, secret))
  },
  sonarqube: {
    env: "SONAR_TOKEN",
    extra: "SONAR_PROJECT_KEY",
    label: "SonarQube",
    run: (t, key) => {
      if (!key) throw new Error("SONAR_PROJECT_KEY must be the project key.");
      return runSonarChecks({ api: sonarApi(process.env.SONAR_HOST_URL || "https://sonarcloud.io", t), projectKey: key });
    }
  },
  // The password and secrets managers. None of these credentials can be made
  // read-only, which is exactly why they never leave this machine.
  bitwarden: {
    env: "BW_CLIENT_SECRET",
    extra: "BW_CLIENT_ID",
    label: "Bitwarden",
    run: async (secret, id) => {
      const region = process.env.BW_REGION || "com";
      if (region !== "com" && region !== "eu") throw new Error("BW_REGION must be com or eu.");
      return runBitwardenChecks(await bitwardenContext(id, secret, region));
    }
  },
  onepassword: {
    env: "OP_EVENTS_TOKEN",
    extra: "OP_REGION",
    label: "1Password",
    run: (t, region) => {
      const r = region || "com";
      if (!HOSTS[r]) throw new Error(`OP_REGION must be one of ${Object.keys(HOSTS).join(", ")}.`);
      return runOnePasswordChecks({ api: onePasswordApi(t, r) });
    }
  },
  doppler: { env: "DOPPLER_TOKEN", label: "Doppler", run: (t) => runDopplerChecks({ api: dopplerApi(t) }) }
};
function text(key) {
  return COPY[key] ?? key;
}
function usage() {
  return [
    `snoopios ${"0.7.0"}: continuous compliance for small software teams`,
    "",
    "Usage:",
    "  snoopios scan <domain> [--email <resend|postmark|mailgun|ses|other>] [--json]",
    "  snoopios run <provider> [--json] [--push] [--ci]        (see the list below)",
    "  snoopios doctor <postgres-connection-string> [--json]",
    "  snoopios repo [path] [--json] [--push] [--ci]",
    "",
    "scan    the domain checks (HTTPS, HSTS, CSP, TLS, SPF, DMARC, CAA, security.txt, privacy",
    "        page); --email adds the sending-domain checks with that provider's defaults",
    "run     a provider whose token cannot be made read-only, or whose token you should not",
    "        hand to a compliance tool at all. It runs here instead of on Snoopios's",
    "        servers, and the token never leaves this machine.",
    "",
    "        hosting and data    netlify NETLIFY_AUTH_TOKEN | neon NEON_API_KEY",
    "                            render RENDER_API_KEY | heroku HEROKU_API_KEY",
    "                            railway RAILWAY_TOKEN | turso TURSO_API_TOKEN + TURSO_ORG",
    "                            upstash UPSTASH_API_KEY + UPSTASH_EMAIL",
    "        identity            clerk CLERK_SECRET_KEY | workos WORKOS_API_KEY",
    "        monitoring and CI   betterstack BETTERSTACK_API_TOKEN | checkly CHECKLY_API_KEY",
    "                            + CHECKLY_ACCOUNT_ID | circleci CIRCLECI_TOKEN +",
    "                            CIRCLECI_PROJECT (gh/org/repo)",
    "        scanning            snyk SNYK_TOKEN + SNYK_ORG_ID | semgrep SEMGREP_APP_TOKEN +",
    "                            SEMGREP_DEPLOYMENT | gitguardian GITGUARDIAN_API_KEY",
    "                            aikido AIKIDO_CLIENT_ID + AIKIDO_CLIENT_SECRET",
    "                            sonarqube SONAR_TOKEN + SONAR_PROJECT_KEY, and",
    "                            SONAR_HOST_URL for a self-hosted server",
    "        secrets             onepassword OP_EVENTS_TOKEN + OP_REGION (com, ca, eu, ent)",
    "                            bitwarden BW_CLIENT_ID + BW_CLIENT_SECRET (+ BW_REGION=eu)",
    "                            doppler DOPPLER_TOKEN",
    "",
    "        The scanners are read, never re-run: Snoopios does not rescan your code. What",
    "        it asks is whether anybody fixes what your own tools find, and how fast.",
    "doctor  the Supabase SQL checks (RLS on every table, no anon writes, private schema",
    "        closed, SECURITY DEFINER search_path, anon-callable definers) against any",
    "        Postgres connection string. Runs SELECT statements only.",
    "repo    a local git checkout: .env committed, .gitignore, credential shapes anywhere in",
    "        the history, lockfiles, SECURITY.md and CODEOWNERS, Dependabot or Renovate, and",
    "        npm audit. Works for any git host. Only the audit touches the network.",
    "",
    "--push  posts the results of run or repo to your Snoopios project, using the key in",
    "        SNOOPIOS_INGEST_KEY (project page \u2192 Run locally and push). Results only: the",
    "        provider token stays here. They show as run by you; --ci labels them as run in",
    "        CI and records the run URL (GitHub Actions and GitLab CI are detected).",
    "",
    "Every check is pass, fail or unknown; unknown is never a pass. Exit code 1 on any fail.",
    "Nothing is sent to Snoopios without --push. Keep it checked hourly: https://snoopios.com"
  ].join("\n");
}
var ICON = { pass: "\u2713", fail: "\u2717", unknown: "?" };
var COLOUR = { pass: "\x1B[32m", fail: "\x1B[31m", unknown: "\x1B[90m" };
var RESET = "\x1B[0m";
function rows(results) {
  return results.map(({ code, result }) => ({
    code,
    status: result.status,
    title: text(`check.${code}.title`),
    line: result.status === "unknown" ? `Could not be determined (${result.errorScope ?? "unknown"}). Never counted as a pass.` : text(`check.${code}.${result.status}`)
  }));
}
function print(heading, all) {
  const colour = process.stdout.isTTY === true && !process.env.NO_COLOR;
  const c = (s, t) => colour ? `${COLOUR[s]}${t}${RESET}` : t;
  console.log(`
${heading}
`);
  for (const r of all) {
    console.log(`  ${c(r.status, ICON[r.status])}  ${r.title}`);
    console.log(`     ${c(r.status, r.line)}`);
    if (r.status === "fail") console.log(`     Fix: ${text(`check.${r.code}.fix`)}`);
  }
  const n = (s) => all.filter((r) => r.status === s).length;
  console.log(`
  ${n("pass")} pass, ${n("fail")} fail, ${n("unknown")} unknown. Unknown is never a pass.`);
  console.log(`  Checked once from this machine. Keep it checked hourly with evidence: https://snoopios.com
`);
}
async function emit(heading, subject, results, json, pushTo) {
  if (json) {
    console.log(JSON.stringify({ subject, version: "0.7.0", checks: results.map((r) => ({ code: r.code, version: r.version, status: r.result.status, observed: r.result.observed, errorScope: r.result.errorScope ?? null })) }, null, 2));
  } else {
    print(heading, rows(results));
  }
  if (pushTo && !await push(pushTo, results)) return 2;
  return results.some((r) => r.result.status === "fail") ? 1 : 0;
}
function parse(rest) {
  const positional = [];
  let json = false;
  let push2 = false;
  let ci = false;
  let esp = null;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--json") json = true;
    else if (a === "--push") push2 = true;
    else if (a === "--ci") ci = true;
    else if (a === "--email") {
      const v = rest[++i];
      if (!v || !ESPS.includes(v)) return { positional, json, esp, push: push2, ci, error: `--email needs one of ${ESPS.join(", ")}` };
      esp = v;
    } else if (a.startsWith("-")) return { positional, json, esp, push: push2, ci, error: `Unknown option "${a}".` };
    else positional.push(a);
  }
  return { positional, json, esp, push: push2, ci };
}
function detectRunner(ci) {
  const env = process.env;
  const github = env.GITHUB_ACTIONS === "true";
  const gitlab = env.GITLAB_CI === "true";
  const inCi = ci || github || gitlab || env.CI === "true";
  if (!inCi) return { kind: "cli", host: hostname() };
  const ciUrl = github && env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : gitlab && env.CI_JOB_URL ? env.CI_JOB_URL : void 0;
  return { kind: "ci", ...ciUrl ? { ciUrl } : {} };
}
async function push(p, results) {
  const key = (process.env.SNOOPIOS_INGEST_KEY ?? "").trim();
  const parsed = key ? parseIngestKey(key) : null;
  if (!parsed) {
    console.error(key ? "SNOOPIOS_INGEST_KEY is not a Snoopios ingest key (snpi_\u2026). Create one on the project page under Run locally and push." : "SNOOPIOS_INGEST_KEY is not set. Create a key on the project page under Run locally and push, and put it in that environment variable.");
    return false;
  }
  const base = (process.env.SNOOPIOS_URL ?? "https://snoopios.com").replace(/\/+$/, "");
  const body = {
    provider: p.provider,
    results: results.map((r) => ({ code: r.code, version: r.version, status: r.result.status, observed: r.result.observed, evidence: r.result.evidence ?? null, errorScope: r.result.errorScope ?? null })),
    runner: detectRunner(p.ci)
  };
  try {
    const res = await fetch(`${base}/api/projects/${parsed.projectId}/ingest`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", accept: "application/json", connection: "close", "user-agent": `snoopios-cli/${"0.7.0"}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(3e4)
    });
    const json = await res.json().catch(() => null);
    if (!res.ok || !json?.ok) {
      console.error(`Push refused (${res.status}${json?.error ? `, ${json.error}` : ""}). Nothing was stored.`);
      return false;
    }
    console.error(`Pushed ${json.written} results to ${base}/app/projects/${parsed.projectId} as ${body.runner.kind === "ci" ? "run in CI" : "run by you"}.`);
    return true;
  } catch (e) {
    console.error(`Push failed: ${e instanceof Error ? e.message : String(e)}. Nothing was stored.`);
    return false;
  }
}
async function scan(rest) {
  const { positional, json, esp, push: pushFlag, error } = parse(rest);
  if (pushFlag) {
    console.error("--push is for run and repo; Snoopios already checks your domain itself.");
    return 2;
  }
  if (error) {
    console.error(`${error}

${usage()}`);
    return 2;
  }
  const host = (positional[0] ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) {
    console.error(`"${host || "(empty)"}" is not a hostname. Example: snoopios scan example.com`);
    return 2;
  }
  const domain = await runDomainChecks({ host });
  const email = esp ? await runEmailChecks({ domain: host, esp }) : [];
  return emit(`snoopios scan ${host}`, host, [...domain, ...email], json);
}
async function run(rest) {
  const { positional, json, push: pushFlag, ci, error } = parse(rest);
  if (error) {
    console.error(`${error}

${usage()}`);
    return 2;
  }
  const name = (positional[0] ?? "").toLowerCase();
  const p = LOCAL[name];
  if (!p) {
    console.error(`run needs one of ${Object.keys(LOCAL).join(", ")}. Example: snoopios run netlify`);
    return 2;
  }
  const token = (process.env[p.env] ?? "").trim();
  if (!token) {
    console.error(`${p.env} is not set. Put your ${p.label} token in that environment variable; it is read here and never leaves this machine.`);
    return 2;
  }
  const extra = p.extra ? (process.env[p.extra] ?? "").trim() : "";
  if (p.extra && !extra) {
    console.error(`${p.extra} is not set. ${p.label} needs it beside ${p.env}; both are read here and never leave this machine.`);
    return 2;
  }
  const results = await p.run(token, extra);
  return emit(`snoopios run ${name}`, name, results, json, pushFlag ? { provider: name, ci } : void 0);
}
async function doctor(rest) {
  const { positional, json, push: pushFlag, error } = parse(rest);
  if (pushFlag) {
    console.error("--push is for run and repo; connect Supabase on the project page for hosted SQL checks.");
    return 2;
  }
  if (error) {
    console.error(`${error}

${usage()}`);
    return 2;
  }
  const url = positional[0] ?? process.env.DATABASE_URL ?? "";
  if (!/^postgres(ql)?:\/\//.test(url)) {
    console.error("doctor needs a Postgres connection string (postgres://\u2026), as an argument or in DATABASE_URL. It is used here and never leaves this machine.");
    return 2;
  }
  const { default: pg } = await import("pg");
  const local = /@(localhost|127\.0\.0\.1)(:|\/|$)/.test(url);
  const supabase = /@[^/]*\.supabase\.(com|co)(:|\/|$)/.test(url);
  const ssl = local ? void 0 : supabase ? { ca: "-----BEGIN CERTIFICATE-----\nMIIDxDCCAqygAwIBAgIUbLxMod62P2ktCiAkxnKJwtE9VPYwDQYJKoZIhvcNAQEL\nBQAwazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l\ndyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJh\nc2UgUm9vdCAyMDIxIENBMB4XDTIxMDQyODEwNTY1M1oXDTMxMDQyNjEwNTY1M1ow\nazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5ldyBD\nYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJhc2Ug\nUm9vdCAyMDIxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQXW\nQyHOB+qR2GJobCq/CBmQ40G0oDmCC3mzVnn8sv4XNeWtE5XcEL0uVih7Jo4Dkx1Q\nDmGHBH1zDfgs2qXiLb6xpw/CKQPypZW1JssOTMIfQppNQ87K75Ya0p25Y3ePS2t2\nGtvHxNjUV6kjOZjEn2yWEcBdpOVCUYBVFBNMB4YBHkNRDa/+S4uywAoaTWnCJLUi\ncvTlHmMw6xSQQn1UfRQHk50DMCEJ7Cy1RxrZJrkXXRP3LqQL2ijJ6F4yMfh+Gyb4\nO4XajoVj/+R4GwywKYrrS8PrSNtwxr5StlQO8zIQUSMiq26wM8mgELFlS/32Uclt\nNaQ1xBRizkzpZct9DwIDAQABo2AwXjALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFKjX\nuXY32CztkhImng4yJNUtaUYsMB8GA1UdIwQYMBaAFKjXuXY32CztkhImng4yJNUt\naUYsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB8spzNn+4VU\ntVxbdMaX+39Z50sc7uATmus16jmmHjhIHz+l/9GlJ5KqAMOx26mPZgfzG7oneL2b\nVW+WgYUkTT3XEPFWnTp2RJwQao8/tYPXWEJDc0WVQHrpmnWOFKU/d3MqBgBm5y+6\njB81TU/RG2rVerPDWP+1MMcNNy0491CTL5XQZ7JfDJJ9CCmXSdtTl4uUQnSuv/Qx\nCea13BX2ZgJc7Au30vihLhub52De4P/4gonKsNHYdbWjg7OWKwNv/zitGDVDB9Y2\nCMTyZKG3XEu5Ghl1LEnI3QmEKsqaCLv12BnVjbkSeZsMnevJPs1Ye6TjjJwdik5P\no/bKiIz+Fq8=\n-----END CERTIFICATE-----\n", rejectUnauthorized: true } : { rejectUnauthorized: true };
  const client = new pg.Client({ connectionString: url, ssl, connectionTimeoutMillis: 15e3 });
  try {
    await client.connect();
  } catch (e) {
    const err = e;
    const why = err.code ?? err.errors?.map((x) => x.code).filter(Boolean).join(", ") ?? "";
    const reason = why || err.message || "network error";
    const hint = /ssl|tls|cert|self.signed|unable_to_verify|depth_zero|altname|hostname/i.test(reason) ? "The certificate is verified; a self-hosted server needs one the system trusts." : "Check the host and port are reachable from this machine; some networks block outbound 5432 and 6543.";
    console.error(`Could not connect to the database: ${reason}. ${hint}`);
    return 2;
  }
  try {
    const sql = { query: async (q) => (await client.query(q)).rows };
    const all = await runSupabaseChecks({ projectRef: "local", sql });
    const codes = new Set(SUPABASE_SQL_CHECKS.map((c) => c.code));
    const results = all.filter((r) => codes.has(r.code));
    const host = url.replace(/^[^@]*@/, "").replace(/[?/].*$/, "");
    return emit(`snoopios doctor ${host}`, host, results, json);
  } finally {
    await client.end();
  }
}
function git(cwd, args) {
  return new Promise((res, rej) => {
    execFile("git", args, { cwd, maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout) => err ? rej(err) : res(String(stdout)));
  });
}
function gitHistory(cwd, maxBytes) {
  return new Promise((res, rej) => {
    const child = spawn("git", ["log", "-p", "--all", "--no-color", "--format=commit %H"], { cwd, windowsHide: true });
    const chunks = [];
    let size = 0;
    let truncated = false;
    child.stdout.on("data", (b) => {
      if (truncated) return;
      if (size + b.length > maxBytes) {
        chunks.push(b.subarray(0, maxBytes - size));
        size = maxBytes;
        truncated = true;
        child.kill();
        return;
      }
      chunks.push(b);
      size += b.length;
    });
    child.on("error", rej);
    child.on("close", () => res({ text: Buffer.concat(chunks).toString("utf8"), truncated }));
  });
}
function npmAudit(cwd) {
  return new Promise((res) => {
    const npmCli = join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
    const [file, args] = existsSync(npmCli) ? [process.execPath, [npmCli, "audit", "--json", "--audit-level=none"]] : [process.platform === "win32" ? "npm.cmd" : "npm", ["audit", "--json", "--audit-level=none"]];
    execFile(file, args, { cwd, maxBuffer: 32 * 1024 * 1024, windowsHide: true, shell: file !== process.execPath && process.platform === "win32" }, (_err, stdout) => {
      try {
        const j = JSON.parse(String(stdout));
        const v = j.metadata?.vulnerabilities;
        if (!v) return res(null);
        res({ critical: v.critical ?? 0, high: v.high ?? 0, moderate: v.moderate ?? 0, low: v.low ?? 0 });
      } catch {
        res(null);
      }
    });
  });
}
async function repo(rest) {
  const { positional, json, push: pushFlag, ci, error } = parse(rest);
  if (error) {
    console.error(`${error}

${usage()}`);
    return 2;
  }
  const root = resolve(positional[0] ?? ".");
  try {
    await git(root, ["rev-parse", "--is-inside-work-tree"]);
  } catch {
    console.error(`${root} is not inside a git repository. Example: snoopios repo .`);
    return 2;
  }
  const top = (await git(root, ["rev-parse", "--show-toplevel"])).trim();
  const hasLock = await stat(join(top, "package-lock.json")).then(() => true, () => false);
  const source = {
    files: async () => (await git(top, ["ls-files", "-z"])).split("\0").filter(Boolean).map((f) => f.replace(/\\/g, "/")),
    read: async (p) => readFile(join(top, p), "utf8").catch(() => null),
    history: (max) => gitHistory(top, max),
    audit: hasLock ? () => npmAudit(top) : void 0
  };
  const results = await runRepoChecks({ source });
  return emit(`snoopios repo ${top}`, top, results, json, pushFlag ? { provider: "repo", ci } : void 0);
}
async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    console.log(usage());
    return 0;
  }
  if (cmd === "--version" || cmd === "-v") {
    console.log("0.7.0");
    return 0;
  }
  if (cmd === "scan") return scan(rest);
  if (cmd === "run") return run(rest);
  if (cmd === "doctor") return doctor(rest);
  if (cmd === "repo") return repo(rest);
  console.error(`Unknown command "${cmd}".

${usage()}`);
  return 2;
}
main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 2;
  }
);
