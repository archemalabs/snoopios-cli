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
    return unknown(err instanceof Error && err.message === "edge.challenge" ? "edge.challenge" : scope);
  }
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
  // UptimeRobot's API is POST-only; these two methods read.
  /^https:\/\/api\.uptimerobot\.com\/v2\/(getMonitors|getAccountDetails)$/
];
var GRAPHQL_READ = [/^https:\/\/api\.fly\.io\/graphql$/, /^https:\/\/backboard\.railway\.com\/graphql\/v2$/];
function isReadQueryBody(body) {
  if (typeof body !== "string") return false;
  try {
    const q = JSON.parse(body).query;
    return typeof q === "string" && /^\s*(query\b|\{)/.test(q);
  } catch {
    return false;
  }
}
var WriteRefused = class extends Error {
  constructor(method, url) {
    super(`read-only: ${method} ${url} refused`);
    this.name = "WriteRefused";
  }
};
function isReadOnlyRequest(url, method, body) {
  const m = method.toUpperCase();
  if (m === "GET" || m === "HEAD") return true;
  if (m === "POST") return READ_ONLY_POST.some((re) => re.test(url)) || GRAPHQL_READ.some((re) => re.test(url)) && isReadQueryBody(body);
  return false;
}
var readOnlyFetch = (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const method = init?.method ?? (typeof input === "object" && !(input instanceof URL) ? input.method : "GET") ?? "GET";
  if (!isReadOnlyRequest(url, method, init?.body)) return Promise.reject(new WriteRefused(method.toUpperCase(), url));
  return fetch(input, init);
};

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
function rejectChallenge(res) {
  if (challenged(res)) throw new EdgeChallenge();
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
async function dohTxt(ctx, name3, type = "TXT") {
  const f = ctx.fetch ?? readOnlyFetch;
  const res = await f(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name3)}&type=${type}`,
    { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  const json = await res.json();
  return json;
}
function realTls(host) {
  return new Promise((resolve2, reject) => {
    const socket = tlsConnect(
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
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.6", "ce:secure-config", "iso:8.26", "iso:8.9"],
  run: (ctx) => guarded("http.get", async () => {
    const r = await head(ctx, `https://${ctx.host}/`, "follow");
    const csp = r.headers["content-security-policy"] ?? null;
    const observed = {
      present: Boolean(csp),
      objectSrcNone: /object-src\s+'none'/i.test(csp ?? ""),
      baseUriSelf: /base-uri\s+'self'/i.test(csp ?? ""),
      frameAncestors: /frame-ancestors/i.test(csp ?? "")
    };
    const ok = observed.present && observed.objectSrcNone && observed.baseUriSelf && observed.frameAncestors;
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
    const policy = /p=(none|quarantine|reject)/i.exec(rec ?? "")?.[1]?.toLowerCase() ?? null;
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
async function doh(ctx, name3, type = "TXT") {
  const f = ctx.fetch ?? readOnlyFetch;
  const res = await f(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name3)}&type=${type}`, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(TIMEOUT_MS2)
  });
  return await res.json();
}
function txt(answer) {
  return (answer ?? []).filter((a) => a.type === 16).map((a) => a.data.replace(/"\s+"/g, "").replace(/^"|"$/g, ""));
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
    const rec = txt(json.Answer).find((t) => /(^|;)\s*p=/.test(t)) ?? null;
    const key = /(?:^|;)\s*p=([A-Za-z0-9+/=]*)/.exec(rec ?? "")?.[1] ?? "";
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
  const policy = /(?:^|;)\s*p=(none|quarantine|reject)/i.exec(rec ?? "")?.[1]?.toLowerCase() ?? null;
  const rua = /(?:^|;)\s*rua=mailto:([^;,\s]+)/i.exec(rec ?? "")?.[1] ?? null;
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
var mtaSts = {
  code: "email.mta_sts",
  provider: "email",
  version: 1,
  severity: "low",
  maps: ["iso:8.24", "iso:8.20"],
  run: (ctx) => guarded("doh.mta-sts", async () => {
    const json = await doh(ctx, `_mta-sts.${ctx.domain}`);
    const rec = txt(json.Answer).find((t) => t.toLowerCase().startsWith("v=stsv1")) ?? null;
    let mode = null;
    let policyStatus = null;
    if (rec) {
      const f = ctx.fetch ?? readOnlyFetch;
      const res = await f(`https://mta-sts.${ctx.domain}/.well-known/mta-sts.txt`, { signal: AbortSignal.timeout(TIMEOUT_MS2) });
      policyStatus = res.status;
      if (res.ok) mode = /^\s*mode:\s*(enforce|testing|none)/im.exec(await res.text())?.[1]?.toLowerCase() ?? null;
    }
    const observed = { dnsRecord: Boolean(rec), policyStatus, mode };
    return mode === "enforce" ? pass(observed, { dns: json, policyStatus, mode }) : fail(observed, { dns: json, policyStatus, mode });
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
var EMAIL_CHECKS = [dkimPresent, spfReturnPath, dmarcEnforced, dmarcReporting, mtaSts, tlsRpt];
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
var SECRET_KEY = /(SECRET|TOKEN|PASSWORD|PRIVATE|API_KEY|_KEY$|^KEY_)/i;
var PUBLIC_KEY = /^(NEXT_PUBLIC_|PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|GATSBY_)|_PUBLIC_KEY$|PUBLISHABLE/i;
var forceHttps = {
  code: "netlify.site.force_https",
  provider: "netlify",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("api.sites", async () => {
    const list4 = await sites(ctx);
    if (list4.length === 0) return unknown("api.no_sites");
    const off = list4.filter((s) => s.ssl !== true || s.force_ssl !== true).map((s) => s.name);
    const observed = { sites: list4.length, notForced: off };
    const evidence = list4.map((s) => ({ name: s.name, ssl: s.ssl ?? null, force_ssl: s.force_ssl ?? null }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var siteProtected = {
  code: "netlify.site.protected",
  provider: "netlify",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.3"],
  run: (ctx) => guarded("api.sites", async () => {
    const list4 = await sites(ctx);
    if (list4.length === 0) return unknown("api.no_sites");
    if (list4.every((s) => s.password === void 0)) return unknown("api.protection_hidden", { sites: list4.length });
    const open = list4.filter((s) => !s.password).map((s) => s.name);
    const observed = { sites: list4.length, unprotected: open };
    const evidence = list4.map((s) => ({ name: s.name, passwordSet: Boolean(s.password) }));
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var envSecretsMarked = {
  code: "netlify.env.secrets_marked",
  provider: "netlify",
  version: 1,
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
    return Object.keys(unmarked).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var liveHeaders = {
  code: "netlify.site.headers",
  provider: "netlify",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("site.headers", async () => {
    const list4 = await sites(ctx);
    if (list4.length === 0) return unknown("api.no_sites");
    const f = ctx.fetch ?? readOnlyFetch;
    const missing = {};
    const evidence = {};
    for (const s of list4) {
      const url = s.ssl_url ?? s.url;
      if (!url) continue;
      const res = await f(url, { method: "HEAD", redirect: "follow", signal: AbortSignal.timeout(1e4) });
      const h = (n) => res.headers.get(n);
      const csp = h("content-security-policy") ?? "";
      const gaps = [];
      if (!h("x-frame-options") && !/frame-ancestors/i.test(csp)) gaps.push("framing");
      if ((h("x-content-type-options") ?? "").toLowerCase() !== "nosniff") gaps.push("nosniff");
      if (!h("referrer-policy")) gaps.push("referrer-policy");
      evidence[s.name] = { url, status: res.status, xFrameOptions: h("x-frame-options"), nosniff: h("x-content-type-options"), referrerPolicy: h("referrer-policy"), cspFrameAncestors: /frame-ancestors/i.test(csp) };
      if (gaps.length) missing[s.name] = gaps;
    }
    const observed = { sites: list4.length, missing };
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
async function projects(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxProjects ?? 20;
  let ids = ctx.projects ?? [];
  if (ids.length === 0) {
    const r = await ctx.api.get("/projects?limit=100");
    if (r.status === 403) throw new Error("scope:projects.read");
    if (r.status !== 200) throw new Error("scope:api.projects");
    ids = (r.json?.projects ?? []).map((p) => p.id);
  }
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
  for (let page = 0; page < 5; page++) {
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
  version: 1,
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
    const observed = { services: list4.length, customDomains: domains, unverified: pending };
    return Object.keys(pending).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var notifyOnFail = {
  code: "render.service.notify_on_fail",
  provider: "render",
  version: 1,
  severity: "low",
  maps: ["soc2:A1.1", "soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.services", async () => {
    const list4 = (await services(ctx)).filter((s) => s.suspended !== "suspended");
    if (list4.length === 0) return unknown("api.no_services");
    const silent = list4.filter((s) => s.notifyOnFail === "ignore").map((s) => s.name);
    const observed = { services: list4.length, deployFailuresIgnored: silent };
    const evidence = list4.map((s) => ({ name: s.name, type: s.type, notifyOnFail: s.notifyOnFail ?? null }));
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
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.redirect_urls", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get("/redirect_urls");
    if (r.status === 403) throw new Error("scope:redirect_urls.read");
    if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.redirect_urls");
    const urls = r.json.map((u) => u.url ?? "").filter(Boolean);
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
    const users3 = r.json.filter((u) => u && u.id && !u.banned && !u.locked);
    if (r.json.length >= USER_CAP) return unknown("api.users.too_many", { users: r.json.length, cap: USER_CAP });
    if (users3.length === 0) return unknown("api.no_users");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    const dormant = users3.filter((u) => {
      const last = u.last_active_at ?? u.last_sign_in_at ?? null;
      if (last) return now - last > DORMANT_DAYS * DAY;
      return (u.created_at ?? now) < now - NEW_DAYS * DAY;
    });
    const observed = { users: users3.length, dormant: dormant.length, dormantDays: DORMANT_DAYS };
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
  for (let page = 1; page <= MAX_PAGES; page++) {
    const r = await ctx.api.get(`/monitors?per_page=250&page=${page}`);
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
    const live2 = (await monitors(ctx)).filter(active);
    if (live2.length === 0) return unknown("api.no_active_monitors");
    const slow = live2.filter((m) => !(typeof m.check_frequency === "number" && m.check_frequency <= MAX_FREQUENCY_SECONDS)).map(label);
    const observed = { monitors: live2.length, slowerThanSeconds: MAX_FREQUENCY_SECONDS, slow };
    const evidence = live2.map((m) => ({ name: label(m), checkFrequencySeconds: m.check_frequency ?? null }));
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
    const live2 = (await monitors(ctx)).filter(active);
    if (live2.length === 0) return unknown("api.no_active_monitors");
    const silent = live2.filter((m) => !(m.policy_id || m.call || m.sms || m.email || m.push)).map(label);
    const observed = { monitors: live2.length, withoutAlerts: silent };
    const evidence = live2.map((m) => ({ name: label(m), policy: Boolean(m.policy_id), call: m.call ?? false, sms: m.sms ?? false, email: m.email ?? false, push: m.push ?? false }));
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
var definerSearchPath = {
  code: "supabase.definer.search_path",
  provider: "supabase",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.28", "iso:8.2"],
  run: (ctx) => guarded("sql.catalogue", async () => {
    if (!ctx.sql) return unknown("sql.not_connected");
    const rows2 = await ctx.sql.query(`
        select n.nspname as schema, p.proname as name,
               coalesce(pg_catalog.array_to_string(p.proconfig, ','), '') as config
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where p.prosecdef and n.nspname in ('public', 'private')
        order by n.nspname, p.proname`);
    const unpinned = rows2.filter((r) => !String(r.config).includes("search_path")).map((r) => `${r.schema}.${r.name}`);
    const observed = { definerFunctions: rows2.length, unpinned };
    return unpinned.length === 0 ? pass(observed, rows2) : fail(observed, rows2);
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
  noAnonCallableFunctions
];
var SUPABASE_API_CHECKS = [
  authConfirmations,
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
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
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
  version: 2,
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
      for (const { name: name3, re } of SECRET_PATTERNS) {
        const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
        const n = (body.match(global) ?? []).length;
        if (!n) continue;
        if (isTest) {
          inTests[name3] = (inTests[name3] ?? 0) + n;
          testPaths.add(path);
        } else {
          found[name3] = (found[name3] ?? 0) + n;
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
    const configs = files.filter((f) => /^\.github\/dependabot\.ya?ml$|^(\.github\/)?renovate\.json5?$|^\.renovaterc(\.json)?$/.test(f));
    const observed = { configured: configs.length > 0, configs };
    return configs.length > 0 ? pass(observed, { configs }) : fail(observed, { configs });
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
  "meta.title": "Snoopios \u2014 continuous compliance for small software teams",
  "meta.description": "Snoopios watches the stack you actually run on \u2014 Supabase, Vercel, Cloudflare, GitHub, Stripe \u2014 collects real evidence, and turns it into the documents customers and auditors ask for. Flat price. No sales call.",
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
  "home.nav.how": "How it works",
  "home.nav.checks": "Checks",
  "home.nav.pricing": "Pricing",
  "home.nav.signin": "Sign in",
  "home.nav.start": "Start free",
  "home.nav.open": "Open app",
  // ── home: hero ────────────────────────────────────────────────────────────
  "home.hero.eyebrow": "Early access \xB7 built in the UK",
  "home.hero.title": "Two eyes on your stack. Evidence you can hand over.",
  "home.hero.body": "Snoopios connects read-only to Supabase, Vercel, Cloudflare, GitHub and Stripe, runs real configuration checks every hour on Studio and Scale and every six hours on Solo, and keeps the evidence. When a customer sends a security questionnaire or the ICO asks a question, the answer is already written.",
  "home.hero.cta": "Start with one project, free",
  "home.hero.secondary": "See what it checks",
  "home.hero.note": "For teams of one to twenty. Flat price by project, never by headcount. No sales call.",
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
  "home.problem.title": "Compliance tools weren't built for your stack, or your budget.",
  "home.problem.body": "Vanta and Drata start at five figures a year and are built around AWS and Okta. You're on Supabase and Vercel, you're the DPO and the on-call engineer, and the first enterprise customer just sent a forty-question spreadsheet.",
  "home.problem.p1.title": "The obligations don't wait",
  "home.problem.p1.body": "UK GDPR applies from your first user. Since June 2026 every controller needs a complaints procedure. A Stripe review wants a privacy policy that matches the code.",
  "home.problem.p2.title": "Nobody checks the things that matter",
  "home.problem.p2.body": "Is RLS on every table? Does any policy let anon write? Is a preview deployment open to the internet? The big platforms sync your user list and call it monitoring.",
  "home.problem.p3.title": "The documents rot",
  "home.problem.p3.body": "A privacy policy written once says things the code stopped doing months ago. That gap is a misrepresentation, not a typo.",
  // ── home: how it works ────────────────────────────────────────────────────
  "home.how.title": "How it works",
  "home.how.s1.title": "Connect, read-only",
  "home.how.s1.body": "Grant Snoopios read access through each provider's own consent screen. No write scope is ever requested. Revoke it from their dashboard any time.",
  "home.how.s2.title": "Checks run every hour",
  "home.how.s2.body": "Each check is code with a recorded fixture. It returns pass, fail or unknown, and a check that can't run says unknown \u2014 it never says pass.",
  "home.how.s3.title": "Evidence is kept, unchanged",
  "home.how.s3.body": "Every run stores the raw response, a timestamp and a hash. Nothing is edited after the fact. Corrections are new rows.",
  "home.how.s4.title": "Documents write themselves from the facts",
  "home.how.s4.body": "The sub-processor register comes from what's connected. Every policy claim links to a live check, so a sentence the code no longer honours is flagged in the document.",
  // ── home: checks ──────────────────────────────────────────────────────────
  "home.checks.title": "What it checks",
  "home.checks.body": "Thirty-nine read-only checks across five providers, each with a recorded fixture, and each one exists because it caught a real problem on a real app. More as customers ask.",
  "home.checks.supabase": "Supabase",
  "home.checks.supabase.items": "RLS enabled on every public table \xB7 no policy admits anon writes \xB7 private schema closed to session roles \xB7 search_path pinned on definer functions \xB7 email confirmation on \xB7 captcha on \xB7 backups or PITR on \xB7 SSL enforced \xB7 production SMTP configured \xB7 no undeclared public bucket",
  "home.checks.vercel": "Vercel",
  "home.checks.vercel.items": "preview deployment protection on \xB7 git fork protection on \xB7 domains verified and configured \xB7 sensitive-variable policy enforced \xB7 cron routes reject unauthenticated calls \xB7 SAML enforced or members reviewed",
  "home.checks.github": "GitHub",
  "home.checks.github.items": "default branch protected \xB7 Dependabot alerts on, none critical \xB7 no .env committed \xB7 .gitignore covers .env \xB7 SECURITY.md and CODEOWNERS present \xB7 outside collaborators reviewed",
  "home.checks.cloudflare": "Cloudflare",
  "home.checks.cloudflare.items": "DNSSEC active \xB7 TLS mode strict, minimum 1.2 \xB7 always HTTPS with HSTS \xB7 no R2 bucket publicly exposed \xB7 WAF managed ruleset deployed \xB7 Bot Fight Mode on",
  "home.checks.stripe": "Stripe",
  "home.checks.stripe.items": "every webhook endpoint enabled and pinned to an API version \xB7 no failed deliveries in 30 days \xB7 live mode with charges enabled",
  "home.checks.domain": "Your domain",
  "home.checks.domain.items": "CSP, HSTS, frame-ancestors, nosniff \xB7 HTTP redirects to HTTPS \xB7 HSTS preload status \xB7 SPF, DMARC and CAA present \xB7 TLS 1.2 minimum, certificate not expiring \xB7 security.txt present \xB7 privacy page names a controller and a date",
  "home.checks.aside": "No model decides whether you pass. The full feasibility table, endpoint by endpoint, is published in the documentation.",
  // ── home: the pack ────────────────────────────────────────────────────────
  "home.pack.title": "The pack",
  "home.pack.body": "The documents a customer, an auditor or the ICO asks for, generated from what's connected and checked against what's running. Every one is a draft for your review, and says so.",
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
  "home.pricing.body": "No per-seat pricing, no per-framework upsell, no renewal uplift. Annual pays for ten months. Cancel monthly plans any time.",
  "home.pricing.permonth": "/month",
  "home.pricing.free.note": "Evaluate on one project",
  "home.pricing.popular": "Most teams",
  "home.pricing.cta.free": "Start free",
  "home.pricing.cta.paid": "Start",
  "home.pricing.compare": "For comparison: the cheapest enterprise platform starts around \xA34,400 a year. Vanta's entry tier for a team your size is about \xA310,000.",
  // ── tiers (also read by lib/access-policy.ts) ────────────────────────────
  "tier.free.name": "Free",
  "tier.free.f1": "One project",
  "tier.free.f2": "Weekly checks",
  "tier.free.f3": "Dashboard and findings",
  "tier.free.f4": "No document exports",
  "tier.solo.name": "Solo",
  "tier.solo.f1": "One project",
  "tier.solo.f2": "Checks every six hours",
  "tier.solo.f3": "Evidence vault, 12 months",
  "tier.solo.f4": "Full document pack",
  "tier.solo.f5": "Public trust page",
  "tier.studio.name": "Studio",
  "tier.studio.f1": "Up to five projects",
  "tier.studio.f2": "Checks every hour",
  "tier.studio.f3": "Everything in Solo, plus the questionnaire answer bank",
  "tier.studio.f4": "Agency white-label trust pages",
  "tier.scale.name": "Scale",
  "tier.scale.f1": "Unlimited projects",
  "tier.scale.f2": "Checks every hour",
  "tier.scale.f3": "Everything in Studio, plus SOC 2 and ISO 27001 readiness maps",
  "tier.scale.f4": "Auditor export package",
  "tier.scale.f5": "Priority support",
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
  "home.who.title": "Built by the kind of company it's for.",
  "home.who.body": "Archema Labs runs five products on Supabase and Vercel with one developer. Every check in Snoopios exists because it caught something on one of them. The compliance pack is the one we wrote by hand, five times, before deciding to build the tool.",
  // ── auth ──────────────────────────────────────────────────────────────────
  "auth.signup.title": "Create your account",
  "auth.signup.frame": "One project free, no card. Confirm your email and you're in.",
  "auth.signup.cta": "Create account",
  // Private beta: the live site refuses sign-ups until the founder opens them
  // (NEXT_PUBLIC_SIGNUPS_OPEN and the Supabase config together).
  "auth.signup.closed.title": "Private beta",
  "auth.signup.closed.body": "Snoopios is running with a small group of founding customers while we finish the first release. If you have been invited, your invitation email has the sign-in link. If you would like to join, email us and we will be in touch.",
  "auth.signup.closed.signin": "Already have an account? Sign in",
  "auth.signup.closed.refused": "Sign-ups are closed for now. Email us to be invited.",
  "auth.signin.title": "Sign in",
  "auth.signin.cta": "Sign in",
  "auth.email.label": "Work email",
  "auth.password.label": "Password",
  "auth.password.hint": "At least ten characters. A sentence you'll remember beats a word you won't.",
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
  "conn.supabase.oauth.fallback": "Or connect with a personal access token. A token cannot be limited to reads by Supabase, so that connection shows as read-only requested.",
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
  "conn.supabase.token.hint": "Create one at supabase.com/dashboard/account/tokens. Give it an expiry; you'll be asked to reconnect when it lapses.",
  "conn.supabase.cta": "Connect read-only",
  "conn.supabase.error.ref": "A project ref is twenty lowercase letters and digits.",
  "conn.supabase.error.token": "That doesn't look like a Supabase personal access token.",
  "conn.github.title": "Connect GitHub",
  "conn.github.intro": "Until the GitHub App is listed, connect with a fine-grained personal access token scoped to read: Metadata, Contents, Administration, Dependabot alerts and Secret scanning alerts, plus Members if the owner is an organisation (a personal account has no Members permission; leave it out). Classic tokens are refused because they cannot be made read-only.",
  "conn.github.org.label": "Organisation or username",
  "conn.github.org.placeholder": "your-org or your-username",
  "conn.github.repos.label": "Repositories to check",
  "conn.github.repos.placeholder": "app, api, website",
  "conn.github.repos.hint": "Optional. Leave empty to check up to thirty active repositories.",
  "conn.github.token.label": "Fine-grained personal access token",
  "conn.github.token.placeholder": "github_pat_\u2026",
  "conn.github.token.hint": "Create it at github.com/settings/personal-access-tokens with an expiry. It is encrypted before it reaches the database.",
  "conn.github.cta": "Connect read-only",
  "conn.github.error.org": "A GitHub organisation or username is letters, digits and hyphens.",
  "conn.github.error.token": "That isn't a fine-grained token. Classic tokens (ghp_) are refused because they can't be scoped read-only.",
  "conn.cloudflare.title": "Connect Cloudflare",
  "conn.cloudflare.intro": "Create an API token with read permissions only: Zone Read, DNS Read, Zone Settings Read, Zone WAF Read, Bot Management Read, Workers R2 Storage Read, Turnstile Read, Cloudflare Pages Read and Access: Apps and Policies Read, scoped to the zones you want checked. Set an expiry and, if you can, restrict it to our IP ranges.",
  "conn.cloudflare.account.label": "Account ID",
  "conn.cloudflare.account.placeholder": "32 hex characters, from the dashboard overview",
  "conn.cloudflare.zones.label": "Zones to check",
  "conn.cloudflare.zones.placeholder": "example.com, api.example.com",
  "conn.cloudflare.zones.hint": "Optional. Leave empty to check every active zone the token can see, up to ten.",
  "conn.cloudflare.token.label": "API token",
  "conn.cloudflare.token.placeholder": "Token value, shown once by Cloudflare",
  "conn.cloudflare.token.hint": "Turnstile cannot be read by an account-owned token; that check will show unknown rather than fail.",
  "conn.cloudflare.cta": "Connect read-only",
  "conn.cloudflare.error.account": "An account ID is 32 hexadecimal characters.",
  "conn.cloudflare.error.token": "That doesn't look like a Cloudflare API token.",
  "conn.stripe.title": "Connect Stripe",
  "conn.stripe.intro": "Create a restricted key with Read on Webhook Endpoints, Events and Account, nothing else. Secret keys are refused: nothing here needs one.",
  "conn.stripe.key.label": "Restricted key",
  "conn.stripe.key.placeholder": "rk_live_\u2026",
  "conn.stripe.key.hint": "Developers \u2192 API keys \u2192 Create restricted key. Add an IP allow-list for our egress ranges if you can.",
  "conn.stripe.cta": "Connect read-only",
  "conn.stripe.error.key": "That isn't a restricted key. Secret keys (sk_) are refused; create a restricted key with Read permissions.",
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
  "check.domain.headers.csp.title": "A Content-Security-Policy that stops exfiltration",
  "check.domain.headers.csp.pass": "A CSP is present with object-src 'none', base-uri 'self' and frame-ancestors.",
  "check.domain.headers.csp.fail": "No CSP, or one without object-src 'none', base-uri 'self' and frame-ancestors.",
  "check.domain.headers.csp.fix": "Ship a policy even if it needs 'unsafe-inline' for hydration: object-src 'none', base-uri 'self', form-action 'self', frame-ancestors 'none', and a connect-src limited to your own backends. A policy that stops exfiltration is worth having even when it cannot stop execution.",
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
  "check.domain.dns.dmarc.fix": "Publish a TXT record at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>. Start with quarantine and pct=100 once the reports show every legitimate sender aligns, then move to reject.",
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
  "check.supabase.definer.search_path.pass": "Every SECURITY DEFINER function in public and private sets search_path.",
  "check.supabase.definer.search_path.fail": "A SECURITY DEFINER function has no search_path, so a caller can put a schema in front and run their own code as the definer.",
  "check.supabase.definer.search_path.fix": "Add set search_path = '' to each function and schema-qualify every reference inside it. This is the most common SECURITY DEFINER vulnerability and the cheapest to fix.",
  "check.supabase.functions.anon_callable.title": "Anon-callable SECURITY DEFINER functions are safe to expose",
  "check.supabase.functions.anon_callable.pass": "Every SECURITY DEFINER function the anon role can execute pins its search_path and takes no caller-supplied identity. They are listed for review.",
  "check.supabase.functions.anon_callable.fail": "An unauthenticated request can execute a definer function that has no pinned search_path, or that accepts a user, org or account id as an argument.",
  "check.supabase.functions.anon_callable.fix": "For each function listed: add set search_path = '' and remove any user_id, org_id or account_id parameter, deriving identity from auth.uid() inside. If anon has no business calling it, revoke execute on function public.<name>(...) from anon.",
  "check.supabase.auth.confirmations.title": "Email confirmation on, OTP of 8 or more",
  "check.supabase.auth.confirmations.pass": "Sign-ups must confirm their address and the email OTP is at least 8 characters.",
  "check.supabase.auth.confirmations.fail": "Sign-ups are auto-confirmed or the OTP is short enough to guess.",
  "check.supabase.auth.confirmations.fix": "In Authentication settings turn on Confirm email and set the OTP length to 8 or more. Turning confirmation on is a product change too: make sure the app has a confirmation screen and the trial clock starts at confirmation.",
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
  "check.netlify.site.force_https.pass": "Every site has SSL on and forces HTTPS.",
  "check.netlify.site.force_https.fail": "At least one site serves plain HTTP without redirecting to HTTPS.",
  "check.netlify.site.force_https.fix": "Site settings \u2192 Domain management \u2192 HTTPS \u2192 Force HTTPS, on every site.",
  "check.netlify.site.protected.title": "Sites are behind site protection",
  "check.netlify.site.protected.pass": "Every site has password protection set, so previews and branch deploys are not public.",
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
  "check.atlas.project.ip_access_list.fail": "The project's IP access list admits every address (0.0.0.0/0) or is empty, so the password is the only barrier, or nothing can connect at all.",
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
  "check.atlas.db_users.least_privilege.title": "No database user holds an admin role",
  "check.atlas.db_users.least_privilege.pass": "Every database user holds only database-scoped roles.",
  "check.atlas.db_users.least_privilege.fail": "At least one database user holds an admin role (atlasAdmin, root, readWriteAnyDatabase, dbAdminAnyDatabase, userAdminAnyDatabase or clusterAdmin), so a leaked application credential is a full takeover.",
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
  "check.bitbucket.deploy_keys.recent.title": "Deploy keys in use",
  "check.bitbucket.deploy_keys.recent.pass": "Every deploy key was used in the last ninety days or added in the last thirty.",
  "check.bitbucket.deploy_keys.recent.fail": "At least one deploy key has not been used for ninety days, so it is a standing credential nobody is watching.",
  "check.bitbucket.deploy_keys.recent.fix": "Bitbucket \u2192 the repository \u2192 Repository settings \u2192 Access keys: delete the stale keys. Prefer short-lived pipeline credentials to standing keys.",
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
  "conn.bitbucket.intro": "Create an Atlassian API token with scopes (Account settings \u2192 Security \u2192 API tokens \u2192 Create API token with scopes \u2192 Bitbucket) and tick only read:repository, read:pullrequest, read:pipeline, read:ssh-key, read:user and read:workspace. Bitbucket sometimes reports a token's scopes back; when it does, a write scope is refused. Otherwise the connection shows as read-only requested and every request is limited to reads by code.",
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
  "conn.google.intro": "A super-admin grants Snoopios two read-only Admin SDK scopes (users and domains). Google returns a refresh token, which is stored encrypted; nothing is written, and a grant with more scopes than asked is refused.",
  "conn.google.cta": "Grant read-only access on Google",
  "conn.google.label": "Google Workspace",
  "conn.google.connected": "Google Workspace is connected. The first run starts within a minute.",
  "conn.google.scopes": "Google granted different scopes from the two read-only ones requested, so the connection was refused. Try again and leave the scopes as shown.",
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
  "check.email.mta_sts.pass": "An MTA-STS record exists and the policy at mta-sts.yourdomain is in enforce mode.",
  "check.email.mta_sts.fail": "No MTA-STS policy in enforce mode. Mail sent to this domain can be downgraded to plain text by an attacker on the path.",
  "check.email.mta_sts.fix": "Publish _mta-sts.yourdomain TXT v=STSv1; id=<date>, and serve https://mta-sts.yourdomain/.well-known/mta-sts.txt with version: STSv1, mode: enforce, your mx: lines and max_age: 604800. Run in testing mode for a week first if you receive mail through more than one provider.",
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
  "privacy.updated": "Last updated 6 September 2026",
  "privacy.intro": "This notice describes what Snoopios does with personal data today. Every sentence describes code that exists. A solicitor reviews it before launch; until then it is a draft that is nonetheless true.",
  "privacy.s1.h": "Who we are",
  "privacy.s1.p": "Snoopios is a product of Archema Labs, a company in the United Kingdom and the controller for the data described here. Archema Labs is registered with the Information Commissioner's Office.",
  "privacy.s2.h": "Accounts",
  "privacy.s2.p": "When you create an account we hold your email address, the name you give, and a password hash kept by our authentication provider. We use them to sign you in, to send the emails the product needs (confirmation, a check that starts failing, a document access decision), and for nothing else. There is no marketing list.",
  "privacy.s3.h": "Projects and connections",
  "privacy.s3.p": "The tokens you connect are encrypted before they reach our database with a key that is not stored there, are used only to read configuration from the provider, and are deleted the moment you remove the connection. Each check stores the raw response it read as evidence, kept for the number of months your plan states and then deleted by a nightly job. Documents you attach to a control as your own evidence are stored in a private bucket for your organisation, reviewed by a fixed checklist and never by a model, kept for the life of the account, and included in your export. Evidence can contain identifiers from your own systems; it is never shared with anyone but the members of your organisation. If you confirm a statement about your organisation on a control, we record your name, the time and the words you confirmed, and show them to the members of your organisation. If you ask for written feedback on a document you attached, its text and the review lines are sent once to an AI language model provider, which returns the suggestions; nothing is sent unless you ask, and the feature stays switched off until that provider's agreement, retention and region are recorded in this notice.",
  "privacy.s4.h": "Visitors to a trust page",
  "privacy.s4.p": "If you request documents from a customer's trust page we hold the name, work email and company you give, the time you accepted the confidentiality undertaking, a keyed hash of your IP address for abuse limits, the decision, and a record of each download. The customer whose page it is sees this register; that customer, not Snoopios, decides your request. Requests are kept for 24 months and then deleted.",
  "privacy.s5.h": "Who else is involved",
  "privacy.s5.p": "Data is held in a Supabase project in London. The application runs on Vercel and is served through Cloudflare, which see the ordinary technical data any web server sees, such as your IP address, to deliver pages and defend against abuse. Email is sent through Resend. No advertising or analytics scripts run anywhere on the site, so there is no consent banner.",
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

// ../lib/checks/providers/github.ts
async function ownerType(ctx) {
  if (ctx.ownerType) return ctx.ownerType;
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(`/users/${encodeURIComponent(ctx.org)}`);
  if (r.status !== 200) throw new Error("scope:api.owner");
  ctx.ownerType = r.json.type === "Organization" ? "org" : "user";
  return ctx.ownerType;
}
async function listRepos(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxRepos ?? 30;
  if (ctx.repos && ctx.repos.length) {
    const out = [];
    for (const name3 of ctx.repos.slice(0, max)) {
      const r2 = await ctx.api.get(`/repos/${ctx.org}/${name3}`);
      if (r2.status === 200) out.push(r2.json);
    }
    return out;
  }
  const kind = await ownerType(ctx);
  const r = await ctx.api.get(kind === "org" ? `/orgs/${ctx.org}/repos?per_page=100&type=all&sort=pushed` : `/user/repos?affiliation=owner&per_page=100&sort=pushed`);
  if (r.status !== 200) throw new Error("scope:api.repos");
  const owner = ctx.org.toLowerCase();
  return r.json.filter((x) => !x.archived && !x.fork).filter((x) => kind === "org" || (x.owner?.login ?? "").toLowerCase() === owner).slice(0, max);
}
var org2fa = {
  code: "github.org.2fa",
  provider: "github",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5", "iso:5.17"],
  run: (ctx) => guarded("api.org", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const r = await ctx.api.get(`/orgs/${ctx.org}`);
    if (r.status !== 200) return unknown("api.org");
    const org = r.json;
    if (org.two_factor_requirement_enabled == null) return unknown("api.org_2fa_hidden", { visible: false });
    const observed = { required: org.two_factor_requirement_enabled };
    return observed.required ? pass(observed, org) : fail(observed, org);
  })
};
var branchProtection = {
  code: "github.repo.default_branch_protected",
  provider: "github",
  version: 1,
  severity: "high",
  maps: ["soc2:CC8.1", "iso:8.32", "iso:8.25"],
  run: (ctx) => guarded("api.repos", async () => {
    const repos2 = await listRepos(ctx);
    const unprotected = [];
    const evidence = {};
    for (const repo2 of repos2) {
      const rules = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/rules/branches/${encodeURIComponent(repo2.default_branch)}`);
      const ruleTypes = rules.status === 200 ? rules.json.map((x) => x.type) : [];
      let protectedBranch = ruleTypes.includes("pull_request") || ruleTypes.includes("non_fast_forward");
      if (!protectedBranch) {
        const classic = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/branches/${encodeURIComponent(repo2.default_branch)}/protection`);
        protectedBranch = classic.status === 200;
        evidence[repo2.name] = { rules: rules.json, classic: classic.status === 200 ? classic.json : null };
      } else {
        evidence[repo2.name] = { rules: rules.json };
      }
      if (!protectedBranch) unprotected.push(repo2.name);
    }
    const observed = { repos: repos2.length, unprotected };
    return unprotected.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var dependabot = {
  code: "github.repo.dependabot",
  provider: "github",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.1", "ce:patching", "iso:8.8"],
  run: (ctx) => guarded("api.repos", async () => {
    const repos2 = await listRepos(ctx);
    const disabled = [];
    const openCritical = {};
    const evidence = {};
    for (const repo2 of repos2) {
      const enabled = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/vulnerability-alerts`);
      if (enabled.status !== 204) {
        disabled.push(repo2.name);
        evidence[repo2.name] = { enabled: false };
        continue;
      }
      const alerts = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/dependabot/alerts?state=open&severity=critical,high&per_page=100`);
      const n = alerts.status === 200 ? alerts.json.length : 0;
      if (n > 0) openCritical[repo2.name] = n;
      evidence[repo2.name] = { enabled: true, openCriticalOrHigh: n };
    }
    const observed = { repos: repos2.length, disabled, openCriticalOrHigh: openCritical };
    const ok = disabled.length === 0 && Object.keys(openCritical).length === 0;
    return ok ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var secretScanning = {
  code: "github.repo.secret_scanning",
  provider: "github",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.12", "iso:8.28"],
  run: (ctx) => guarded("api.repos", async () => {
    const repos2 = await listRepos(ctx);
    const off = [];
    const unverifiedPush = [];
    const evidence = {};
    for (const repo2 of repos2) {
      const sa = repo2.security_and_analysis;
      if (sa) {
        evidence[repo2.name] = sa;
        const scanning = sa.secret_scanning?.status === "enabled";
        const push2 = sa.secret_scanning_push_protection?.status === "enabled";
        if (!scanning || !push2) off.push(repo2.name);
        continue;
      }
      const probe = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/secret-scanning/alerts?per_page=1`);
      const message = String(probe.json?.message ?? "");
      if (probe.status === 200) {
        evidence[repo2.name] = { probe: "alerts", status: 200, scanning: true, pushProtection: "unverified" };
        unverifiedPush.push(repo2.name);
      } else if (probe.status === 404 && /disabled|not enabled|not available/i.test(message)) {
        evidence[repo2.name] = { probe: "alerts", status: 404, message, scanning: false };
        off.push(repo2.name);
      } else {
        return unknown("api.secret_scanning_probe", { repo: repo2.name, status: probe.status });
      }
    }
    const purchasable = off.length === 0 ? null : await ownerType(ctx) === "org";
    const observed = { repos: repos2.length, missingScanningOrPushProtection: off, pushProtectionUnverified: unverifiedPush, secretProtectionPurchasable: purchasable };
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var ENV_PATH2 = /(^|\/)\.env(\.[^/]+)?$/;
var ENV_ALLOWED2 = /\.env\.(example|sample|template|dist)$/;
var noEnvCommitted = {
  code: "github.repo.no_env_committed",
  provider: "github",
  version: 1,
  severity: "critical",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.12", "iso:5.17"],
  run: (ctx) => guarded("api.tree", async () => {
    const repos2 = await listRepos(ctx);
    const offenders = {};
    const evidence = {};
    for (const repo2 of repos2) {
      const tree = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/git/trees/${encodeURIComponent(repo2.default_branch)}?recursive=1`);
      if (tree.status !== 200) {
        evidence[repo2.name] = { status: tree.status };
        continue;
      }
      const t = tree.json;
      const hits = t.tree.filter((e) => e.type === "blob" && ENV_PATH2.test(e.path) && !ENV_ALLOWED2.test(e.path)).map((e) => e.path);
      if (hits.length) offenders[repo2.name] = hits;
      evidence[repo2.name] = { truncated: Boolean(t.truncated), envFiles: hits, entries: t.tree.length };
    }
    const observed = { repos: repos2.length, offenders };
    return Object.keys(offenders).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var repoHygiene = {
  code: "github.repo.hygiene",
  provider: "github",
  version: 1,
  severity: "medium",
  maps: ["iso:8.25", "iso:5.24", "soc2:CC7.3"],
  run: (ctx) => guarded("api.contents", async () => {
    const repos2 = await listRepos(ctx);
    const missing = {};
    const evidence = {};
    for (const repo2 of repos2) {
      const gaps = [];
      const gi = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/contents/.gitignore`);
      let ignoresEnv = false;
      if (gi.status === 200) {
        const body = Buffer.from(String(gi.json.content ?? ""), "base64").toString("utf8");
        ignoresEnv = /^\s*\.env(\*|\.\*|\.local|$)/m.test(body) || /^\s*\*\.env/m.test(body) || /^\s*\.env\*?\.local/m.test(body);
      }
      if (!ignoresEnv) gaps.push(".gitignore covers .env");
      const sec = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/contents/SECURITY.md`);
      if (sec.status !== 200) gaps.push("SECURITY.md");
      let codeowners = false;
      for (const p of ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]) {
        const co = await ctx.api.get(`/repos/${ctx.org}/${repo2.name}/contents/${p}`);
        if (co.status === 200) {
          codeowners = true;
          break;
        }
      }
      if (!codeowners) gaps.push("CODEOWNERS");
      if (gaps.length) missing[repo2.name] = gaps;
      evidence[repo2.name] = { ignoresEnv, securityMd: sec.status === 200, codeowners };
    }
    const observed = { repos: repos2.length, missing };
    return Object.keys(missing).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var outsideCollaborators = {
  code: "github.org.outside_collaborators",
  provider: "github",
  version: 1,
  severity: "low",
  maps: ["soc2:CC6.2", "ce:user-access", "iso:5.18", "iso:8.4"],
  run: (ctx) => guarded("api.org", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const r = await ctx.api.get(`/orgs/${ctx.org}/outside_collaborators?per_page=100`);
    if (r.status !== 200) return unknown("api.outside_collaborators");
    const list4 = r.json.map((x) => x.login);
    const observed = { count: list4.length, logins: list4 };
    return list4.length === 0 ? pass(observed, r.json) : fail(observed, r.json);
  })
};
var GITHUB_CHECKS = [
  org2fa,
  branchProtection,
  secretScanning,
  dependabot,
  noEnvCommitted,
  repoHygiene,
  outsideCollaborators
];

// ../lib/checks/providers/cloudflare.ts
async function listZones(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(`/zones?account.id=${encodeURIComponent(ctx.accountId)}&per_page=50&status=active`);
  if (r.status !== 200) throw new Error("scope:api.zones");
  let zones = r.json.result ?? [];
  if (ctx.zones?.length) zones = zones.filter((z) => ctx.zones.includes(z.name));
  return zones.slice(0, ctx.maxZones ?? 10);
}
async function setting(ctx, zoneId, id) {
  const r = await ctx.api.get(`/zones/${zoneId}/settings/${id}`);
  if (r.status !== 200) return null;
  return r.json.result?.value ?? null;
}
var dnssec = {
  code: "cloudflare.zone.dnssec",
  provider: "cloudflare",
  version: 1,
  severity: "medium",
  maps: ["ce:secure-config", "iso:8.20"],
  run: (ctx) => guarded("api.zones", async () => {
    const zones = await listZones(ctx);
    const off = [];
    const evidence = {};
    for (const z of zones) {
      const r = await ctx.api.get(`/zones/${z.id}/dnssec`);
      const status = r.status === 200 ? r.json.result?.status : null;
      evidence[z.name] = r.json;
      if (status !== "active") off.push(z.name);
    }
    const observed = { zones: zones.length, dnssecNotActive: off };
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var tlsStrict = {
  code: "cloudflare.tls.strict",
  provider: "cloudflare",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("api.settings", async () => {
    const zones = await listZones(ctx);
    const weak = {};
    const evidence = {};
    for (const z of zones) {
      const ssl = await setting(ctx, z.id, "ssl");
      const minTls = await setting(ctx, z.id, "min_tls_version");
      evidence[z.name] = { ssl, minTls };
      const ok = ssl === "strict" && (minTls === "1.2" || minTls === "1.3");
      if (!ok) weak[z.name] = { ssl, minTls };
    }
    const observed = { zones: zones.length, weak };
    return Object.keys(weak).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var alwaysHttps = {
  code: "cloudflare.https.always",
  provider: "cloudflare",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("api.settings", async () => {
    const zones = await listZones(ctx);
    const off = [];
    const evidence = {};
    for (const z of zones) {
      const always = await setting(ctx, z.id, "always_use_https");
      const sh = await setting(ctx, z.id, "security_header");
      const hsts = sh?.strict_transport_security;
      evidence[z.name] = { always, hsts };
      const ok = always === "on" && hsts?.enabled === true && (hsts.max_age ?? 0) >= 31536e3 && hsts.include_subdomains === true;
      if (!ok) off.push(z.name);
    }
    const observed = { zones: zones.length, notEnforced: off };
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var r2NoPublic = {
  code: "cloudflare.r2.no_public_bucket",
  provider: "cloudflare",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "gdpr:art32", "iso:8.3", "iso:8.12"],
  run: (ctx) => guarded("api.r2", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const zones = await listZones(ctx);
    const zoneNames = zones.map((z) => z.name.toLowerCase());
    const inZone = (host) => zoneNames.some((z) => host === z || host.endsWith("." + z));
    const exposed = [];
    const outside = [];
    const evidence = {};
    let total = 0;
    for (const jur of ["default", "eu", "us"]) {
      const r = await ctx.api.get(`/accounts/${ctx.accountId}/r2/buckets?per_page=100`, { "cf-r2-jurisdiction": jur });
      if (r.status === 403) return unknown("api.r2_forbidden");
      if (r.status !== 200) continue;
      const buckets = r.json.result?.buckets ?? [];
      for (const b of buckets) {
        total++;
        const m = await ctx.api.get(`/accounts/${ctx.accountId}/r2/buckets/${encodeURIComponent(b.name)}/domains/managed`, { "cf-r2-jurisdiction": jur });
        const enabled = m.status === 200 ? m.json.result?.enabled : null;
        const c = await ctx.api.get(`/accounts/${ctx.accountId}/r2/buckets/${encodeURIComponent(b.name)}/domains/custom`, { "cf-r2-jurisdiction": jur });
        const customDomains = c.status === 200 ? (c.json.result?.domains ?? []).map((d) => d.domain.toLowerCase()) : [];
        evidence[`${jur}/${b.name}`] = { managed: m.json, customDomains };
        if (enabled !== true) continue;
        if (customDomains.some(inZone)) exposed.push(b.name);
        else outside.push(b.name);
      }
    }
    const unique = [...new Set(exposed)];
    const observed = { buckets: total, zones: zoneNames, publicViaR2Dev: unique, publicOutsideProject: [...new Set(outside)] };
    return unique.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var wafManaged = {
  code: "cloudflare.waf.managed",
  provider: "cloudflare",
  version: 2,
  severity: "medium",
  maps: ["ce:firewalls", "iso:8.20", "iso:8.21", "soc2:CC6.6"],
  run: (ctx) => guarded("api.rulesets", async () => {
    const zones = await listZones(ctx);
    const missing = [];
    const evidence = {};
    const freeZones = [];
    for (const z of zones) {
      const r = await ctx.api.get(`/zones/${z.id}/rulesets/phases/http_request_firewall_managed/entrypoint`);
      const rules = r.status === 200 ? r.json.result?.rules ?? [] : [];
      let deployed = rules.some((x) => x.action === "execute" && x.enabled !== false);
      if (!deployed && r.status === 404 && z.plan?.legacy_id === "free") {
        deployed = true;
        freeZones.push(z.name);
      }
      evidence[z.name] = r.status === 200 ? r.json : { status: r.status, plan: z.plan?.legacy_id ?? null };
      if (!deployed) missing.push(z.name);
    }
    const observed = { zones: zones.length, noManagedRuleset: missing, freePlanManagedByCloudflare: freeZones };
    return missing.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var botFightMode = {
  code: "cloudflare.bot.fight_mode",
  provider: "cloudflare",
  version: 1,
  severity: "low",
  maps: ["ce:firewalls", "iso:8.20", "soc2:CC6.6"],
  run: (ctx) => guarded("api.bot_management", async () => {
    const zones = await listZones(ctx);
    const off = [];
    const evidence = {};
    for (const z of zones) {
      const r = await ctx.api.get(`/zones/${z.id}/bot_management`);
      if (r.status === 403) return unknown("api.bot_management_forbidden");
      const cfg = r.status === 200 ? r.json.result : null;
      evidence[z.name] = cfg;
      const on = cfg?.fight_mode === true || cfg?.sbfm_definitely_automated === "block" || cfg?.sbfm_definitely_automated === "managed_challenge";
      if (!on) off.push(z.name);
    }
    const observed = { zones: zones.length, botProtectionOff: off };
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var turnstileWidgets = {
  code: "cloudflare.turnstile.widgets",
  provider: "cloudflare",
  version: 1,
  severity: "low",
  maps: ["soc2:CC6.6", "iso:8.5"],
  run: (ctx) => guarded("api.turnstile", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const zones = await listZones(ctx);
    const r = await ctx.api.get(`/accounts/${ctx.accountId}/challenges/widgets?per_page=100`);
    if (r.status === 403) return unknown("api.turnstile_forbidden");
    if (r.status !== 200) return unknown("api.turnstile");
    const widgets = r.json.result ?? [];
    const covered = new Set(widgets.flatMap((w) => w.domains));
    const uncovered = zones.map((z) => z.name).filter((n) => ![...covered].some((d) => d === n || d.endsWith(`.${n}`)));
    const observed = { widgets: widgets.length, zonesWithoutWidget: uncovered };
    return widgets.length > 0 && uncovered.length === 0 ? pass(observed, widgets) : fail(observed, widgets);
  })
};
async function pagesProjects(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(`/accounts/${ctx.accountId}/pages/projects`);
  if (r.status === 403) return null;
  if (r.status !== 200) throw new Error("scope:api.pages");
  return (r.json.result ?? []).filter((p) => p && p.name);
}
var COMPAT_MAX_DAYS = 365;
var pagesCompatDate = {
  code: "cloudflare.pages.compat_date",
  provider: "cloudflare",
  version: 1,
  severity: "medium",
  maps: ["ce:patching", "iso:8.8", "soc2:CC7.1"],
  run: (ctx) => guarded("api.pages", async () => {
    const projects4 = await pagesProjects(ctx);
    if (projects4 === null) return unknown("pages.readonly");
    if (projects4.length === 0) return unknown("api.no_pages_projects");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    const stale = {};
    const evidence = {};
    for (const p of projects4) {
      const date = p.deployment_configs?.production?.compatibility_date ?? null;
      const age = date ? Math.floor((now - new Date(date).getTime()) / 864e5) : null;
      evidence[p.name] = { compatibilityDate: date, ageDays: age };
      if (age === null || age > COMPAT_MAX_DAYS) stale[p.name] = date;
    }
    const observed = { projects: projects4.length, maxAgeDays: COMPAT_MAX_DAYS, stale };
    return Object.keys(stale).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var pagesPreviewProtected = {
  code: "cloudflare.pages.preview_protected",
  provider: "cloudflare",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "soc2:CC8.1", "iso:8.31"],
  run: (ctx) => guarded("api.pages", async () => {
    const projects4 = await pagesProjects(ctx);
    if (projects4 === null) return unknown("pages.readonly");
    if (projects4.length === 0) return unknown("api.no_pages_projects");
    const r = await ctx.api.get(`/accounts/${ctx.accountId}/access/apps?per_page=100`);
    const notEnabled = r.status === 403 && /not_enabled/i.test(JSON.stringify(r.json ?? ""));
    if (r.status === 403 && !notEnabled) return unknown("access.readonly");
    if (r.status !== 200 && !notEnabled) throw new Error("scope:api.access");
    const apps3 = notEnabled ? [] : r.json.result ?? [];
    const domains = apps3.flatMap((a) => [a.domain ?? "", ...a.self_hosted_domains ?? []]).map((d) => d.toLowerCase());
    const covered = (name3) => domains.some((d) => d === `${name3}.pages.dev` || d === `*.${name3}.pages.dev` || d.endsWith(`.${name3}.pages.dev`));
    const open = projects4.filter((p) => !covered(p.name)).map((p) => p.name);
    const observed = { projects: projects4.length, accessApplications: apps3.length, unprotected: open };
    const evidence = { projects: projects4.map((p) => p.name), accessDomains: domains };
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var CLOUDFLARE_CHECKS = [
  tlsStrict,
  alwaysHttps,
  dnssec,
  wafManaged,
  botFightMode,
  r2NoPublic,
  turnstileWidgets,
  pagesCompatDate,
  pagesPreviewProtected
];

// ../lib/checks/providers/stripe.ts
var webhooksHealthy = {
  code: "stripe.webhooks.healthy",
  provider: "stripe",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.2", "iso:8.16", "iso:8.26"],
  run: (ctx) => guarded("api.webhook_endpoints", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const r = await ctx.api.get("/v1/webhook_endpoints?limit=100");
    if (r.status === 403) return unknown("api.webhooks_forbidden");
    if (r.status !== 200) return unknown("api.webhook_endpoints");
    const list4 = (r.json.data ?? []).map((e) => ({
      id: e.id,
      url: e.url,
      status: e.status,
      api_version: e.api_version,
      livemode: e.livemode,
      events: e.enabled_events?.length ?? 0
    }));
    const problems = {};
    for (const e of list4) {
      const p = [];
      if (e.status !== "enabled") p.push("disabled");
      if (!e.api_version) p.push("api version not pinned");
      if (!/^https:\/\//.test(e.url) || /localhost|127\.0\.0\.1|ngrok|trycloudflare\.com|\.vercel\.app|\.netlify\.app|\.local(\/|$)/.test(e.url)) p.push("url not production");
      if (p.length) problems[e.id] = p;
    }
    const observed = { endpoints: list4.length, problems };
    const ok = list4.length > 0 && Object.keys(problems).length === 0;
    return ok ? pass(observed, list4) : fail(observed, list4);
  })
};
var noFailedDeliveries = {
  code: "stripe.webhooks.deliveries",
  provider: "stripe",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.events", async () => {
    if (!ctx.api) return unknown("api.not_connected");
    const since = Math.floor(Date.now() / 1e3) - 30 * 86400;
    const r = await ctx.api.get(`/v1/events?delivery_success=false&created[gte]=${since}&limit=100`);
    if (r.status === 403) return unknown("api.events_forbidden");
    if (r.status !== 200) return unknown("api.events");
    const data = r.json.data ?? [];
    const byType = {};
    for (const e of data) byType[e.type] = (byType[e.type] ?? 0) + 1;
    const observed = { undeliveredLast30Days: data.length, byType };
    const evidence = data.map((e) => ({ id: e.id, type: e.type, created: e.created, pending_webhooks: e.pending_webhooks }));
    return data.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var STRIPE_CHECKS = [webhooksHealthy, noFailedDeliveries];

// ../lib/checks/providers/sentry.ts
var WRITE_SCOPE = /:(write|admin|releases|ci)$/;
async function organisation(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(`/organizations/${encodeURIComponent(ctx.org)}/`);
  if (r.status === 403 || r.status === 404) throw new Error("scope:org.access");
  if (r.status !== 200) throw new Error("scope:api.org");
  const org = r.json;
  if ((org.access ?? []).some((s) => WRITE_SCOPE.test(s))) throw new Error("scope:token.write_scope");
  return org;
}
function maskEmail(email) {
  if (!email || !email.includes("@")) return "?";
  const [local, domain] = email.split("@");
  return `${local.slice(0, 1)}\u2026@${domain}`;
}
var orgSubset = (o) => ({
  slug: o.slug,
  require2FA: o.require2FA,
  dataScrubber: o.dataScrubber,
  dataScrubberDefaults: o.dataScrubberDefaults,
  scrubIPAddresses: o.scrubIPAddresses,
  sensitiveFields: o.sensitiveFields,
  storeCrashReports: o.storeCrashReports,
  allowSharedIssues: o.allowSharedIssues,
  enhancedPrivacy: o.enhancedPrivacy,
  openMembership: o.openMembership,
  allowJoinRequests: o.allowJoinRequests
});
var require2fa = {
  code: "sentry.org.require_2fa",
  provider: "sentry",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.org", async () => {
    const org = await organisation(ctx);
    if (org.require2FA == null) return unknown("api.org_2fa_hidden");
    const observed = { required: org.require2FA === true };
    return observed.required ? pass(observed, orgSubset(org)) : fail(observed, orgSubset(org));
  })
};
var members2fa = {
  code: "sentry.members.2fa",
  provider: "sentry",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.members", async () => {
    await organisation(ctx);
    const r = await ctx.api.get(`/organizations/${encodeURIComponent(ctx.org)}/members/?per_page=100`);
    if (r.status !== 200) throw new Error("scope:api.members");
    const members2 = (r.json ?? []).filter((m) => m && !m.pending && !m.expired && m.user);
    const flags = members2.map((m) => m.user?.has2fa);
    if (members2.length > 0 && flags.every((f) => f == null)) return unknown("api.members_2fa_hidden", { members: members2.length });
    const without = members2.filter((m) => m.user?.has2fa !== true).map((m) => `${m.role ?? "member"} ${maskEmail(m.email)}`);
    const observed = { members: members2.length, without2fa: without };
    const evidence = members2.map((m) => ({ role: m.role, email: maskEmail(m.email), has2fa: m.user?.has2fa ?? null }));
    return without.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var orgScrubbing = {
  code: "sentry.org.data_scrubbing",
  provider: "sentry",
  version: 1,
  severity: "high",
  maps: ["gdpr:art5", "gdpr:art25", "iso:8.11", "soc2:CC6.7"],
  run: (ctx) => guarded("api.org", async () => {
    const org = await organisation(ctx);
    const observed = {
      dataScrubber: org.dataScrubber === true,
      defaults: org.dataScrubberDefaults === true,
      scrubIpAddresses: org.scrubIPAddresses === true,
      sensitiveFields: (org.sensitiveFields ?? []).length
    };
    const ok = observed.dataScrubber && observed.defaults && observed.scrubIpAddresses;
    return ok ? pass(observed, orgSubset(org)) : fail(observed, orgSubset(org));
  })
};
var projectScrubbing = {
  code: "sentry.projects.data_scrubbing",
  provider: "sentry",
  version: 1,
  severity: "medium",
  maps: ["gdpr:art5", "gdpr:art25", "iso:8.11"],
  run: (ctx) => guarded("api.projects", async () => {
    await organisation(ctx);
    const r = await ctx.api.get(`/organizations/${encodeURIComponent(ctx.org)}/projects/?per_page=100`);
    if (r.status !== 200) throw new Error("scope:api.projects");
    const list4 = (r.json ?? []).filter((p) => p && p.slug).slice(0, ctx.maxProjects ?? 30);
    const weak = [];
    const evidence = {};
    for (const p of list4) {
      const d = await ctx.api.get(`/projects/${encodeURIComponent(ctx.org)}/${encodeURIComponent(p.slug)}/`);
      if (d.status !== 200) throw new Error("scope:api.project");
      const proj = d.json;
      const scrubbing = proj.dataScrubber !== false && proj.scrubIPAddresses !== false;
      const crashDumps = typeof proj.storeCrashReports === "number" && proj.storeCrashReports !== 0;
      evidence[p.slug] = { dataScrubber: proj.dataScrubber, scrubIPAddresses: proj.scrubIPAddresses, storeCrashReports: proj.storeCrashReports, scrapeJavaScript: proj.scrapeJavaScript };
      if (!scrubbing || crashDumps) weak.push(p.slug);
    }
    const observed = { projects: list4.length, weak };
    return weak.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var membershipClosed = {
  code: "sentry.org.membership_closed",
  provider: "sentry",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.2", "iso:5.16", "iso:5.18"],
  run: (ctx) => guarded("api.org", async () => {
    const org = await organisation(ctx);
    const observed = { openMembership: org.openMembership === true, allowJoinRequests: org.allowJoinRequests === true };
    const ok = !observed.openMembership && !observed.allowJoinRequests;
    return ok ? pass(observed, orgSubset(org)) : fail(observed, orgSubset(org));
  })
};
var noSharedIssues = {
  code: "sentry.org.no_shared_issues",
  provider: "sentry",
  version: 1,
  severity: "low",
  maps: ["iso:8.12", "soc2:CC6.7"],
  run: (ctx) => guarded("api.org", async () => {
    const org = await organisation(ctx);
    const observed = { allowSharedIssues: org.allowSharedIssues === true, enhancedPrivacy: org.enhancedPrivacy === true };
    return observed.allowSharedIssues ? fail(observed, orgSubset(org)) : pass(observed, orgSubset(org));
  })
};
var SENTRY_CHECKS = [require2fa, members2fa, orgScrubbing, projectScrubbing, membershipClosed, noSharedIssues];

// ../lib/checks/providers/slack.ts
async function members(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  let cursor = "";
  for (let page = 0; page < 10; page++) {
    const r = await ctx.api.get("users.list", { limit: "200", ...cursor ? { cursor } : {} });
    const body = r.json;
    if (!body?.ok) throw new Error(body?.error === "missing_scope" ? "scope:users.read" : "scope:api.users");
    for (const u of body.members ?? []) if (u && u.id !== "USLACKBOT" && !u.deleted && !u.is_bot && !u.is_app_user) out.push(u);
    cursor = body.response_metadata?.next_cursor ?? "";
    if (!cursor) break;
  }
  return out;
}
var handle = (u) => `${(u.name ?? "?").slice(0, 2)}\u2026`;
var roleOf = (u) => u.is_primary_owner ? "primary owner" : u.is_owner ? "owner" : u.is_admin ? "admin" : u.is_ultra_restricted ? "single-channel guest" : u.is_restricted ? "guest" : "member";
var evidenceOf = (list4) => list4.map((u) => ({ handle: handle(u), role: roleOf(u), has_2fa: u.has_2fa ?? null }));
var members2fa2 = {
  code: "slack.members.2fa",
  provider: "slack",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await members(ctx);
    if (list4.length > 0 && list4.every((u) => u.has_2fa == null)) return unknown("api.2fa_hidden", { members: list4.length });
    const without = list4.filter((u) => u.has_2fa !== true).map((u) => `${roleOf(u)} ${handle(u)}`);
    const observed = { members: list4.length, without2fa: without };
    return without.length === 0 ? pass(observed, evidenceOf(list4)) : fail(observed, evidenceOf(list4));
  })
};
var adminsLimited = {
  code: "slack.admins.limited",
  provider: "slack",
  version: 1,
  severity: "medium",
  maps: ["iso:8.2", "soc2:CC6.3", "iso:5.18"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await members(ctx);
    const admins = list4.filter((u) => u.is_admin || u.is_owner || u.is_primary_owner);
    const ceiling = Math.max(3, Math.ceil(list4.length * 0.25));
    const observed = { members: list4.length, admins: admins.length, ceiling, holders: admins.map((u) => `${roleOf(u)} ${handle(u)}`) };
    const ok = admins.length >= 1 && admins.length <= ceiling;
    return ok ? pass(observed, evidenceOf(admins)) : fail(observed, evidenceOf(admins));
  })
};
var guestsReviewed = {
  code: "slack.guests.none",
  provider: "slack",
  version: 1,
  severity: "low",
  maps: ["iso:5.18", "soc2:CC6.2"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await members(ctx);
    const guests = list4.filter((u) => u.is_restricted || u.is_ultra_restricted);
    const observed = { guests: guests.length, logins: guests.map((u) => `${roleOf(u)} ${handle(u)}`) };
    return guests.length === 0 ? pass(observed, evidenceOf(guests)) : fail(observed, evidenceOf(guests));
  })
};
var joinRestricted = {
  code: "slack.team.join_restricted",
  provider: "slack",
  version: 1,
  severity: "medium",
  maps: ["iso:5.16", "soc2:CC6.2"],
  run: (ctx) => guarded("api.team", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get("team.info");
    const body = r.json;
    if (!body?.ok) throw new Error(body?.error === "missing_scope" ? "scope:team.read" : "scope:api.team");
    const domains = (body.team?.email_domain ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const observed = { workspace: body.team?.domain ?? null, emailDomains: domains };
    const evidence = { name: body.team?.name, domain: body.team?.domain, email_domain: body.team?.email_domain };
    return domains.length > 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var SLACK_CHECKS = [members2fa2, adminsLimited, guestsReviewed, joinRestricted];

// ../lib/checks/providers/google.ts
async function users(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  let pageToken = "";
  for (let page = 0; page < 10; page++) {
    const r = await ctx.api.get(`/users?customer=my_customer&maxResults=500&projection=basic${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`);
    if (r.status === 403) throw new Error("scope:users.readonly");
    if (r.status !== 200) throw new Error("scope:api.users");
    const body = r.json;
    for (const u of body.users ?? []) if (u && !u.suspended && !u.archived) out.push(u);
    pageToken = body.nextPageToken ?? "";
    if (!pageToken) break;
  }
  return out;
}
function maskEmail2(email) {
  if (!email || !email.includes("@")) return "?";
  const [local, domain] = email.split("@");
  return `${local.slice(0, 1)}\u2026@${domain}`;
}
var roleOf2 = (u) => u.isAdmin ? "super admin" : u.isDelegatedAdmin ? "delegated admin" : "user";
var evidenceOf2 = (list4) => list4.map((u) => ({ email: maskEmail2(u.primaryEmail), role: roleOf2(u), enrolled2sv: u.isEnrolledIn2Sv ?? null, enforced2sv: u.isEnforcedIn2Sv ?? null, lastLogin: u.lastLoginTime ?? null }));
var twoStepEnforced = {
  code: "google.users.2sv_enforced",
  provider: "google",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await users(ctx);
    if (list4.length === 0) return unknown("api.no_users");
    const not = list4.filter((u) => u.isEnforcedIn2Sv !== true).map((u) => `${roleOf2(u)} ${maskEmail2(u.primaryEmail)}`);
    const observed = { users: list4.length, notEnforced: not };
    return not.length === 0 ? pass(observed, evidenceOf2(list4)) : fail(observed, evidenceOf2(list4));
  })
};
var twoStepEnrolled = {
  code: "google.users.2sv_enrolled",
  provider: "google",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await users(ctx);
    if (list4.length === 0) return unknown("api.no_users");
    const not = list4.filter((u) => u.isEnrolledIn2Sv !== true).map((u) => `${roleOf2(u)} ${maskEmail2(u.primaryEmail)}`);
    const observed = { users: list4.length, notEnrolled: not };
    return not.length === 0 ? pass(observed, evidenceOf2(list4)) : fail(observed, evidenceOf2(list4));
  })
};
var adminsLimited2 = {
  code: "google.admins.limited",
  provider: "google",
  version: 1,
  severity: "medium",
  maps: ["iso:8.2", "soc2:CC6.3", "iso:5.18"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await users(ctx);
    if (list4.length === 0) return unknown("api.no_users");
    const admins = list4.filter((u) => u.isAdmin);
    const ceiling = Math.max(3, Math.ceil(list4.length * 0.25));
    const observed = { users: list4.length, superAdmins: admins.length, ceiling, holders: admins.map((u) => maskEmail2(u.primaryEmail)) };
    const ok = admins.length >= 1 && admins.length <= ceiling;
    return ok ? pass(observed, evidenceOf2(admins)) : fail(observed, evidenceOf2(admins));
  })
};
var DORMANT_DAYS2 = 90;
var dormantUsers2 = {
  code: "google.users.dormant",
  provider: "google",
  version: 1,
  severity: "medium",
  maps: ["iso:5.18", "iso:6.5", "soc2:CC6.3"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await users(ctx);
    if (list4.length === 0) return unknown("api.no_users");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    const days = (iso) => iso ? Math.floor((now - new Date(iso).getTime()) / 864e5) : null;
    const dormant = list4.filter((u) => {
      const last = u.lastLoginTime && !u.lastLoginTime.startsWith("1970") ? days(u.lastLoginTime) : null;
      const age = days(u.creationTime);
      return last === null ? age !== null && age > 30 : last > DORMANT_DAYS2;
    });
    const observed = { users: list4.length, dormantDays: DORMANT_DAYS2, dormant: dormant.map((u) => `${roleOf2(u)} ${maskEmail2(u.primaryEmail)}`) };
    return dormant.length === 0 ? pass(observed, evidenceOf2(list4)) : fail(observed, evidenceOf2(dormant));
  })
};
var GOOGLE_CHECKS = [twoStepEnforced, twoStepEnrolled, adminsLimited2, dormantUsers2];

// ../lib/checks/providers/microsoft.ts
var USER_FIELDS = "id,userPrincipalName,accountEnabled,userType,createdDateTime";
async function users2(ctx, select = USER_FIELDS) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  let next = `/users?$select=${select}&$top=999`;
  for (let page = 0; page < 10 && next; page++) {
    const r = await ctx.api.get(next);
    if (r.status === 403) {
      const text2 = JSON.stringify(r.json ?? "");
      throw new Error(/NonPremium|Premium/i.test(text2) && select.includes("signInActivity") ? "scope:licence.premium" : "scope:users.readonly");
    }
    if (r.status !== 200) throw new Error("scope:api.users");
    const body = r.json;
    for (const u of body.value ?? []) if (u && u.accountEnabled !== false && (u.userType ?? "Member") === "Member") out.push(u);
    next = body["@odata.nextLink"] ?? "";
  }
  return out;
}
function maskEmail3(email) {
  if (!email || !email.includes("@")) return "?";
  const [local, domain] = email.split("@");
  return `${local.slice(0, 1)}\u2026@${domain}`;
}
var MFA_METHODS = /* @__PURE__ */ new Set([
  "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
  "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod",
  "#microsoft.graph.phoneAuthenticationMethod",
  "#microsoft.graph.fido2AuthenticationMethod",
  "#microsoft.graph.softwareOathAuthenticationMethod",
  "#microsoft.graph.hardwareOathAuthenticationMethod",
  "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
  "#microsoft.graph.platformCredentialAuthenticationMethod"
]);
var MAX_METHOD_LOOKUPS = 300;
var mfaRegistered = {
  code: "microsoft.users.mfa_registered",
  provider: "microsoft",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.users", async () => {
    const list4 = await users2(ctx);
    if (list4.length === 0) return unknown("api.no_users");
    if (list4.length > MAX_METHOD_LOOKUPS) return unknown("api.too_many_users");
    const evidence = [];
    const not = [];
    for (const u of list4) {
      const r = await ctx.api.get(`/users/${encodeURIComponent(u.id ?? "")}/authentication/methods`);
      if (r.status === 403) throw new Error("scope:auth_methods.readonly");
      if (r.status !== 200) throw new Error("scope:api.auth_methods");
      const methods = (r.json.value ?? []).map((m) => String(m["@odata.type"] ?? ""));
      evidence.push({ email: maskEmail3(u.userPrincipalName), methods: methods.map((m) => m.replace("#microsoft.graph.", "")) });
      if (!methods.some((m) => MFA_METHODS.has(m))) not.push(maskEmail3(u.userPrincipalName));
    }
    const observed = { users: list4.length, notRegistered: not };
    return not.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var mfaEnforced = {
  code: "microsoft.tenant.mfa_enforced",
  provider: "microsoft",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.policies", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const d = await ctx.api.get("/policies/identitySecurityDefaultsEnforcementPolicy");
    if (d.status === 403) throw new Error("scope:policy.readonly");
    if (d.status !== 200) throw new Error("scope:api.security_defaults");
    const securityDefaults = d.json.isEnabled === true;
    if (securityDefaults) return pass({ securityDefaults, conditionalAccess: null }, { securityDefaults: d.json });
    const c = await ctx.api.get("/identity/conditionalAccess/policies");
    const policies = c.status === 200 ? c.json.value ?? [] : [];
    const requiresMfa = (p) => p.state === "enabled" && (p.conditions?.users?.includeUsers ?? []).includes("All") && (p.conditions?.applications?.includeApplications ?? []).includes("All") && ((p.grantControls?.builtInControls ?? []).includes("mfa") || p.grantControls?.authenticationStrength != null);
    const matching = policies.filter(requiresMfa).map((p) => p.displayName ?? "unnamed");
    const observed = { securityDefaults, conditionalAccessAvailable: c.status === 200, policies: policies.length, requiringMfaForAll: matching };
    const evidence = { securityDefaults: d.json, policies: policies.map((p) => ({ name: p.displayName, state: p.state, users: p.conditions?.users, apps: p.conditions?.applications, grant: p.grantControls })) };
    return matching.length > 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
var adminsLimited3 = {
  code: "microsoft.admins.limited",
  provider: "microsoft",
  version: 1,
  severity: "medium",
  maps: ["iso:8.2", "soc2:CC6.3", "iso:5.18"],
  run: (ctx) => guarded("api.roles", async () => {
    const list4 = await users2(ctx);
    if (list4.length === 0) return unknown("api.no_users");
    const roles = await ctx.api.get(`/directoryRoles?$filter=roleTemplateId eq '${GLOBAL_ADMIN_TEMPLATE}'`);
    if (roles.status === 403) throw new Error("scope:directory.readonly");
    if (roles.status !== 200) throw new Error("scope:api.roles");
    const role = (roles.json.value ?? [])[0];
    let admins = [];
    if (role?.id) {
      const m = await ctx.api.get(`/directoryRoles/${encodeURIComponent(role.id)}/members?$select=${USER_FIELDS}`);
      if (m.status === 403) throw new Error("scope:directory.readonly");
      if (m.status !== 200) throw new Error("scope:api.role_members");
      admins = (m.json.value ?? []).filter((x) => (x["@odata.type"] ?? "#microsoft.graph.user") === "#microsoft.graph.user" && x.accountEnabled !== false);
    }
    const ceiling = Math.max(3, Math.ceil(list4.length * 0.25));
    const observed = { users: list4.length, globalAdmins: admins.length, ceiling, holders: admins.map((u) => maskEmail3(u.userPrincipalName)) };
    const ok = admins.length >= 1 && admins.length <= ceiling;
    const evidence = admins.map((u) => ({ email: maskEmail3(u.userPrincipalName), type: u.userType ?? null }));
    return ok ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var DORMANT_DAYS3 = 90;
var dormantUsers3 = {
  code: "microsoft.users.dormant",
  provider: "microsoft",
  version: 1,
  severity: "medium",
  maps: ["iso:5.18", "iso:6.5", "soc2:CC6.3"],
  run: (ctx) => guarded("api.users", async () => {
    let list4;
    try {
      list4 = await users2(ctx, `${USER_FIELDS},signInActivity`);
    } catch (e) {
      if (e instanceof Error && e.message === "scope:licence.premium") return unknown("licence.premium");
      throw e;
    }
    if (list4.length === 0) return unknown("api.no_users");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    const days = (iso) => iso ? Math.floor((now - new Date(iso).getTime()) / 864e5) : null;
    const dormant = list4.filter((u) => {
      const last = days(u.signInActivity?.lastSuccessfulSignInDateTime ?? u.signInActivity?.lastSignInDateTime);
      const age = days(u.createdDateTime);
      return last === null ? age !== null && age > 30 : last > DORMANT_DAYS3;
    });
    const observed = { users: list4.length, dormantDays: DORMANT_DAYS3, dormant: dormant.map((u) => maskEmail3(u.userPrincipalName)) };
    const evidence = (dormant.length ? dormant : list4).map((u) => ({ email: maskEmail3(u.userPrincipalName), lastSignIn: u.signInActivity?.lastSuccessfulSignInDateTime ?? u.signInActivity?.lastSignInDateTime ?? null, created: u.createdDateTime ?? null }));
    return dormant.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var MICROSOFT_CHECKS = [mfaEnforced, mfaRegistered, adminsLimited3, dormantUsers3];

// ../lib/checks/providers/uptimerobot.ts
var PAUSED = 0;
async function monitors2(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  for (let offset = 0; offset < 500; offset += 50) {
    const r = await ctx.api.post("getMonitors", { alert_contacts: "1", limit: "50", offset: String(offset) });
    const body = r.json;
    if (r.status !== 200 || body?.stat !== "ok") throw new Error("scope:api.monitors");
    out.push(...body.monitors ?? []);
    if ((body.pagination?.total ?? 0) <= offset + 50) break;
  }
  return out;
}
function hostOf(url) {
  try {
    return new URL(url ?? "").hostname.toLowerCase();
  } catch {
    return "";
  }
}
function productionMonitors(list4, host) {
  const h = host.toLowerCase().replace(/^www\./, "");
  return list4.filter((m) => (m.type === 1 || m.type === 2) && [h, `www.${h}`].includes(hostOf(m.url)));
}
var summarise = (list4) => list4.map((m) => ({ name: m.friendly_name ?? null, host: hostOf(m.url), type: m.type ?? null, status: m.status ?? null, interval: m.interval ?? null, alertContacts: (m.alert_contacts ?? []).length }));
var productionMonitored = {
  code: "uptimerobot.monitor.production",
  provider: "uptimerobot",
  version: 1,
  severity: "high",
  maps: ["soc2:A1.1", "soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.monitors", async () => {
    if (!ctx.host) return unknown("connection.host");
    const list4 = await monitors2(ctx);
    const prod = productionMonitors(list4, ctx.host).filter((m) => m.status !== PAUSED);
    const observed = { monitors: list4.length, host: ctx.host, productionMonitors: prod.map((m) => m.friendly_name ?? hostOf(m.url)) };
    return prod.length > 0 ? pass(observed, summarise(prod)) : fail(observed, summarise(list4));
  })
};
var alertsConfigured = {
  code: "uptimerobot.alerts.configured",
  provider: "uptimerobot",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("api.monitors", async () => {
    const list4 = await monitors2(ctx);
    const active2 = list4.filter((m) => m.status !== PAUSED);
    if (active2.length === 0) return unknown("api.no_monitors");
    const silent = active2.filter((m) => (m.alert_contacts ?? []).length === 0).map((m) => m.friendly_name ?? hostOf(m.url));
    const observed = { monitors: active2.length, withoutAlertContact: silent };
    return silent.length === 0 ? pass(observed, summarise(active2)) : fail(observed, summarise(active2));
  })
};
var MAX_INTERVAL_SECONDS = 300;
var productionInterval = {
  code: "uptimerobot.monitor.interval",
  provider: "uptimerobot",
  version: 1,
  severity: "low",
  maps: ["soc2:A1.1", "iso:8.16"],
  run: (ctx) => guarded("api.monitors", async () => {
    if (!ctx.host) return unknown("connection.host");
    const list4 = await monitors2(ctx);
    const prod = productionMonitors(list4, ctx.host).filter((m) => m.status !== PAUSED);
    if (prod.length === 0) return unknown("api.no_production_monitor");
    const slow = prod.filter((m) => (m.interval ?? Infinity) > MAX_INTERVAL_SECONDS).map((m) => `${m.friendly_name ?? hostOf(m.url)} (${m.interval}s)`);
    const observed = { productionMonitors: prod.length, maxIntervalSeconds: MAX_INTERVAL_SECONDS, slower: slow };
    return slow.length === 0 ? pass(observed, summarise(prod)) : fail(observed, summarise(prod));
  })
};
var UPTIMEROBOT_CHECKS = [productionMonitored, alertsConfigured, productionInterval];

// ../lib/checks/providers/gitlab.ts
async function ownerType2(ctx) {
  if (ctx.ownerType) return ctx.ownerType;
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const g = await ctx.api.get(`/groups/${encodeURIComponent(ctx.owner)}`);
  if (g.status === 200) {
    ctx.ownerType = "group";
    return "group";
  }
  const u = await ctx.api.get(`/users?username=${encodeURIComponent(ctx.owner)}`);
  if (u.status === 200 && Array.isArray(u.json) && u.json.length > 0) {
    ctx.ownerType = "user";
    return "user";
  }
  throw new Error("scope:api.owner");
}
async function projects2(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxProjects ?? 30;
  if (ctx.projects?.length) {
    const out = [];
    for (const p of ctx.projects.slice(0, max)) {
      const r2 = await ctx.api.get(`/projects/${encodeURIComponent(`${ctx.owner}/${p}`)}`);
      if (r2.status === 200 && !r2.json.empty_repo) out.push(r2.json);
    }
    return out;
  }
  const kind = await ownerType2(ctx);
  const r = await ctx.api.get(kind === "group" ? `/groups/${encodeURIComponent(ctx.owner)}/projects?include_subgroups=true&archived=false&per_page=100&order_by=last_activity_at` : `/users/${encodeURIComponent(ctx.owner)}/projects?archived=false&per_page=100&order_by=last_activity_at`);
  if (r.status === 403) throw new Error("scope:projects.read");
  if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.projects");
  return r.json.filter((p) => !p.archived && !p.forked_from_project && !p.empty_repo).slice(0, max);
}
async function file(ctx, project, path) {
  const ref = project.default_branch ?? "main";
  const r = await ctx.api.get(`/projects/${project.id}/repository/files/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`);
  if (r.status !== 200) return null;
  const body = r.json;
  if (!body || typeof body.content !== "string") return null;
  return body.encoding === "base64" ? Buffer.from(body.content, "base64").toString("utf8") : body.content;
}
var group2fa = {
  code: "gitlab.group.2fa",
  provider: "gitlab",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5", "iso:5.17"],
  run: (ctx) => guarded("api.group", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get(`/groups/${encodeURIComponent(ctx.owner)}`);
    if (r.status === 403) throw new Error("scope:group.read");
    if (r.status !== 200) throw new Error("scope:api.group");
    const g = r.json;
    const observed = { group: ctx.owner, requireTwoFactor: g.require_two_factor_authentication === true, gracePeriodHours: g.two_factor_grace_period ?? null };
    return observed.requireTwoFactor ? pass(observed, g) : fail(observed, g);
  })
};
var branchProtection2 = {
  code: "gitlab.repo.default_branch_protected",
  provider: "gitlab",
  version: 2,
  severity: "high",
  maps: ["soc2:CC8.1", "iso:8.32", "iso:8.25"],
  run: (ctx) => guarded("api.projects", async () => {
    const list4 = await projects2(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const unprotected = [];
    const evidence = {};
    for (const p of list4) {
      const r = await ctx.api.get(`/projects/${p.id}/protected_branches`);
      const rules = r.status === 200 && Array.isArray(r.json) ? r.json : [];
      const branch = p.default_branch ?? "main";
      const rule = rules.find((x) => x.name === branch || x.name === "*");
      const ok = Boolean(rule) && rule.allow_force_push !== true && (rule.push_access_levels ?? []).every((l) => (l.access_level ?? 0) === 0 || (l.access_level ?? 0) >= 40);
      evidence[p.path] = { branch, rule: rule ?? null };
      if (!ok) unprotected.push(p.path);
    }
    const observed = { projects: list4.length, unprotected };
    return unprotected.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var noEnvCommitted2 = {
  code: "gitlab.repo.no_env_committed",
  provider: "gitlab",
  version: 2,
  severity: "critical",
  maps: ["soc2:CC6.1", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.projects", async () => {
    const list4 = await projects2(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const offenders = {};
    const evidence = {};
    for (const p of list4) {
      const r = await ctx.api.get(`/projects/${p.id}/repository/tree?ref=${encodeURIComponent(p.default_branch ?? "main")}&per_page=100`);
      const names = r.status === 200 && Array.isArray(r.json) ? r.json.filter((e) => e.type === "blob").map((e) => e.name ?? "") : [];
      const envs = names.filter((n) => /^\.env(\..+)?$/.test(n) && !/\.(example|sample|template)$/.test(n));
      evidence[p.path] = { files: names.length, envFiles: envs };
      if (envs.length) offenders[p.path] = envs;
    }
    const observed = { projects: list4.length, offenders };
    return Object.keys(offenders).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var hygiene2 = {
  code: "gitlab.repo.hygiene",
  provider: "gitlab",
  version: 2,
  severity: "medium",
  maps: ["iso:5.37", "soc2:CC2.3", "iso:8.24"],
  run: (ctx) => guarded("api.projects", async () => {
    const list4 = await projects2(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const missing = {};
    const evidence = {};
    for (const p of list4) {
      const gaps = [];
      const gi = await file(ctx, p, ".gitignore");
      const ignoresEnv = gi !== null && (/^\s*\.env(\*|\.\*|\.local|$)/m.test(gi) || /^\s*\*\.env/m.test(gi));
      if (!ignoresEnv) gaps.push(".gitignore covers .env");
      const sec = await file(ctx, p, "SECURITY.md");
      if (sec === null) gaps.push("SECURITY.md");
      let codeowners = false;
      for (const path of ["CODEOWNERS", ".gitlab/CODEOWNERS", "docs/CODEOWNERS"]) {
        if (await file(ctx, p, path) !== null) {
          codeowners = true;
          break;
        }
      }
      if (!codeowners) gaps.push("CODEOWNERS");
      evidence[p.path] = { ignoresEnv, securityMd: sec !== null, codeowners };
      if (gaps.length) missing[p.path] = gaps;
    }
    const observed = { projects: list4.length, missing };
    return Object.keys(missing).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var secretDetection = {
  code: "gitlab.repo.secret_detection",
  provider: "gitlab",
  version: 2,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.24"],
  run: (ctx) => guarded("api.projects", async () => {
    const list4 = await projects2(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const without = [];
    const evidence = {};
    for (const p of list4) {
      const ci = await file(ctx, p, ".gitlab-ci.yml");
      const on = ci !== null && /Security\/Secret-Detection\.gitlab-ci\.yml|Jobs\/Secret-Detection\.gitlab-ci\.yml|components\/secret-detection/i.test(ci);
      evidence[p.path] = { hasPipeline: ci !== null, secretDetection: on };
      if (!on) without.push(p.path);
    }
    const observed = { projects: list4.length, withoutSecretDetection: without };
    return without.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var visibility = {
  code: "gitlab.repo.visibility",
  provider: "gitlab",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:5.10"],
  run: (ctx) => guarded("api.projects", async () => {
    const list4 = await projects2(ctx);
    if (list4.length === 0) return unknown("api.no_projects");
    const open = (ctx.openSource ?? []).map((s) => s.toLowerCase());
    const exposed = list4.filter((p) => p.visibility === "public" && !open.includes(p.path.toLowerCase())).map((p) => p.path);
    const observed = { projects: list4.length, publicUndeclared: exposed, declaredOpenSource: open };
    const evidence = list4.map((p) => ({ path: p.path, visibility: p.visibility ?? null }));
    return exposed.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var membersReviewed = {
  code: "gitlab.group.members_reviewed",
  provider: "gitlab",
  version: 1,
  severity: "medium",
  maps: ["iso:5.18", "soc2:CC6.3", "iso:8.2"],
  run: (ctx) => guarded("api.group", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get(`/groups/${encodeURIComponent(ctx.owner)}/members/all?per_page=100`);
    if (r.status === 403) throw new Error("scope:members.read");
    if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.members");
    const members2 = r.json;
    const active2 = members2.filter((m) => m.state !== "blocked");
    if (active2.length === 0) return unknown("api.no_members");
    const now = Date.now();
    const expired = active2.filter((m) => m.expires_at && new Date(m.expires_at).getTime() < now).map((m) => m.username ?? "?");
    const owners = active2.filter((m) => (m.access_level ?? 0) >= 50);
    const ceiling = Math.max(3, Math.ceil(active2.length * 0.25));
    const observed = { members: active2.length, owners: owners.length, ceiling, expiredStillPresent: expired };
    const ok = expired.length === 0 && owners.length >= 1 && owners.length <= ceiling;
    const evidence = active2.map((m) => ({ username: m.username ?? null, accessLevel: m.access_level ?? null, expiresAt: m.expires_at ?? null }));
    return ok ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var GITLAB_CHECKS = [group2fa, branchProtection2, noEnvCommitted2, hygiene2, secretDetection, visibility, membersReviewed];

// ../lib/checks/providers/fly.ts
async function apps2(ctx) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const max = ctx.maxApps ?? 30;
  if (ctx.apps?.length) return ctx.apps.slice(0, max).map((name3) => ({ name: name3 }));
  const r = await ctx.api.get(`/apps?org_slug=${encodeURIComponent(ctx.org)}`);
  if (r.status === 403) throw new Error("scope:apps.read");
  if (r.status !== 200) throw new Error("scope:api.apps");
  const list4 = r.json?.apps ?? [];
  return list4.filter((a) => a && a.name).slice(0, max);
}
async function machines(ctx, app) {
  const r = await ctx.api.get(`/apps/${encodeURIComponent(app)}/machines`);
  if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.machines");
  return r.json;
}
var SECRET_KEY3 = /(SECRET|TOKEN|PASSWORD|PRIVATE|API_KEY|_KEY$|^KEY_)/i;
var PUBLIC_KEY2 = /^(NEXT_PUBLIC_|PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)|_PUBLIC_KEY$|PUBLISHABLE/i;
var forceHttps2 = {
  code: "fly.services.force_https",
  provider: "fly",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "ce:secure-config", "iso:8.24"],
  run: (ctx) => guarded("api.machines", async () => {
    const list4 = await apps2(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    const open = {};
    const evidence = {};
    for (const a of list4) {
      const ms = await machines(ctx, a.name);
      const offenders = [];
      for (const m of ms) {
        for (const s of m.config?.services ?? []) {
          for (const p of s.ports ?? []) {
            const isHttp = (p.handlers ?? []).includes("http") && !(p.handlers ?? []).includes("tls");
            if (isHttp && p.force_https !== true) offenders.push(`${m.name ?? m.id}:${p.port ?? "?"}`);
          }
        }
      }
      evidence[a.name] = { machines: ms.length, plainHttpPorts: offenders };
      if (offenders.length) open[a.name] = offenders;
    }
    const observed = { apps: list4.length, plainHttp: open };
    return Object.keys(open).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var volumesEncrypted = {
  code: "fly.volumes.encrypted",
  provider: "fly",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "iso:8.24", "gdpr:art32"],
  run: (ctx) => guarded("api.volumes", async () => {
    const list4 = await apps2(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    const plain = {};
    const evidence = {};
    let total = 0;
    for (const a of list4) {
      const r = await ctx.api.get(`/apps/${encodeURIComponent(a.name)}/volumes`);
      if (r.status !== 200 || !Array.isArray(r.json)) throw new Error("scope:api.volumes");
      const vols = r.json;
      total += vols.length;
      const bad = vols.filter((v) => v.encrypted === false).map((v) => v.name ?? v.id ?? "?");
      evidence[a.name] = vols.map((v) => ({ name: v.name ?? v.id, encrypted: v.encrypted ?? null, sizeGb: v.size_gb ?? null }));
      if (bad.length) plain[a.name] = bad;
    }
    const observed = { apps: list4.length, volumes: total, unencrypted: plain };
    return Object.keys(plain).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var noPlaintextSecrets = {
  code: "fly.machines.no_plaintext_secrets",
  provider: "fly",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.machines", async () => {
    const list4 = await apps2(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    const leaks = {};
    const evidence = {};
    for (const a of list4) {
      const ms = await machines(ctx, a.name);
      const keys = /* @__PURE__ */ new Set();
      for (const m of ms) for (const k of Object.keys(m.config?.env ?? {})) if (SECRET_KEY3.test(k) && !PUBLIC_KEY2.test(k)) keys.add(k);
      evidence[a.name] = { machines: ms.length, secretLikeEnvKeys: [...keys] };
      if (keys.size) leaks[a.name] = [...keys];
    }
    const observed = { apps: list4.length, plaintext: leaks };
    return Object.keys(leaks).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var members2fa3 = {
  code: "fly.org.members_2fa",
  provider: "fly",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "ce:user-access", "iso:8.5"],
  run: (ctx) => guarded("api.graphql", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.graphql(
      "query SnoopiosMembers($slug: String!) { organization(slug: $slug) { members { edges { role node { email twoFactorProtection } } } } }",
      { slug: ctx.org }
    );
    const body = r.json;
    if (r.status !== 200 || !body?.data?.organization || body.errors?.length) return unknown("api.members");
    const edges = body.data.organization.members?.edges ?? [];
    if (edges.length === 0) return unknown("api.no_members");
    const mask = (e) => e && e.includes("@") ? `${e[0]}\u2026@${e.split("@")[1]}` : "?";
    const without = edges.filter((e) => e.node?.twoFactorProtection !== true).map((e) => `${e.role ?? "member"} ${mask(e.node?.email)}`);
    const observed = { members: edges.length, without2fa: without };
    const evidence = edges.map((e) => ({ role: e.role ?? null, email: mask(e.node?.email), twoFactor: e.node?.twoFactorProtection ?? null }));
    return without.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var certificates = {
  code: "fly.app.certificates",
  provider: "fly",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.24"],
  run: (ctx) => guarded("api.graphql", async () => {
    const list4 = await apps2(ctx);
    if (list4.length === 0) return unknown("api.no_apps");
    const pending = {};
    const evidence = {};
    let hostnames = 0;
    for (const a of list4) {
      const r = await ctx.api.graphql("query SnoopiosCerts($name: String!) { app(name: $name) { certificates { nodes { hostname clientStatus } } } }", { name: a.name });
      const body = r.json;
      if (r.status !== 200 || !body?.data?.app || body.errors?.length) return unknown("api.certificates");
      const certs = body.data.app.certificates?.nodes ?? [];
      hostnames += certs.length;
      const bad = certs.filter((c) => (c.clientStatus ?? "").toLowerCase() !== "ready").map((c) => `${c.hostname ?? "?"} (${c.clientStatus ?? "unknown"})`);
      evidence[a.name] = certs;
      if (bad.length) pending[a.name] = bad;
    }
    const observed = { apps: list4.length, hostnames, notReady: pending };
    return Object.keys(pending).length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var FLY_CHECKS = [forceHttps2, volumesEncrypted, noPlaintextSecrets, members2fa3, certificates];

// ../lib/checks/providers/vercel.ts
async function projects3(ctx) {
  const r = await ctx.api.get("/v9/projects?limit=100");
  if (r.status !== 200) throw new Error("scope:projects.list");
  const list4 = (r.json?.projects ?? []).filter((p) => p && p.id);
  return { list: list4, raw: r.json };
}
var SUPPORTED_NODE = /* @__PURE__ */ new Set(["22.x", "24.x"]);
var previewProtection = {
  code: "vercel.projects.preview_protection",
  provider: "vercel",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.3", "iso:8.31"],
  run: (ctx) => guarded("projects.list", async () => {
    const { list: list4, raw } = await projects3(ctx);
    const unprotected = list4.filter((p) => !p.ssoProtection && !p.passwordProtection).map((p) => p.name);
    const observed = { projects: list4.length, unprotected };
    return list4.length > 0 && unprotected.length === 0 ? pass(observed, raw) : fail(observed, raw);
  })
};
var forkProtection = {
  code: "vercel.projects.fork_protection",
  provider: "vercel",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC8.1", "iso:8.32", "iso:8.25"],
  run: (ctx) => guarded("projects.list", async () => {
    const { list: list4, raw } = await projects3(ctx);
    const linked = list4.filter((p) => p.link?.type);
    const unprotected = linked.filter((p) => p.gitForkProtection !== true).map((p) => p.name);
    const observed = { gitLinked: linked.length, unprotected };
    return unprotected.length === 0 ? pass(observed, raw) : fail(observed, raw);
  })
};
var nodeSupported = {
  code: "vercel.projects.node_supported",
  provider: "vercel",
  version: 1,
  severity: "medium",
  maps: ["ce:patching", "iso:8.8", "soc2:CC7.1"],
  run: (ctx) => guarded("projects.list", async () => {
    const { list: list4, raw } = await projects3(ctx);
    const outdated = list4.filter((p) => p.nodeVersion && !SUPPORTED_NODE.has(p.nodeVersion)).map((p) => `${p.name} (${p.nodeVersion})`);
    const observed = { projects: list4.length, supported: [...SUPPORTED_NODE], outdated };
    return outdated.length === 0 ? pass(observed, raw) : fail(observed, raw);
  })
};
var domainsVerified = {
  code: "vercel.domains.verified",
  provider: "vercel",
  version: 1,
  severity: "medium",
  maps: ["iso:8.9", "soc2:CC6.7"],
  run: (ctx) => guarded("projects.domains", async () => {
    const { list: list4 } = await projects3(ctx);
    const unverified = [];
    let total = 0;
    const evidence = {};
    for (const p of list4.slice(0, 50)) {
      const r = await ctx.api.get(`/v9/projects/${encodeURIComponent(p.id)}/domains`);
      if (r.status !== 200) throw new Error("scope:projects.domains");
      const domains = r.json?.domains ?? [];
      evidence[p.name] = domains;
      for (const d of domains) {
        total++;
        if (d.verified !== true) unverified.push(d.name);
      }
    }
    const observed = { domains: total, unverified };
    return unverified.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var noRecentErrors = {
  code: "vercel.deployments.no_recent_errors",
  provider: "vercel",
  version: 1,
  severity: "low",
  maps: ["soc2:CC7.2", "iso:8.16"],
  run: (ctx) => guarded("deployments.list", async () => {
    const since = Date.now() - 30 * 864e5;
    const r = await ctx.api.get(`/v6/deployments?limit=100&state=ERROR&target=production&since=${since}`);
    if (r.status !== 200) throw new Error("scope:deployments.list");
    const list4 = r.json?.deployments ?? [];
    const observed = { failedProductionDeployments30d: list4.length, projects: [...new Set(list4.map((d) => d.name ?? "?"))].slice(0, 10) };
    return list4.length === 0 ? pass(observed, r.json) : fail(observed, r.json);
  })
};
var VERCEL_CHECKS = [previewProtection, forkProtection, nodeSupported, domainsVerified, noRecentErrors];

// ../lib/checks/providers/atlas.ts
async function list(ctx, resource, scope) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(`/groups/${encodeURIComponent(ctx.projectId)}/${resource}?itemsPerPage=500`);
  if (r.status === 403) throw new Error(`scope:${scope}.read`);
  if (r.status !== 200) throw new Error(`scope:api.${scope}`);
  return r.json?.results ?? [];
}
var SUPPORTED_MAJOR = /* @__PURE__ */ new Set(["8.0", "8.1", "8.2"]);
var ADMIN_ROLES = /* @__PURE__ */ new Set(["atlasAdmin", "readWriteAnyDatabase", "dbAdminAnyDatabase", "userAdminAnyDatabase", "root", "clusterAdmin"]);
var ipAccessList = {
  code: "atlas.project.ip_access_list",
  provider: "atlas",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.20", "ce:firewalls"],
  run: (ctx) => guarded("api.access_list", async () => {
    const entries2 = await list(ctx, "accessList", "access_list");
    const open = entries2.filter((e) => e.cidrBlock === "0.0.0.0/0" || e.cidrBlock === "::/0").map((e) => e.cidrBlock ?? "");
    const observed = { entries: entries2.length, openToInternet: open };
    const evidence = entries2.map((e) => ({ cidr: e.cidrBlock ?? e.ipAddress ?? null, comment: e.comment ?? null }));
    if (entries2.length === 0) return fail({ ...observed, note: "no entries: nothing can connect, or private endpoints only" }, evidence);
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var backupsEnabled = {
  code: "atlas.cluster.backups_enabled",
  provider: "atlas",
  version: 1,
  severity: "high",
  maps: ["soc2:A1.2", "iso:8.13", "gdpr:art32"],
  run: (ctx) => guarded("api.clusters", async () => {
    const clusters = await list(ctx, "clusters", "clusters");
    if (clusters.length === 0) return unknown("api.no_clusters");
    const off = clusters.filter((c) => c.backupEnabled !== true).map((c) => c.name);
    const observed = { clusters: clusters.length, withoutBackups: off };
    const evidence = clusters.map((c) => ({ name: c.name, backupEnabled: c.backupEnabled ?? null, type: c.clusterType ?? null }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var versionSupported = {
  code: "atlas.cluster.version_supported",
  provider: "atlas",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.1", "iso:8.8", "ce:patching"],
  run: (ctx) => guarded("api.clusters", async () => {
    const clusters = await list(ctx, "clusters", "clusters");
    if (clusters.length === 0) return unknown("api.no_clusters");
    const old = clusters.filter((c) => !SUPPORTED_MAJOR.has(c.mongoDBMajorVersion ?? "")).map((c) => `${c.name} (${c.mongoDBMajorVersion ?? "unknown"})`);
    const observed = { clusters: clusters.length, unsupportedVersion: old, supported: [...SUPPORTED_MAJOR] };
    const evidence = clusters.map((c) => ({ name: c.name, version: c.mongoDBMajorVersion ?? null }));
    return old.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var terminationProtection = {
  code: "atlas.cluster.termination_protection",
  provider: "atlas",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.2", "soc2:CC6.1", "iso:8.13"],
  run: (ctx) => guarded("api.clusters", async () => {
    const clusters = await list(ctx, "clusters", "clusters");
    if (clusters.length === 0) return unknown("api.no_clusters");
    const off = clusters.filter((c) => c.terminationProtectionEnabled !== true).map((c) => c.name);
    const observed = { clusters: clusters.length, deletable: off };
    const evidence = clusters.map((c) => ({ name: c.name, terminationProtection: c.terminationProtectionEnabled ?? null }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var leastPrivilegeUsers = {
  code: "atlas.db_users.least_privilege",
  provider: "atlas",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.3", "iso:5.15", "iso:8.2", "ce:user-access"],
  run: (ctx) => guarded("api.database_users", async () => {
    const users3 = await list(ctx, "databaseUsers", "database_users");
    if (users3.length === 0) return unknown("api.no_database_users");
    const admins = users3.filter((u) => (u.roles ?? []).some((r) => ADMIN_ROLES.has(r.roleName ?? ""))).map((u) => u.username ?? "?");
    const observed = { users: users3.length, withAdminRole: admins };
    const evidence = users3.map((u) => ({ username: u.username ?? null, roles: (u.roles ?? []).map((r) => `${r.roleName}@${r.databaseName}`) }));
    return admins.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var ATLAS_CHECKS = [ipAccessList, backupsEnabled, versionSupported, terminationProtection, leastPrivilegeUsers];

// ../lib/checks/providers/digitalocean.ts
async function get(ctx, path, key, scope) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(path);
  if (r.status === 403) throw new Error(`scope:${scope}.read`);
  if (r.status !== 200) throw new Error(`scope:api.${scope}`);
  const items = r.json?.[key];
  return Array.isArray(items) ? items : [];
}
var publicDroplets = (ds) => ds.filter((d) => d.status === "active" && (d.networks?.v4 ?? []).some((n) => n.type === "public"));
var dropletFirewall = {
  code: "do.droplet.firewall",
  provider: "digitalocean",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.20", "ce:firewalls"],
  run: (ctx) => guarded("api.droplets", async () => {
    const droplets = publicDroplets(await get(ctx, "/droplets?per_page=200", "droplets", "droplets"));
    if (droplets.length === 0) return unknown("api.no_public_droplets");
    const firewalls = await get(ctx, "/firewalls?per_page=200", "firewalls", "firewalls");
    const covered = /* @__PURE__ */ new Set();
    const taggedFirewalls = /* @__PURE__ */ new Set();
    for (const f of firewalls) {
      for (const id of f.droplet_ids ?? []) covered.add(id);
      for (const t of f.tags ?? []) taggedFirewalls.add(t);
    }
    const bare = droplets.filter((d) => !covered.has(d.id) && !(d.tags ?? []).some((t) => taggedFirewalls.has(t))).map((d) => d.name);
    const observed = { publicDroplets: droplets.length, firewalls: firewalls.length, withoutFirewall: bare };
    const evidence = droplets.map((d) => ({ name: d.name, covered: covered.has(d.id) || (d.tags ?? []).some((t) => taggedFirewalls.has(t)) }));
    return bare.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var dropletBackups = {
  code: "do.droplet.backups",
  provider: "digitalocean",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.2", "iso:8.13"],
  run: (ctx) => guarded("api.droplets", async () => {
    const droplets = (await get(ctx, "/droplets?per_page=200", "droplets", "droplets")).filter((d) => d.status === "active");
    if (droplets.length === 0) return unknown("api.no_droplets");
    const off = droplets.filter((d) => !(d.features ?? []).includes("backups")).map((d) => d.name);
    const observed = { droplets: droplets.length, withoutBackups: off };
    const evidence = droplets.map((d) => ({ name: d.name, features: d.features ?? [] }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var databaseTrustedSources = {
  code: "do.database.trusted_sources",
  provider: "digitalocean",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.20", "ce:firewalls"],
  run: (ctx) => guarded("api.databases", async () => {
    const dbs = await get(ctx, "/databases", "databases", "databases");
    if (dbs.length === 0) return unknown("api.no_databases");
    const open = [];
    const evidence = {};
    for (const db of dbs) {
      const rules = await get(ctx, `/databases/${encodeURIComponent(db.id)}/firewall`, "rules", "database_firewall");
      evidence[db.name] = rules.map((r) => ({ type: r.type ?? null, value: r.type === "ip_addr" ? r.value ?? null : "\u2026" }));
      if (rules.length === 0) open.push(db.name);
    }
    const observed = { databases: dbs.length, openToAnyAddress: open };
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var databaseVersionSupported = {
  code: "do.database.version_supported",
  provider: "digitalocean",
  version: 1,
  severity: "high",
  maps: ["soc2:CC7.1", "iso:8.8", "ce:patching"],
  run: (ctx) => guarded("api.databases", async () => {
    const dbs = await get(ctx, "/databases", "databases", "databases");
    if (dbs.length === 0) return unknown("api.no_databases");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    const eol = dbs.filter((db) => db.version_end_of_life && Date.parse(db.version_end_of_life) < now).map((db) => `${db.name} (${db.engine ?? "?"} ${db.version ?? "?"})`);
    const observed = { databases: dbs.length, pastEndOfLife: eol };
    const evidence = dbs.map((db) => ({ name: db.name, engine: db.engine ?? null, version: db.version ?? null, endOfLife: db.version_end_of_life ?? null }));
    return eol.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var DIGITALOCEAN_CHECKS = [dropletFirewall, dropletBackups, databaseTrustedSources, databaseVersionSupported];

// ../lib/checks/providers/auth0.ts
async function get2(ctx, path, scope) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const r = await ctx.api.get(path);
  if (r.status === 403) throw new Error(`scope:scope.${scope}`);
  if (r.status !== 200) throw new Error(`scope:api.${scope}`);
  return r.json;
}
var PER_PAGE = 100;
var MAX_PAGES2 = 5;
async function clients(ctx) {
  const out = [];
  for (let page = 0; page < MAX_PAGES2; page++) {
    const batch = await get2(ctx, `/clients?page=${page}&per_page=${PER_PAGE}&is_global=false&fields=client_id,name,app_type,callbacks,allowed_logout_urls,web_origins,grant_types,refresh_token`, "clients");
    if (!Array.isArray(batch)) throw new Error("scope:api.clients");
    out.push(...batch);
    if (batch.length < PER_PAGE) break;
  }
  return out;
}
var LOCAL_HOST = /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?$/i;
function insecureUrl(u) {
  try {
    const url = new URL(u);
    if (url.protocol === "http:") return true;
    if (url.protocol === "https:") return LOCAL_HOST.test(url.host);
    return false;
  } catch {
    return u.startsWith("http://");
  }
}
var attackProtection = {
  code: "auth0.attack_protection.enabled",
  provider: "auth0",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "soc2:CC6.6", "iso:8.5", "ce:user-access"],
  run: (ctx) => guarded("api.attack_protection", async () => {
    const [brute, breached, throttle] = await Promise.all([
      get2(ctx, "/attack-protection/brute-force-protection", "attack_protection"),
      get2(ctx, "/attack-protection/breached-password-detection", "attack_protection"),
      get2(ctx, "/attack-protection/suspicious-ip-throttling", "attack_protection")
    ]);
    const observed = { bruteForceProtection: brute.enabled === true, breachedPasswordDetection: breached.enabled === true, suspiciousIpThrottling: throttle.enabled === true };
    const off = Object.entries(observed).filter(([, v]) => !v).map(([k]) => k);
    return off.length === 0 ? pass({ ...observed, off }, observed) : fail({ ...observed, off }, observed);
  })
};
var mfaEnforced2 = {
  code: "auth0.mfa.enforced",
  provider: "auth0",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:5.17", "iso:8.5", "ce:user-access"],
  run: (ctx) => guarded("api.mfa", async () => {
    const policies = await get2(ctx, "/guardian/policies", "mfa_policies");
    const factors = await get2(ctx, "/guardian/factors", "guardian_factors");
    const enabledFactors = (Array.isArray(factors) ? factors : []).filter((f) => f.enabled === true).map((f) => f.name ?? "?");
    const enforced = Array.isArray(policies) && policies.some((p) => p === "all-applications" || p === "confidence-score");
    const observed = { policies: Array.isArray(policies) ? policies : [], enforced, enabledFactors };
    return enforced && enabledFactors.length > 0 ? pass(observed, observed) : fail(observed, observed);
  })
};
var callbacksHttps = {
  code: "auth0.clients.callbacks_https",
  provider: "auth0",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.7", "iso:8.24", "iso:8.26"],
  run: (ctx) => guarded("api.clients", async () => {
    const all = await clients(ctx);
    if (all.length === 0) return unknown("api.no_clients");
    const bad = all.map((c) => ({ name: c.name ?? c.client_id ?? "?", urls: [...c.callbacks ?? [], ...c.allowed_logout_urls ?? [], ...c.web_origins ?? []].filter(insecureUrl) })).filter((c) => c.urls.length > 0);
    const observed = { clients: all.length, withInsecureUrls: bad.map((b) => b.name) };
    const evidence = all.map((c) => ({ name: c.name ?? null, appType: c.app_type ?? null, urls: [...c.callbacks ?? [], ...c.allowed_logout_urls ?? [], ...c.web_origins ?? []].length, insecure: bad.find((b) => b.name === (c.name ?? c.client_id))?.urls ?? [] }));
    return bad.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var refreshTokenRotation = {
  code: "auth0.clients.refresh_token_rotation",
  provider: "auth0",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.5"],
  run: (ctx) => guarded("api.clients", async () => {
    const refreshing = (await clients(ctx)).filter((c) => (c.grant_types ?? []).includes("refresh_token") && (c.app_type === "spa" || c.app_type === "native"));
    if (refreshing.length === 0) return unknown("api.no_public_clients_with_refresh");
    const weak = refreshing.filter((c) => c.refresh_token?.rotation_type !== "rotating" || c.refresh_token?.expiration_type !== "expiring").map((c) => c.name ?? c.client_id ?? "?");
    const observed = { publicClientsWithRefresh: refreshing.length, withoutRotation: weak };
    const evidence = refreshing.map((c) => ({ name: c.name ?? null, appType: c.app_type ?? null, rotation: c.refresh_token?.rotation_type ?? null, expiration: c.refresh_token?.expiration_type ?? null }));
    return weak.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var MAX_SESSION_HOURS = 30 * 24;
var MAX_IDLE_HOURS = 7 * 24;
var sessionLifetime = {
  code: "auth0.tenant.session_lifetime",
  provider: "auth0",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.5"],
  run: (ctx) => guarded("api.tenant_settings", async () => {
    const t = await get2(ctx, "/tenants/settings?fields=session_lifetime,idle_session_lifetime", "tenant_settings");
    const session = typeof t.session_lifetime === "number" ? t.session_lifetime : 168;
    const idle = typeof t.idle_session_lifetime === "number" ? t.idle_session_lifetime : 72;
    const observed = { sessionLifetimeHours: session, idleSessionLifetimeHours: idle, maxSessionHours: MAX_SESSION_HOURS, maxIdleHours: MAX_IDLE_HOURS };
    return session <= MAX_SESSION_HOURS && idle <= MAX_IDLE_HOURS ? pass(observed, observed) : fail(observed, observed);
  })
};
var STRONG = /* @__PURE__ */ new Set(["good", "excellent"]);
var passwordPolicy = {
  code: "auth0.connections.password_policy",
  provider: "auth0",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:5.17", "ce:user-access"],
  run: (ctx) => guarded("api.connections", async () => {
    const conns = await get2(ctx, "/connections?strategy=auth0&per_page=100&fields=id,name,strategy,options", "connections");
    const db = (Array.isArray(conns) ? conns : []).filter((c) => c.strategy === "auth0");
    if (db.length === 0) return unknown("api.no_database_connections");
    if (db.every((c) => !c.options || !("passwordPolicy" in c.options))) return unknown("scope.connections_options", { connections: db.length });
    const weak = db.filter((c) => !STRONG.has(c.options?.passwordPolicy ?? "")).map((c) => `${c.name ?? c.id ?? "?"} (${c.options?.passwordPolicy ?? "none"})`);
    const observed = { databaseConnections: db.length, weakPolicy: weak };
    const evidence = db.map((c) => ({ name: c.name ?? null, passwordPolicy: c.options?.passwordPolicy ?? null }));
    return weak.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var AUTH0_CHECKS = [attackProtection, mfaEnforced2, callbacksHttps, refreshTokenRotation, sessionLifetime, passwordPolicy];

// ../lib/checks/providers/bitbucket.ts
var PAGELEN = 100;
var MAX_PAGES3 = 10;
var MAX_REPOS = 50;
async function list2(ctx, path, scope) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  for (let page = 1; page <= MAX_PAGES3; page++) {
    const r = await ctx.api.get(`${path}${path.includes("?") ? "&" : "?"}pagelen=${PAGELEN}&page=${page}`);
    if (r.status === 403) throw new Error(`scope:scope.${scope}`);
    if (r.status !== 200) throw new Error(`scope:api.${scope}`);
    const body = r.json;
    out.push(...body?.values ?? []);
    if (!body?.next) break;
  }
  return out;
}
async function repos(ctx) {
  const all = await list2(ctx, `/repositories/${encodeURIComponent(ctx.workspace)}`, "repositories");
  return all.slice(0, MAX_REPOS);
}
var repoPath = (ctx, r) => `/repositories/${encodeURIComponent(ctx.workspace)}/${encodeURIComponent(r.slug ?? "")}`;
var name = (r) => r.full_name ?? r.slug ?? "?";
var reposPrivate = {
  code: "bitbucket.repos.private",
  provider: "bitbucket",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:8.3", "iso:8.4"],
  run: (ctx) => guarded("api.repositories", async () => {
    const all = await repos(ctx);
    if (all.length === 0) return unknown("api.no_repositories");
    const open = all.filter((r) => r.is_private !== true).map(name);
    const observed = { repositories: all.length, public: open };
    const evidence = all.map((r) => ({ name: name(r), private: r.is_private ?? null }));
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var forkPolicy = {
  code: "bitbucket.repos.fork_policy",
  provider: "bitbucket",
  version: 1,
  severity: "low",
  maps: ["soc2:CC6.1", "iso:8.4"],
  run: (ctx) => guarded("api.repositories", async () => {
    const priv = (await repos(ctx)).filter((r) => r.is_private === true);
    if (priv.length === 0) return unknown("api.no_private_repositories");
    const loose = priv.filter((r) => r.fork_policy === "allow_forks").map(name);
    const observed = { privateRepositories: priv.length, publicForksAllowed: loose };
    const evidence = priv.map((r) => ({ name: name(r), forkPolicy: r.fork_policy ?? null }));
    return loose.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var defaultReviewers = {
  code: "bitbucket.repos.default_reviewers",
  provider: "bitbucket",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC8.1", "iso:8.25", "iso:8.29"],
  run: (ctx) => guarded("api.default_reviewers", async () => {
    const all = await repos(ctx);
    if (all.length === 0) return unknown("api.no_repositories");
    const without = [];
    const evidence = [];
    for (const r of all) {
      const reviewers = await list2(ctx, `${repoPath(ctx, r)}/effective-default-reviewers`, "pullrequest");
      evidence.push({ name: name(r), reviewers: reviewers.length });
      if (reviewers.length === 0) without.push(name(r));
    }
    const observed = { repositories: all.length, withoutDefaultReviewers: without };
    return without.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var STALE_DAYS2 = 90;
var NEW_DAYS2 = 30;
var DAY2 = 24 * 3600 * 1e3;
var deployKeysRecent = {
  code: "bitbucket.deploy_keys.recent",
  provider: "bitbucket",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "soc2:CC6.3", "iso:5.18", "iso:8.2"],
  run: (ctx) => guarded("api.deploy_keys", async () => {
    const all = await repos(ctx);
    if (all.length === 0) return unknown("api.no_repositories");
    const now = (ctx.now ?? /* @__PURE__ */ new Date()).getTime();
    const stale = [];
    const evidence = [];
    for (const r of all) {
      const keys = await list2(ctx, `${repoPath(ctx, r)}/deploy-keys`, "ssh_key");
      for (const k of keys) {
        const used = k.last_used ? Date.parse(k.last_used) : NaN;
        const added = k.added_on ? Date.parse(k.added_on) : NaN;
        const fresh = Number.isFinite(used) && now - used <= STALE_DAYS2 * DAY2 || Number.isFinite(added) && now - added <= NEW_DAYS2 * DAY2;
        evidence.push({ repository: name(r), label: k.label ?? null, addedOn: k.added_on ?? null, lastUsed: k.last_used ?? null });
        if (!fresh) stale.push(`${name(r)}: ${k.label ?? k.id ?? "?"}`);
      }
    }
    if (evidence.length === 0) return unknown("api.no_deploy_keys", { repositories: all.length });
    const observed = { deployKeys: evidence.length, staleDays: STALE_DAYS2, stale };
    return stale.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var SECRET_NAME = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)/i;
var pipelineSecrets = {
  code: "bitbucket.pipelines.secured_variables",
  provider: "bitbucket",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.1", "iso:8.12", "iso:8.28"],
  run: (ctx) => guarded("api.pipeline_variables", async () => {
    const all = await repos(ctx);
    if (all.length === 0) return unknown("api.no_repositories");
    const exposed = [];
    const evidence = [];
    for (const r of all) {
      if (!ctx.api) throw new Error("scope:api.not_connected");
      const probe = await ctx.api.get(`${repoPath(ctx, r)}/pipelines_config/variables?pagelen=1`);
      if (probe.status === 404) continue;
      if (probe.status === 403) throw new Error("scope:scope.pipeline");
      const vars = await list2(ctx, `${repoPath(ctx, r)}/pipelines_config/variables`, "pipeline");
      for (const v of vars) {
        const key = v.key ?? "?";
        if (!SECRET_NAME.test(key)) continue;
        evidence.push({ repository: name(r), variable: key, secured: v.secured === true });
        if (v.secured !== true) exposed.push(`${name(r)}: ${key}`);
      }
    }
    if (evidence.length === 0) return unknown("api.no_secret_named_variables", { repositories: all.length });
    const observed = { secretNamedVariables: evidence.length, unsecured: exposed };
    return exposed.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var accountTwoFactor = {
  code: "bitbucket.account.two_factor",
  provider: "bitbucket",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.1", "iso:5.17", "ce:user-access"],
  run: (ctx) => guarded("api.user", async () => {
    if (!ctx.api) throw new Error("scope:api.not_connected");
    const r = await ctx.api.get("/user");
    if (r.status === 403) throw new Error("scope:scope.user");
    if (r.status !== 200) throw new Error("scope:api.user");
    const u = r.json;
    if (typeof u?.has_2fa_enabled !== "boolean") return unknown("api.two_factor_unreported");
    const observed = { account: u.display_name ?? null, twoStepVerification: u.has_2fa_enabled };
    return u.has_2fa_enabled ? pass(observed, observed) : fail(observed, observed);
  })
};
var BITBUCKET_CHECKS = [reposPrivate, forkPolicy, defaultReviewers, deployKeysRecent, pipelineSecrets, accountTwoFactor];

// ../lib/checks/providers/hetzner.ts
var PER_PAGE2 = 50;
var MAX_PAGES4 = 10;
async function list3(ctx, resource) {
  if (!ctx.api) throw new Error("scope:api.not_connected");
  const out = [];
  for (let page = 1; page <= MAX_PAGES4; page++) {
    const r = await ctx.api.get(`/${resource}?per_page=${PER_PAGE2}&page=${page}`);
    if (r.status === 403) throw new Error(`scope:scope.${resource}`);
    if (r.status !== 200) throw new Error(`scope:api.${resource}`);
    const body = r.json;
    const items = body?.[resource];
    if (!Array.isArray(items)) throw new Error(`scope:api.${resource}`);
    out.push(...items);
    if (!body?.meta?.pagination?.next_page) break;
  }
  return out;
}
var live = (s) => s.status !== "deleting";
var isPublic2 = (s) => Boolean(s.public_net?.ipv4?.ip || s.public_net?.ipv6?.ip);
var name2 = (s) => s.name ?? String(s.id ?? "?");
var serverFirewall = {
  code: "hetzner.server.firewall",
  provider: "hetzner",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.20", "ce:firewalls"],
  run: (ctx) => guarded("api.servers", async () => {
    const servers = (await list3(ctx, "servers")).filter(live).filter(isPublic2);
    if (servers.length === 0) return unknown("api.no_public_servers");
    const bare = servers.filter((s) => !(s.public_net?.firewalls ?? []).some((f) => f.status === "applied")).map(name2);
    const observed = { publicServers: servers.length, withoutFirewall: bare };
    const evidence = servers.map((s) => ({ name: name2(s), firewalls: (s.public_net?.firewalls ?? []).map((f) => ({ id: f.id ?? null, status: f.status ?? null })) }));
    return bare.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var serverBackups = {
  code: "hetzner.server.backups",
  provider: "hetzner",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.2", "iso:8.13", "gdpr:art32"],
  run: (ctx) => guarded("api.servers", async () => {
    const servers = (await list3(ctx, "servers")).filter(live);
    if (servers.length === 0) return unknown("api.no_servers");
    const off = servers.filter((s) => !s.backup_window).map(name2);
    const observed = { servers: servers.length, withoutBackups: off };
    const evidence = servers.map((s) => ({ name: name2(s), backupWindow: s.backup_window ?? null }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var deleteProtection = {
  code: "hetzner.server.delete_protection",
  provider: "hetzner",
  version: 1,
  severity: "medium",
  maps: ["soc2:A1.2", "soc2:CC6.1", "iso:8.13"],
  run: (ctx) => guarded("api.servers", async () => {
    const servers = (await list3(ctx, "servers")).filter(live);
    if (servers.length === 0) return unknown("api.no_servers");
    const off = servers.filter((s) => s.protection?.delete !== true).map(name2);
    const observed = { servers: servers.length, deletable: off };
    const evidence = servers.map((s) => ({ name: name2(s), deleteProtection: s.protection?.delete ?? null, rebuildProtection: s.protection?.rebuild ?? null }));
    return off.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var ADMIN_PORTS = [22, 3389, 5900, 2375, 2376, 3306, 5432, 6379, 27017, 9200, 11211];
var ANYWHERE = /* @__PURE__ */ new Set(["0.0.0.0/0", "::/0"]);
function coversAdminPort(port) {
  if (!port) return [];
  const m = /^(\d+)(?:-(\d+))?$/.exec(port.trim());
  if (!m) return [];
  const lo = Number(m[1]);
  const hi = m[2] ? Number(m[2]) : lo;
  return ADMIN_PORTS.filter((p) => p >= lo && p <= hi);
}
var adminPortsRestricted = {
  code: "hetzner.firewall.admin_ports_restricted",
  provider: "hetzner",
  version: 1,
  severity: "high",
  maps: ["soc2:CC6.6", "iso:8.20", "ce:firewalls", "ce:secure-config"],
  run: (ctx) => guarded("api.firewalls", async () => {
    const firewalls = (await list3(ctx, "firewalls")).filter((f) => (f.applied_to ?? []).length > 0);
    if (firewalls.length === 0) return unknown("api.no_applied_firewalls");
    const open = [];
    const evidence = firewalls.map((f) => {
      const exposed = (f.rules ?? []).filter((r) => r.direction === "in" && (r.protocol === "tcp" || r.protocol === "udp") && (r.source_ips ?? []).some((ip) => ANYWHERE.has(ip))).flatMap((r) => coversAdminPort(r.port));
      const ports = [...new Set(exposed)].sort((a, b) => a - b);
      if (ports.length) open.push(`${name2(f)}: ${ports.join(", ")}`);
      return { name: name2(f), rules: (f.rules ?? []).length, adminPortsOpenToInternet: ports };
    });
    const observed = { firewalls: firewalls.length, adminPortsOpen: open };
    return open.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var loadBalancerHttps = {
  code: "hetzner.load_balancer.https",
  provider: "hetzner",
  version: 1,
  severity: "medium",
  maps: ["soc2:CC6.7", "iso:8.24", "ce:secure-config"],
  run: (ctx) => guarded("api.load_balancers", async () => {
    const lbs = (await list3(ctx, "load_balancers")).filter((lb) => lb.public_net?.enabled !== false);
    if (lbs.length === 0) return unknown("api.no_public_load_balancers");
    const weak = lbs.filter((lb) => {
      const services2 = lb.services ?? [];
      const https = services2.filter((s) => s.protocol === "https");
      const plainHttp = services2.filter((s) => s.protocol === "http" && s.listen_port === 80);
      return https.length === 0 || !https.every((s) => (s.http?.certificates ?? []).length > 0 && s.http?.redirect_http === true) || plainHttp.length > 0;
    }).map(name2);
    const observed = { publicLoadBalancers: lbs.length, withoutHttpsRedirect: weak };
    const evidence = lbs.map((lb) => ({ name: name2(lb), services: (lb.services ?? []).map((s) => ({ protocol: s.protocol ?? null, port: s.listen_port ?? null, certificates: (s.http?.certificates ?? []).length, redirectHttp: s.http?.redirect_http ?? null })) }));
    return weak.length === 0 ? pass(observed, evidence) : fail(observed, evidence);
  })
};
var HETZNER_CHECKS = [serverFirewall, serverBackups, deleteProtection, adminPortsRestricted, loadBalancerHttps];

// ../lib/checks/registry.ts
function entries(defs) {
  return defs.map((d) => ({ code: d.code, provider: d.provider, version: d.version, severity: d.severity, maps: d.maps ?? [] }));
}
var CATALOGUE = [
  ...entries(DOMAIN_CHECKS),
  ...entries(SUPABASE_CHECKS),
  ...entries(GITHUB_CHECKS),
  ...entries(CLOUDFLARE_CHECKS),
  ...entries(STRIPE_CHECKS),
  ...entries(EMAIL_CHECKS),
  ...entries(SENTRY_CHECKS),
  ...entries(SLACK_CHECKS),
  ...entries(GOOGLE_CHECKS),
  ...entries(MICROSOFT_CHECKS),
  ...entries(UPTIMEROBOT_CHECKS),
  ...entries(GITLAB_CHECKS),
  ...entries(FLY_CHECKS),
  ...entries(VERCEL_CHECKS),
  ...entries(NETLIFY_CHECKS),
  ...entries(NEON_CHECKS),
  ...entries(RENDER_CHECKS),
  ...entries(REPO_CHECKS),
  ...entries(HEROKU_CHECKS),
  ...entries(CLERK_CHECKS),
  ...entries(ATLAS_CHECKS),
  ...entries(DIGITALOCEAN_CHECKS),
  ...entries(UPSTASH_CHECKS),
  ...entries(BETTERSTACK_CHECKS),
  ...entries(RAILWAY_CHECKS),
  ...entries(AUTH0_CHECKS),
  ...entries(BITBUCKET_CHECKS),
  ...entries(HETZNER_CHECKS)
];
var catalogueByCode = new Map(CATALOGUE.map((c) => [c.code, c]));

// ../lib/checks/ingest.ts
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
  railway: { env: "RAILWAY_TOKEN", label: "Railway", run: (t) => runRailwayChecks({ api: railwayApi(t) }) }
};
function text(key) {
  return COPY[key] ?? key;
}
function usage() {
  return [
    `snoopios ${"0.5.0"} \u2014 continuous compliance for small software teams`,
    "",
    "Usage:",
    "  snoopios scan <domain> [--email <resend|postmark|mailgun|ses|other>] [--json]",
    "  snoopios run <netlify|neon|render|heroku|clerk|upstash|betterstack|railway> [--json] [--push] [--ci]",
    "  snoopios doctor <postgres-connection-string> [--json]",
    "  snoopios repo [path] [--json] [--push] [--ci]",
    "",
    "scan    the domain checks (HTTPS, HSTS, CSP, TLS, SPF, DMARC, CAA, security.txt, privacy",
    "        page); --email adds the sending-domain checks with that provider's defaults",
    "run     a provider whose token cannot be made read-only, so it runs here instead of on",
    "        Snoopios's servers. Reads NETLIFY_AUTH_TOKEN, NEON_API_KEY, RENDER_API_KEY,",
    "        HEROKU_API_KEY, CLERK_SECRET_KEY, UPSTASH_API_KEY with UPSTASH_EMAIL,",
    "        BETTERSTACK_API_TOKEN or RAILWAY_TOKEN (a project token) from the environment.",
    "        The token never leaves this machine.",
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
    console.log(JSON.stringify({ subject, version: "0.5.0", checks: results.map((r) => ({ code: r.code, version: r.version, status: r.result.status, observed: r.result.observed, errorScope: r.result.errorScope ?? null })) }, null, 2));
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
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", accept: "application/json", connection: "close", "user-agent": `snoopios-cli/${"0.5.0"}` },
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
  const name3 = (positional[0] ?? "").toLowerCase();
  const p = LOCAL[name3];
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
  return emit(`snoopios run ${name3}`, name3, results, json, pushFlag ? { provider: name3, ci } : void 0);
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
  const client = new pg.Client({ connectionString: url, ssl: /localhost|127\.0\.0\.1/.test(url) ? void 0 : { rejectUnauthorized: false } });
  await client.connect();
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
    const [file2, args] = existsSync(npmCli) ? [process.execPath, [npmCli, "audit", "--json", "--audit-level=none"]] : [process.platform === "win32" ? "npm.cmd" : "npm", ["audit", "--json", "--audit-level=none"]];
    execFile(file2, args, { cwd, maxBuffer: 32 * 1024 * 1024, windowsHide: true, shell: file2 !== process.execPath && process.platform === "win32" }, (_err, stdout) => {
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
    console.log("0.5.0");
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
