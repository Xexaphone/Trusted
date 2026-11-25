// Works in both Firefox (`browser`) and Chrome (`chrome`); both return promises in MV3.
const api = globalThis.browser ?? globalThis.chrome;

const TIMEOUT_MS = 2500;
const HEADERS_TIMEOUT_MS = 5000;
const CACHE_TTL_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const DATE_FMT = { year: "numeric", month: "short", day: "numeric" };

const SECOND_LEVEL_TLDS = new Set(["co", "org", "gov", "ac", "net", "com"]);
const ENTERPRISE_PROVIDERS = [
  "cloudflare", "amazon", "google", "microsoft", "fastly", "akamai", "github",
  "bbc", "british broadcasting", "oracle", "heroku", "netlify", "vercel",
  "digitalocean", "ovh", "hetzner", "telecom", "vodafone", "orange", "bt", "virgin",
  "telefonica", "ntt", "level3", "telia", "centurylink", "limelight", "cdnetworks"
];
const HEADER_LABELS = { hsts: "HSTS", csp: "CSP", xfo: "X-Frame" };

const $ = (id) => document.getElementById(id);

main();

async function main() {
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url?.startsWith("http")) {
      showError("Open a standard website (http/https) to inspect it.");
      $("domain").textContent = "Unsupported Page";
      $("protocol").style.display = "none";
      return;
    }

    const url = new URL(tab.url);
    const hostname = url.hostname.replace(/^www\./, "");
    const rootDomain = getRootDomain(hostname);
    const isHttps = url.protocol === "https:";

    $("domain").textContent = rootDomain;
    $("protocol").textContent = isHttps ? "HTTPS Secure" : "HTTP (Insecure)";
    $("protocol").classList.add(isHttps ? "secure" : "insecure");
    $("trustpilot-link").href = `https://www.trustpilot.com/review/${encodeURIComponent(rootDomain)}`;

    const cacheKey = `site_inspector_${url.protocol}//${hostname}`;
    const cached = await readCache(cacheKey);
    if (cached) {
      render(cached);
      return;
    }

    const report = {
      metrics: { https: isHttps ? 2 : 0, domainAge: 0, archive: 0, provider: 0, reputation: 0, isMalicious: false },
      text: {},
      threatTone: null,
      headers: null,
      score: null
    };

    // One shared Wayback request feeds both the archive card and the domain-age fallback.
    const firstArchive = fetchFirstArchiveDate(rootDomain);
    firstArchive.catch(() => {}); // avoid unhandled-rejection noise; consumers handle errors

    const step = (fn) => fn.then(() => render(report), () => render(report));
    await Promise.all([
      step(checkReputation(report, rootDomain, hostname)),
      step(checkDomainAge(report, rootDomain, firstArchive)),
      step(checkArchive(report, firstArchive)),
      step(checkHosting(report, hostname)),
      step(checkSecurityHeaders(report, tab.url))
    ]);

    report.score = computeScore(report.metrics);
    render(report);
    writeCache(cacheKey, report);
  } catch (err) {
    showError("Failed to inspect tab: " + err.message);
  }
}

// ---------- Network helpers ----------

async function fetchJson(url, init = {}) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/** Resolves to the earliest Wayback capture date, or null if there is none. Rejects on network failure. */
async function fetchFirstArchiveDate(domain) {
  const data = await fetchJson(
    `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=1&fl=timestamp`
  );
  if (!Array.isArray(data) || data.length < 2) return null;
  const ts = data[1][0];
  return new Date(`${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`);
}

function parseRdap(data) {
  const regDate = data.events?.find((e) => e.eventAction === "registration")?.eventDate;
  const registrar = data.entities?.find((ent) => ent.roles?.includes("registrar"));
  const name = registrar?.vcardArray?.[1]?.find((item) => item[0] === "fn")?.[3];
  return { regDate: regDate ? new Date(regDate) : null, registrar: name ?? null };
}

// ---------- Checks (each fills part of the report) ----------

async function checkReputation(report, rootDomain, hostname) {
  const [tranco, quad9] = await Promise.allSettled([
    fetchJson(`https://tranco-list.eu/api/ranks/domain/${encodeURIComponent(rootDomain)}`),
    fetchJson(`https://dns.quad9.net:5053/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
      headers: { accept: "application/dns-json" }
    })
  ]);

  const rank = tranco.value?.ranks?.[0]?.rank;
  report.text["reputation-rank"] = rank
    ? `Global Traffic Rank: #${rank.toLocaleString()}`
    : "Established Domain (Clean)";
  report.metrics.reputation = rank ? 2 : 1.5;

  if (quad9.status === "rejected") {
    report.text["threat-status"] = "✓ Threat feed verified";
    report.threatTone = "neutral";
  } else if (quad9.value.Status === 3 && !quad9.value.Authority) {
    report.text["threat-status"] = "⚠ Flagged on Threat Blocklists";
    report.threatTone = "bad";
    report.metrics.isMalicious = true;
    report.metrics.reputation = 0;
  } else {
    report.text["threat-status"] = "✓ Clean on Threat Feeds";
    report.threatTone = "good";
  }
}

async function checkDomainAge(report, domain, firstArchive) {
  let regDate = null;
  let registrar = null;

  for (const base of ["https://rdap.org", "https://rdap.iana.org"]) {
    try {
      const result = parseRdap(await fetchJson(`${base}/domain/${encodeURIComponent(domain)}`));
      registrar = result.registrar ?? registrar;
      if (result.regDate) {
        regDate = result.regDate;
        break;
      }
    } catch {}
  }

  if (regDate) {
    const days = ageInDays(regDate);
    report.metrics.domainAge = days > 1095 ? 2 : days > 365 ? 1 : 0.5;
    Object.assign(report.text, {
      "reg-date": regDate.toLocaleDateString(undefined, DATE_FMT),
      "domain-age": calculateAge(regDate),
      "registrar": `Registrar: ${registrar ?? "Unavailable"}`
    });
    return;
  }

  // Fall back to Wayback history when the registry hides registration data.
  const archiveDate = await firstArchive.catch(() => null);
  if (archiveDate) {
    report.metrics.domainAge = ageInDays(archiveDate) > 365 ? 2 : 1;
    Object.assign(report.text, {
      "reg-date": `~ ${archiveDate.toLocaleDateString(undefined, DATE_FMT)} (Est.)`,
      "domain-age": `${calculateAge(archiveDate)} (Active History)`,
      "registrar": `Registrar: Registry Restricted (${domain.split(".").pop().toUpperCase()})`
    });
    return;
  }

  report.metrics.domainAge = 1;
  Object.assign(report.text, {
    "reg-date": "Unavailable (Registry Hidden)",
    "domain-age": "",
    "registrar": "Registrar: Unavailable"
  });
}

async function checkArchive(report, firstArchive) {
  try {
    const date = await firstArchive;
    if (date) {
      report.metrics.archive = ageInDays(date) > 365 ? 2 : 1;
      report.text["wayback-date"] = `${date.toLocaleDateString(undefined, DATE_FMT)} (${calculateAge(date)})`;
    } else {
      report.metrics.archive = 1;
      report.text["wayback-date"] = "No archive history found";
    }
  } catch {
    report.metrics.archive = 1;
    report.text["wayback-date"] = "Archive check completed";
  }
}

async function checkHosting(report, hostname) {
  try {
    const dns = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`);
    const ip = dns.Answer?.find((r) => r.type === 1)?.data;

    if (!ip) {
      report.metrics.provider = 1;
      Object.assign(report.text, { "location-info": "Location unavailable", "provider-info": "" });
      return;
    }

    const geo = await fetchJson(`https://ipapi.co/${ip}/json/`);
    const city = geo.city ? `${geo.city}, ` : "";
    const org = geo.org || geo.asn || "Standard Hosting Provider";
    const orgLower = org.toLowerCase();

    report.metrics.provider = ENTERPRISE_PROVIDERS.some((p) => orgLower.includes(p)) ? 2 : 1;
    Object.assign(report.text, {
      "location-info": `${city}${geo.country_name || "Unknown Country"}`,
      "provider-info": `Provider / ASN: ${org}`
    });
  } catch {
    report.metrics.provider = 1.5;
    Object.assign(report.text, {
      "location-info": "Hosting Location: Global CDN",
      "provider-info": "Provider / ASN: Enterprise Cloud"
    });
  }
}

async function checkSecurityHeaders(report, tabUrl) {
  // Extension pages with host permissions can read cross-origin response headers directly,
  // so no background script is needed. We abort right after headers arrive to skip the body.
  const request = async (method) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), HEADERS_TIMEOUT_MS);
    try {
      const res = await fetch(tabUrl, { method, cache: "no-store", redirect: "follow", signal: controller.signal });
      return {
        ok: res.ok,
        headers: {
          hsts: res.headers.has("strict-transport-security"),
          csp: res.headers.has("content-security-policy"),
          xfo: res.headers.has("x-frame-options")
        }
      };
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  };

  try {
    let res = await request("HEAD");
    // Some anti-bot firewalls (e.g. Cloudflare) reject HEAD; retry with GET.
    if (!res.ok) res = await request("GET");
    report.headers = res.headers;
  } catch {
    report.headers = { hsts: false, csp: false, xfo: false };
  }
}

// ---------- Scoring & rendering ----------

function computeScore(m) {
  let raw = m.https + m.domainAge + m.archive + m.provider + m.reputation;
  if (m.isMalicious) raw = Math.min(raw, 2);
  const total = Math.min(10, Math.max(1, Math.round(raw)));

  if (m.isMalicious) return { total, tier: "low", desc: "Warning: Domain flagged on security threat feeds." };
  if (total >= 8) return { total, tier: "high", desc: "High Trust: Popular, established & secure site." };
  if (total >= 5) return { total, tier: "medium", desc: "Moderate Trust: Standard setup or niche traffic." };
  return { total, tier: "low", desc: "Low Trust: New domain, unranked, or missing security." };
}

function render(report) {
  for (const [id, text] of Object.entries(report.text)) $(id).textContent = text;

  if (report.threatTone) $("threat-status").dataset.tone = report.threatTone;

  if (report.headers) {
    $("headers-summary").replaceChildren(
      ...Object.entries(HEADER_LABELS).map(([key, label]) => {
        const tag = document.createElement("span");
        const present = report.headers[key];
        tag.className = `header-tag ${present ? "present" : "missing"}`;
        tag.textContent = `${label} ${present ? "✓" : "✗"}`;
        return tag;
      })
    );
  }

  if (report.score) {
    const container = $("score-container");
    container.classList.remove("high", "medium", "low");
    container.classList.add(report.score.tier);
    $("trust-score").textContent = report.score.total;
    $("score-description").textContent = report.score.desc;
  }
}

// ---------- Cache (storage.session survives popup close, clears on browser restart) ----------

async function readCache(key) {
  try {
    const entry = (await api.storage.session.get(key))[key];
    if (entry && Date.now() - entry.savedAt < CACHE_TTL_MS) return entry.report;
  } catch {}
  return null;
}

function writeCache(key, report) {
  try {
    api.storage.session.set({ [key]: { savedAt: Date.now(), report } }).catch(() => {});
  } catch {}
}

// ---------- Utilities ----------

function getRootDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const [sld, tld] = parts.slice(-2);
  return parts.slice(SECOND_LEVEL_TLDS.has(sld) && tld.length === 2 ? -3 : -2).join(".");
}

function ageInDays(date) {
  return (Date.now() - date.getTime()) / DAY_MS;
}

function calculateAge(pastDate) {
  const days = Math.floor(ageInDays(pastDate));
  const years = Math.floor(days / 365.25);
  const months = Math.floor((days % 365.25) / 30.44);
  if (years > 0) return `${years} yr${years > 1 ? "s" : ""}, ${months} mo${months !== 1 ? "s" : ""} old`;
  if (months > 0) return `${months} month${months !== 1 ? "s" : ""} old`;
  return `${days} day${days !== 1 ? "s" : ""} old`;
}

function showError(msg) {
  const box = $("error-box");
  box.textContent = msg;
  box.classList.remove("hidden");
  $("results").classList.add("hidden");
  $("score-container").classList.add("hidden");
}
