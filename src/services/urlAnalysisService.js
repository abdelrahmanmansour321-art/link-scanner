'use strict';


const dns = require('dns').promises;
const net = require('net');
const validator = require('validator');

const ALLOWED_PROTOCOLS = ['http:', 'https:'];
const MAX_URL_LENGTH = 2048;
const MAX_HOSTNAME_LENGTH = 253;

const SUSPICIOUS_TLDS = [
  'zip', 'mov', 'xyz', 'top', 'click', 'link', 'gq', 'tk', 'ml', 'cf', 'ga',
  'work', 'support', 'rest', 'live', 'icu', 'cam', 'quest', 'monster',
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'account', 'secure',
  'security', 'update', 'password', 'credential', 'wallet', 'banking',
  'payment', 'confirm', 'authentication', 'unlock', 'recover',
];


const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'bl.ink', 'lnkd.in', 'rebrand.ly', 'cutt.ly', 'shorte.st',
  'tiny.cc', 'v.gd', 'soo.gd', 'rb.gy', 's.id',
];


class UrlValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'UrlValidationError';
    this.code = code;
  }
}


function parseAndValidateUrl(rawUrl) {
  if (rawUrl === undefined || rawUrl === null) {
    throw new UrlValidationError('MISSING_URL', 'A "url" field is required.');
  }
  if (typeof rawUrl !== 'string') {
    throw new UrlValidationError('INVALID_URL', 'The "url" field must be a string.');
  }
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) {
    throw new UrlValidationError('EMPTY_URL', 'The "url" field must not be empty.');
  }
  if (trimmed.length > MAX_URL_LENGTH) {
    throw new UrlValidationError('URL_TOO_LONG', `URL exceeds maximum length of ${MAX_URL_LENGTH} characters.`);
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (err) {
    throw new UrlValidationError('MALFORMED_URL', 'The provided URL is malformed.');
  }

  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    throw new UrlValidationError(
      'UNSUPPORTED_PROTOCOL',
      `Protocol "${parsed.protocol}" is not supported. Only http and https are allowed.`
    );
  }

  if (parsed.username || parsed.password) {
    throw new UrlValidationError(
      'CREDENTIALS_IN_URL',
      'URLs containing embedded credentials (user:pass@host) are not allowed.'
    );
  }

  if (!parsed.hostname || parsed.hostname.length === 0) {
    throw new UrlValidationError('INVALID_URL', 'The URL is missing a hostname.');
  }

  if (parsed.hostname.length > MAX_HOSTNAME_LENGTH) {
    throw new UrlValidationError('INVALID_URL', 'The URL hostname is too long.');
  }

  // Basic sanity check with validator as a second opinion (not authoritative,
  // since it does not know about our specific policy needs).
  if (!validator.isURL(trimmed, { require_protocol: true, protocols: ['http', 'https'] })) {
    throw new UrlValidationError('INVALID_URL', 'The provided URL failed format validation.');
  }

  return parsed;
}


function classifyHostname(hostname) {
  // Strip IPv6 brackets if present, e.g. "[::1]" -> "::1"
  const bare = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;

  if (net.isIPv4(bare)) return 'ipv4';
  if (net.isIPv6(bare)) return 'ipv6';
  return 'domain';
}


function isPrivateIPv4(ip) {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    return true; // malformed -> treat as unsafe
  }
  const [a, b] = octets;

  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
  if (a === 0) return true; // "this network"
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && octets[2] === 0) return true; // 192.0.0.0/24 IETF protocol assignments
  if (a === 192 && b === 0 && octets[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && octets[2] === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && octets[2] === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast/reserved/broadcast (224+)

  return false;
}


function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  if (normalized === '::1') return true; // loopback
  if (normalized === '::') return true; // unspecified
  if (normalized.startsWith('fe80:')) return true; // link-local
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // unique local (fc00::/7)
  if (normalized.startsWith('::ffff:')) {
    // IPv4-mapped IPv6 address - extract and check the embedded IPv4
    const mapped = normalized.split(':').pop();
    if (net.isIPv4(mapped)) return isPrivateIPv4(mapped);
    return true;
  }
  if (normalized.startsWith('2002:')) return true; // 6to4 (treat conservatively)
  if (normalized.startsWith('::')) return true; // catch remaining compatibility addresses

  return false;
}


async function resolveAndCheckSSRF(hostname) {
  const hostType = classifyHostname(hostname);

  if (hostname.toLowerCase() === 'localhost' || hostname.toLowerCase().endsWith('.localhost')) {
    throw new UrlValidationError('SSRF_BLOCKED', 'Requests to localhost are not allowed.');
  }

  if (hostType === 'ipv4') {
    if (isPrivateIPv4(hostname)) {
      throw new UrlValidationError('SSRF_BLOCKED', 'Requests to private or reserved IP addresses are not allowed.');
    }
    return { hostType, resolvedIps: [hostname] };
  }

  if (hostType === 'ipv6') {
    const bare = hostname.startsWith('[') ? hostname.slice(1, -1) : hostname;
    if (isPrivateIPv6(bare)) {
      throw new UrlValidationError('SSRF_BLOCKED', 'Requests to private or reserved IP addresses are not allowed.');
    }
    return { hostType, resolvedIps: [bare] };
  }

  
  let addresses = [];
  try {
    const [v4, v6] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
    ]);
    if (v4.status === 'fulfilled') addresses = addresses.concat(v4.value);
    if (v6.status === 'fulfilled') addresses = addresses.concat(v6.value);
  } catch (err) {
    throw new UrlValidationError('DNS_RESOLUTION_FAILED', 'The domain could not be resolved.');
  }

  if (addresses.length === 0) {
    throw new UrlValidationError('DNS_RESOLUTION_FAILED', 'The domain did not resolve to any IP address.');
  }

  for (const addr of addresses) {
    if (net.isIPv4(addr) && isPrivateIPv4(addr)) {
      throw new UrlValidationError('SSRF_BLOCKED', 'The domain resolves to a private or internal IP address.');
    }
    if (net.isIPv6(addr) && isPrivateIPv6(addr)) {
      throw new UrlValidationError('SSRF_BLOCKED', 'The domain resolves to a private or internal IP address.');
    }
  }

  return { hostType: 'domain', resolvedIps: addresses };
}


function analyzeUrlStatic(parsedUrl, hostType) {
  const findings = [];
  const fullUrl = parsedUrl.toString();
  const hostname = parsedUrl.hostname.toLowerCase();


  const usesHttps = parsedUrl.protocol === 'https:';
  if (!usesHttps) {
    findings.push({
      severity: 'medium',
      category: 'transport',
      message: 'The URL uses plain HTTP instead of HTTPS, so traffic is not encrypted.',
    });
  }

  const port = parsedUrl.port ? Number(parsedUrl.port) : (usesHttps ? 443 : 80);
  const commonPorts = [80, 443, 8080, 8443];
  const unusualPort = !commonPorts.includes(port);
  if (unusualPort) {
    findings.push({
      severity: 'medium',
      category: 'url',
      message: `The URL uses an unusual port (${port}) rarely seen for legitimate websites.`,
    });
  }

  // --- Host type ---
  if (hostType === 'ipv4' || hostType === 'ipv6') {
    findings.push({
      severity: 'medium',
      category: 'domain',
      message: 'The URL uses a raw IP address instead of a domain name.',
    });
  }

  // --- Length checks ---
  if (fullUrl.length > 200) {
    findings.push({
      severity: 'low',
      category: 'url',
      message: 'The URL is unusually long.',
    });
  }
  if (hostname.length > 40 && hostType === 'domain') {
    findings.push({
      severity: 'low',
      category: 'domain',
      message: 'The domain name is unusually long.',
    });
  }

  // --- Subdomain / hyphen / numeric checks (domains only) ---
  let labels = [];
  if (hostType === 'domain') {
    labels = hostname.split('.');
    const subdomainCount = Math.max(0, labels.length - 2);
    if (subdomainCount >= 3) {
      findings.push({
        severity: 'medium',
        category: 'domain',
        message: 'The domain has an excessive number of subdomains.',
      });
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      findings.push({
        severity: 'low',
        category: 'domain',
        message: 'The domain contains an unusually high number of hyphens.',
      });
    }

    const digitRatio = (hostname.match(/\d/g) || []).length / hostname.length;
    if (digitRatio > 0.3) {
      findings.push({
        severity: 'medium',
        category: 'domain',
        message: 'The domain name contains an unusually high proportion of digits.',
      });
    }

    // Punycode / IDN
    if (labels.some((label) => label.startsWith('xn--'))) {
      findings.push({
        severity: 'medium',
        category: 'domain',
        message: 'The domain uses punycode (internationalized domain name) encoding, sometimes used for lookalike domains.',
      });
    }

    // Suspicious TLD
    const tld = labels[labels.length - 1];
    if (SUSPICIOUS_TLDS.includes(tld)) {
      findings.push({
        severity: 'low',
        category: 'domain',
        message: `The domain uses a top-level domain (.${tld}) frequently associated with abuse.`,
      });
    }

    // Random-looking domain heuristic: long consonant runs / low vowel ratio
    const mainLabel = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
    const vowels = (mainLabel.match(/[aeiou]/gi) || []).length;
    const vowelRatio = mainLabel.length > 0 ? vowels / mainLabel.length : 1;
    if (mainLabel.length >= 8 && vowelRatio < 0.2) {
      findings.push({
        severity: 'low',
        category: 'domain',
        message: 'The domain name looks randomly generated (very few vowels for its length).',
      });
    }

    // URL shortener
    if (URL_SHORTENERS.includes(hostname)) {
      findings.push({
        severity: 'medium',
        category: 'obfuscation',
        message: 'The URL uses a link-shortening service, which can hide the true destination.',
      });
    }
  }

  // --- Path depth ---
  const pathSegments = parsedUrl.pathname.split('/').filter(Boolean);
  if (pathSegments.length > 5) {
    findings.push({
      severity: 'low',
      category: 'url',
      message: 'The URL has an excessive path depth.',
    });
  }

  // --- Query parameters ---
  const paramCount = Array.from(parsedUrl.searchParams.keys()).length;
  if (paramCount > 8) {
    findings.push({
      severity: 'low',
      category: 'url',
      message: 'The URL contains an excessive number of query parameters.',
    });
  }

  // --- Percent-encoding / obfuscation ---
  const percentMatches = fullUrl.match(/%[0-9A-Fa-f]{2}/g) || [];
  if (percentMatches.length > 6) {
    findings.push({
      severity: 'medium',
      category: 'obfuscation',
      message: 'The URL contains excessive percent-encoding, which can be used to obscure content.',
    });
  }
  // Double-encoding detection e.g. %2520
  if (/%25[0-9A-Fa-f]{2}/.test(fullUrl)) {
    findings.push({
      severity: 'high',
      category: 'obfuscation',
      message: 'The URL appears to use double URL-encoding, a common obfuscation technique.',
    });
  }
  // Hex-looking host component (e.g. 0x-prefixed or fully hex label mimicking an IP)
  if (hostType === 'domain' && labels.length && /^0x[0-9a-f]+$/i.test(labels[0])) {
    findings.push({
      severity: 'medium',
      category: 'obfuscation',
      message: 'The URL host contains a hexadecimal-looking component, sometimes used to disguise an IP address.',
    });
  }

  // --- Suspicious keywords (informational risk indicator only) ---
  const lowerFullUrl = fullUrl.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((kw) => lowerFullUrl.includes(kw));
  if (matchedKeywords.length > 0) {
    findings.push({
      severity: matchedKeywords.length >= 3 ? 'medium' : 'low',
      category: 'url',
      message: `The URL contains ${matchedKeywords.length === 1 ? 'a' : 'multiple'} authentication-related keyword(s) (${matchedKeywords.slice(0, 5).join(', ')}). This alone does not indicate malicious intent.`,
    });
  }

  const features = {
    usesHttps,
    port,
    unusualPort,
    hostType,
    urlLength: fullUrl.length,
    hostnameLength: hostname.length,
    pathDepth: pathSegments.length,
    queryParamCount: paramCount,
    percentEncodedCount: percentMatches.length,
    isShortener: hostType === 'domain' && URL_SHORTENERS.includes(hostname),
    suspiciousKeywordMatches: matchedKeywords,
    suspiciousTld: hostType === 'domain' && SUSPICIOUS_TLDS.includes(labels[labels.length - 1]),
  };

  return { findings, features };
}

/**
 * Full pipeline: validate structure, run SSRF/DNS checks, then static analysis.
 * Throws UrlValidationError on any blocking condition.
 */
async function validateAndAnalyzeUrl(rawUrl) {
  const parsed = parseAndValidateUrl(rawUrl);
  const { hostType, resolvedIps } = await resolveAndCheckSSRF(parsed.hostname);
  const { findings, features } = analyzeUrlStatic(parsed, hostType);

  return {
    normalizedUrl: parsed.toString(),
    hostname: parsed.hostname,
    hostType,
    resolvedIps,
    findings,
    features,
  };
}

module.exports = {
  UrlValidationError,
  parseAndValidateUrl,
  resolveAndCheckSSRF,
  analyzeUrlStatic,
  validateAndAnalyzeUrl,
  classifyHostname,
  isPrivateIPv4,
  isPrivateIPv6,
  URL_SHORTENERS,
  SUSPICIOUS_KEYWORDS,
  SUSPICIOUS_TLDS,
};
