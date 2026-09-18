'use strict';

const {
  parseAndValidateUrl,
  isPrivateIPv4,
  isPrivateIPv6,
  classifyHostname,
  analyzeUrlStatic,
  UrlValidationError,
} = require('../src/services/urlAnalysisService');

describe('parseAndValidateUrl', () => {
  test('accepts a valid https URL', () => {
    const parsed = parseAndValidateUrl('https://example.com/path?a=1');
    expect(parsed.hostname).toBe('example.com');
  });

  test('rejects missing url', () => {
    expect(() => parseAndValidateUrl(undefined)).toThrow(UrlValidationError);
  });

  test('rejects empty url', () => {
    expect(() => parseAndValidateUrl('   ')).toThrow(UrlValidationError);
  });

  test('rejects malformed url', () => {
    expect(() => parseAndValidateUrl('not a url')).toThrow(UrlValidationError);
  });

  test('rejects unsupported protocol javascript:', () => {
    expect(() => parseAndValidateUrl('javascript:alert(1)')).toThrow(UrlValidationError);
  });

  test('rejects file: protocol', () => {
    expect(() => parseAndValidateUrl('file:///etc/passwd')).toThrow(UrlValidationError);
  });

  test('rejects data: protocol', () => {
    expect(() => parseAndValidateUrl('data:text/html,<script>alert(1)</script>')).toThrow(UrlValidationError);
  });

  test('rejects credentials in url', () => {
    expect(() => parseAndValidateUrl('https://user:pass@example.com')).toThrow(UrlValidationError);
  });

  test('rejects extremely long urls', () => {
    const longUrl = `https://example.com/${'a'.repeat(3000)}`;
    expect(() => parseAndValidateUrl(longUrl)).toThrow(UrlValidationError);
  });
});

describe('classifyHostname', () => {
  test('detects ipv4', () => {
    expect(classifyHostname('192.168.1.1')).toBe('ipv4');
  });
  test('detects ipv6', () => {
    expect(classifyHostname('::1')).toBe('ipv6');
  });
  test('detects domain', () => {
    expect(classifyHostname('example.com')).toBe('domain');
  });
});

describe('isPrivateIPv4', () => {
  test('flags loopback', () => {
    expect(isPrivateIPv4('127.0.0.1')).toBe(true);
  });
  test('flags 10.x', () => {
    expect(isPrivateIPv4('10.0.0.5')).toBe(true);
  });
  test('flags 192.168.x', () => {
    expect(isPrivateIPv4('192.168.1.100')).toBe(true);
  });
  test('flags 172.16-31.x', () => {
    expect(isPrivateIPv4('172.20.0.1')).toBe(true);
    expect(isPrivateIPv4('172.15.0.1')).toBe(false);
    expect(isPrivateIPv4('172.32.0.1')).toBe(false);
  });
  test('flags link-local 169.254.x', () => {
    expect(isPrivateIPv4('169.254.1.1')).toBe(true);
  });
  test('allows public IP', () => {
    expect(isPrivateIPv4('8.8.8.8')).toBe(false);
  });
});

describe('isPrivateIPv6', () => {
  test('flags loopback ::1', () => {
    expect(isPrivateIPv6('::1')).toBe(true);
  });
  test('flags link-local fe80::', () => {
    expect(isPrivateIPv6('fe80::1')).toBe(true);
  });
  test('flags unique local fd00::', () => {
    expect(isPrivateIPv6('fd12:3456:789a::1')).toBe(true);
  });
  test('allows public IPv6 (Google DNS)', () => {
    expect(isPrivateIPv6('2001:4860:4860::8888')).toBe(false);
  });
});

describe('analyzeUrlStatic', () => {
  test('flags http (non-https)', () => {
    const parsed = new URL('http://example.com');
    const { findings } = analyzeUrlStatic(parsed, 'domain');
    expect(findings.some((f) => f.category === 'transport')).toBe(true);
  });

  test('flags raw IP host', () => {
    const parsed = new URL('http://8.8.8.8/');
    const { findings } = analyzeUrlStatic(parsed, 'ipv4');
    expect(findings.some((f) => f.message.includes('raw IP address'))).toBe(true);
  });

  test('flags suspicious keywords without asserting malicious', () => {
    const parsed = new URL('https://example.com/account/verify/login');
    const { findings } = analyzeUrlStatic(parsed, 'domain');
    const kwFinding = findings.find((f) => f.category === 'url' && f.message.includes('keyword'));
    expect(kwFinding).toBeDefined();
    expect(['low', 'medium']).toContain(kwFinding.severity);
  });

  test('detects double url-encoding obfuscation', () => {
    const parsed = new URL('https://example.com/%2568%2574%2574%2570');
    const { findings } = analyzeUrlStatic(parsed, 'domain');
    expect(findings.some((f) => f.message.toLowerCase().includes('double'))).toBe(true);
  });
});
