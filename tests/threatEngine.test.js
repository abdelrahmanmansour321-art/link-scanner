'use strict';

const { runThreatEngine } = require('../src/services/threatEngine');

describe('runThreatEngine', () => {
  test('returns 0 score with no findings', () => {
    const result = runThreatEngine([], { hostType: 'domain', suspiciousKeywordMatches: [] });
    expect(result.score).toBe(0);
    expect(result.classification).toBe('clean');
  });

  test('accumulates score from findings by severity', () => {
    const findings = [
      { severity: 'high', category: 'url' },
      { severity: 'medium', category: 'domain' },
    ];
    const result = runThreatEngine(findings, { hostType: 'domain', suspiciousKeywordMatches: [] });
    expect(result.score).toBe(34); // 22 + 12
    expect(result.classification).toBe('suspicious');
  });

  test('applies compounding bonus for multiple obfuscation signals', () => {
    const findings = [
      { severity: 'medium', category: 'obfuscation' },
      { severity: 'medium', category: 'obfuscation' },
    ];
    const result = runThreatEngine(findings, { hostType: 'domain', suspiciousKeywordMatches: [] });
    // 12 + 12 + 10 (compounding bonus) = 34
    expect(result.score).toBe(34);
  });

  test('applies bonus for IP host + suspicious keywords', () => {
    const findings = [{ severity: 'low', category: 'url' }];
    const result = runThreatEngine(findings, { hostType: 'ipv4', suspiciousKeywordMatches: ['login'] });
    // 5 + 15 (IP + keyword bonus) = 20
    expect(result.score).toBe(20);
  });
});
