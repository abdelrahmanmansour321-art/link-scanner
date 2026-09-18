'use strict';

const {
  computeRisk, scoreFromVirusTotal, scoreFromThreatFeed, levelFromScore,
} = require('../src/services/riskEngine');

describe('levelFromScore', () => {
  test('buckets correctly', () => {
    expect(levelFromScore(0)).toBe('LOW');
    expect(levelFromScore(20)).toBe('LOW');
    expect(levelFromScore(21)).toBe('MEDIUM');
    expect(levelFromScore(50)).toBe('MEDIUM');
    expect(levelFromScore(51)).toBe('HIGH');
    expect(levelFromScore(75)).toBe('HIGH');
    expect(levelFromScore(76)).toBe('CRITICAL');
    expect(levelFromScore(100)).toBe('CRITICAL');
  });
});

describe('scoreFromVirusTotal', () => {
  test('returns null when unavailable', () => {
    expect(scoreFromVirusTotal({ available: false })).toBeNull();
  });

  test('returns 0 for a clean result', () => {
    const score = scoreFromVirusTotal({
      available: true, status: 'completed', malicious: 0, suspicious: 0, totalEngines: 70,
    });
    expect(score).toBe(0);
  });

  test('guarantees a minimum score for any malicious detection', () => {
    const score = scoreFromVirusTotal({
      available: true, status: 'completed', malicious: 1, suspicious: 0, totalEngines: 70,
    });
    expect(score).toBeGreaterThanOrEqual(30);
  });
});

describe('computeRisk', () => {
  test('low risk when clean everywhere', () => {
    const threatEngineResult = { score: 0, classification: 'clean' };
    const virusTotalResult = {
      available: true, status: 'completed', malicious: 0, suspicious: 0, harmless: 70, undetected: 5, totalEngines: 75,
    };
    const result = computeRisk(threatEngineResult, virusTotalResult, []);
    expect(result.riskLevel).toBe('LOW');
    expect(result.riskScore).toBeLessThanOrEqual(20);
  });

  test('high risk when VT flags a majority of engines as malicious', () => {
    const threatEngineResult = { score: 40, classification: 'suspicious' };
    const virusTotalResult = {
      available: true, status: 'completed', malicious: 50, suspicious: 5, harmless: 15, undetected: 5, totalEngines: 75,
    };
    const result = computeRisk(threatEngineResult, virusTotalResult, []);
    // maliciousRatio ~0.667, suspiciousRatio ~0.067 -> vtScore ~69.3 (65% weight)
    // teScore 40 (35% weight) -> ~59 -> HIGH
    expect(result.riskLevel).toBe('HIGH');
    expect(result.riskScore).toBeGreaterThanOrEqual(51);
  });

  test('critical risk when almost all engines flag as malicious', () => {
    const threatEngineResult = { score: 80, classification: 'malicious' };
    const virusTotalResult = {
      available: true, status: 'completed', malicious: 70, suspicious: 3, harmless: 2, undetected: 0, totalEngines: 75,
    };
    const result = computeRisk(threatEngineResult, virusTotalResult, []);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('falls back to threat engine weighting when VT unavailable', () => {
    const threatEngineResult = { score: 90, classification: 'malicious' };
    const virusTotalResult = { available: false, status: 'not_configured' };
    const result = computeRisk(threatEngineResult, virusTotalResult, []);
    // 90/100 * 70 = 63 -> HIGH
    expect(result.riskScore).toBe(63);
    expect(result.riskLevel).toBe('HIGH');
  });
});

describe('scoreFromThreatFeed', () => {
  test('returns null when unavailable', () => {
    expect(scoreFromThreatFeed({ available: false })).toBeNull();
  });

  test('returns null when status is not completed', () => {
    expect(scoreFromThreatFeed({ available: true, status: 'pending' })).toBeNull();
  });

  test('returns 0 for a clean verdict', () => {
    const score = scoreFromThreatFeed({ available: true, status: 'completed', isMalicious: false });
    expect(score).toBe(0);
  });

  test('returns a high score for a malicious verdict', () => {
    const score = scoreFromThreatFeed({ available: true, status: 'completed', isMalicious: true, threatType: 'phishing' });
    expect(score).toBe(85);
  });
});

describe('computeRisk (three-source model, with threatFeedResult)', () => {
  const cleanThreatEngine = { score: 0, classification: 'clean' };
  const cleanVt = {
    available: true, status: 'completed', malicious: 0, suspicious: 0, harmless: 70, undetected: 5, totalEngines: 75,
  };
  const cleanFeed = { available: true, status: 'completed', isMalicious: false, threatType: null };

  test('legacy 3-arg call is unaffected by the new weighting model', () => {
    const threatEngineResult = { score: 90, classification: 'malicious' };
    const virusTotalResult = { available: false, status: 'not_configured' };
    const result = computeRisk(threatEngineResult, virusTotalResult, []);
    expect(result.riskScore).toBe(63);
    expect(result.riskLevel).toBe('HIGH');
  });

  test('low risk when all three sources are clean', () => {
    const result = computeRisk(cleanThreatEngine, cleanVt, [], cleanFeed);
    expect(result.riskLevel).toBe('LOW');
    expect(result.riskScore).toBe(0);
  });

  test('threat feed malicious verdict raises the score even when VT and local engine are clean', () => {
    const maliciousFeed = {
      available: true, status: 'completed', isMalicious: true, threatType: 'phishing',
    };
    const result = computeRisk(cleanThreatEngine, cleanVt, [], maliciousFeed);
    // vtScore 0 * 50% + feedScore 85 * 25% + teScore 0 * 25% = 21.25 -> 21 -> MEDIUM
    expect(result.riskScore).toBeGreaterThan(0);
    expect(result.findings.some((f) => f.category === 'threat-feed')).toBe(true);
  });

  test('re-weights to Threat Feed + Threat Engine when VirusTotal is unavailable', () => {
    const unavailableVt = { available: false, status: 'not_configured' };
    const maliciousFeed = {
      available: true, status: 'completed', isMalicious: true, threatType: 'malware',
    };
    const threatEngineResult = { score: 50, classification: 'suspicious' };
    const result = computeRisk(threatEngineResult, unavailableVt, [], maliciousFeed);
    // feedScore 85 * 50% + teScore 50 * 50% = 67.5 -> 68 -> HIGH
    expect(result.riskScore).toBe(68);
    expect(result.riskLevel).toBe('HIGH');
  });

  test('falls back to Threat Engine only when both VT and Threat Feed are unavailable', () => {
    const unavailableVt = { available: false, status: 'not_configured' };
    const unavailableFeed = { available: false, status: 'not_configured' };
    const threatEngineResult = { score: 90, classification: 'malicious' };
    const result = computeRisk(threatEngineResult, unavailableVt, [], unavailableFeed);
    // 90/100 * 70 = 63 -> HIGH (same fallback weight as the legacy model)
    expect(result.riskScore).toBe(63);
    expect(result.riskLevel).toBe('HIGH');
  });

  test('adds an info finding and recommendation when Threat Feed is unavailable', () => {
    const unavailableFeed = { available: false, status: 'timeout', message: 'Threat Feed request timed out.' };
    const result = computeRisk(cleanThreatEngine, cleanVt, [], unavailableFeed);
    expect(result.findings.some((f) => f.category === 'threat-feed' && f.severity === 'info')).toBe(true);
    expect(result.recommendations.some((r) => r.toLowerCase().includes('threat feed'))).toBe(true);
  });
});
