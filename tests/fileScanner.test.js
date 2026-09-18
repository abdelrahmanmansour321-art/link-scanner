'use strict';

const { scanFileWithVirusTotal } = require('../src/services/virusTotalService');
const { computeFileRisk } = require('../src/services/riskEngine');

describe('File Scanner Service and Engine Integration', () => {
  it('should compute risk for a clean file', async () => {
    const mockFileBuffer = Buffer.from('harmless content');
    const mockVtResult = {
      available: true,
      status: 'completed',
      malicious: 0,
      suspicious: 0,
      totalEngines: 70,
      permalink: 'https://example.com/file',
      sha256: 'abc'
    };

    // Spy/mock service call would ideally be here, but just testing risk engine logic for now.
    const risk = computeFileRisk(mockVtResult);

    expect(risk.riskScore).toBe(0);
    expect(risk.riskLevel).toBe('LOW');
    expect(risk.verdict).toBe('Likely Safe');
  });

  it('should compute high risk for a malicious file', async () => {
    const mockVtResult = {
      available: true,
      status: 'completed',
      malicious: 10,
      suspicious: 0,
      totalEngines: 70,
      permalink: 'https://example.com/file',
      sha256: 'abc'
    };

    const risk = computeFileRisk(mockVtResult);

    expect(risk.riskScore).toBeGreaterThan(0);
    expect(risk.riskLevel).not.toBe('LOW');
  });
});
