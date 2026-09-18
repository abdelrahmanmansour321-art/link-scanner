'use strict';


const SEVERITY_WEIGHTS = {
  critical: 35,
  high: 22,
  medium: 12,
  low: 5,
  info: 0,
};

/**
 * Run the local threat engine against pre-computed static findings/features.
 * @param {Array} findings - findings produced by urlAnalysisService.analyzeUrlStatic
 * @param {Object} features - feature bag produced by the same function
 */
function runThreatEngine(findings, features) {
  let rawScore = 0;
  const categoryCounts = {};

  for (const finding of findings) {
    rawScore += SEVERITY_WEIGHTS[finding.severity] ?? 0;
    categoryCounts[finding.category] = (categoryCounts[finding.category] || 0) + 1;
  }

 
  if ((categoryCounts.obfuscation || 0) >= 2) {
    rawScore += 10;
  }
  
  if (features.hostType !== 'domain' && features.suspiciousKeywordMatches?.length > 0) {
    rawScore += 15;
  }

  const score = Math.max(0, Math.min(100, Math.round(rawScore)));

  let classification = 'clean';
  if (score >= 76) classification = 'malicious';
  else if (score >= 51) classification = 'highly_suspicious';
  else if (score >= 21) classification = 'suspicious';
  else if (score >= 1) classification = 'low_risk';

  return {
    engine: 'local-threat-engine',
    version: '1.0.0',
    score,
    classification,
    signalsDetected: findings.length,
    categoryCounts,
  };
}

module.exports = {
  runThreatEngine,
  SEVERITY_WEIGHTS,
};
