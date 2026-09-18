'use strict';



const { clamp } = require('../utils/helpers');

const WEIGHT_VT = 65;
const WEIGHT_THREAT_ENGINE = 35;
const WEIGHT_THREAT_ENGINE_NO_VT = 70;


const THREE_SOURCE_WEIGHTS = {
  vtAndFeed: { vt: 50, feed: 25, te: 25 }, // all three sources usable
  vtOnly: { vt: 65, feed: 0, te: 35 }, // threat feed unavailable
  feedOnly: { vt: 0, feed: 50, te: 50 }, // VirusTotal unavailable
  neither: { vt: 0, feed: 0, te: 70 }, // both external sources unavailable
};

function scoreFromThreatFeed(tf) {
  if (!tf || !tf.available || tf.status !== 'completed') {
    return null; // signals "not usable"
  }
  return tf.isMalicious ? 85 : 0;
}

function scoreFromVirusTotal(vt) {
  if (!vt || !vt.available || vt.status !== 'completed') {
    return null; // signals "not usable"
  }
  const total = vt.totalEngines || 0;
  if (total === 0) return 0;

  const maliciousRatio = vt.malicious / total;
  const suspiciousRatio = vt.suspicious / total;

  
  let ratioScore = (maliciousRatio * 1.0 + suspiciousRatio * 0.4) * 100;

 
  if (vt.malicious > 0) {
    ratioScore = Math.max(ratioScore, 30);
  } else if (vt.suspicious > 0) {
    ratioScore = Math.max(ratioScore, 10);
  }

  return clamp(ratioScore, 0, 100);
}

function levelFromScore(score) {
  if (score >= 76) return 'CRITICAL';
  if (score >= 51) return 'HIGH';
  if (score >= 21) return 'MEDIUM';
  return 'LOW';
}

function verdictFromLevel(level) {
  switch (level) {
    case 'CRITICAL':
      return 'Highly Suspicious';
    case 'HIGH':
      return 'Likely Unsafe';
    case 'MEDIUM':
      return 'Use Caution';
    default:
      return 'Likely Safe';
  }
}

function buildRecommendations(level, findings, vt, threatFeed) {
  const recs = [];

  if (level === 'CRITICAL' || level === 'HIGH') {
    recs.push('Do not enter passwords, personal data, or payment information on this website.');
    recs.push('Avoid opening this link if it was received unexpectedly, especially via email or SMS.');
    recs.push('Report this link to your IT/security team if it arrived through a work account.');
  } else if (level === 'MEDIUM') {
    recs.push('Proceed with caution and verify the domain name carefully before continuing.');
    recs.push('Avoid entering sensitive information unless you can confirm this site is legitimate.');
  } else {
    recs.push('No major threats detected, but always verify the domain before entering sensitive data.');
  }

  if (findings.some((f) => f.category === 'obfuscation')) {
    recs.push('This URL shows signs of obfuscation - inspect the real destination before clicking.');
  }
  if (findings.some((f) => f.category === 'domain' && f.message.toLowerCase().includes('shorten'))) {
    recs.push('This is a shortened link; consider expanding it with a link-preview tool before visiting.');
  }
  if (vt && vt.available === false) {
    recs.push('VirusTotal reputation data was unavailable for this scan; results rely on local static analysis only.');
  }
  if (threatFeed && threatFeed.available && threatFeed.status === 'completed' && threatFeed.isMalicious) {
    recs.push(`Threat feed intelligence flagged this URL${threatFeed.threatType ? ` as ${threatFeed.threatType}` : ''}; treat it as untrustworthy.`);
  }
  if (threatFeed && threatFeed.available === false) {
    recs.push('Threat Feed reputation data was unavailable for this scan.');
  }

  return recs;
}

/**
 * @param {Object} threatEngineResult - output of threatEngine.runThreatEngine
 * @param {Object} virusTotalResult - output of virusTotalService.scanUrlWithVirusTotal
 * @param {Array} findings - findings array from urlAnalysisService (static findings)
 * @param {Object} [threatFeedResult] - output of threatFeedService.scanUrlWithThreatFeed.
 *   Optional for backward compatibility: when omitted, the legacy two-source
 *   (VirusTotal + Threat Engine) weighting model is used unchanged.
 */
function computeRisk(threatEngineResult, virusTotalResult, findings, threatFeedResult) {
  const vtScore = scoreFromVirusTotal(virusTotalResult);
  const teScore = threatEngineResult.score; // 0-100
  const includeThreatFeed = threatFeedResult !== undefined;
  const tfScore = includeThreatFeed ? scoreFromThreatFeed(threatFeedResult) : null;

  let finalScore;
  if (!includeThreatFeed) {
    // Legacy two-source model (VirusTotal + local Threat Engine only).
    if (vtScore === null) {
      finalScore = (teScore / 100) * WEIGHT_THREAT_ENGINE_NO_VT;
    } else {
      finalScore = (vtScore / 100) * WEIGHT_VT + (teScore / 100) * WEIGHT_THREAT_ENGINE;
    }
  } else {
    
    let weights;
    if (vtScore !== null && tfScore !== null) weights = THREE_SOURCE_WEIGHTS.vtAndFeed;
    else if (vtScore !== null) weights = THREE_SOURCE_WEIGHTS.vtOnly;
    else if (tfScore !== null) weights = THREE_SOURCE_WEIGHTS.feedOnly;
    else weights = THREE_SOURCE_WEIGHTS.neither;

    finalScore = (teScore / 100) * weights.te
      + ((vtScore ?? 0) / 100) * weights.vt
      + ((tfScore ?? 0) / 100) * weights.feed;
  }

  finalScore = Math.round(clamp(finalScore, 0, 100));
  const riskLevel = levelFromScore(finalScore);
  const verdict = verdictFromLevel(riskLevel);

  
  const allFindings = [...findings];
  if (virusTotalResult?.available && virusTotalResult.status === 'completed') {
    if (virusTotalResult.malicious > 0) {
      allFindings.unshift({
        severity: 'critical',
        category: 'reputation',
        message: `${virusTotalResult.malicious} of ${virusTotalResult.totalEngines} security engines flagged this URL as malicious.`,
      });
    } else if (virusTotalResult.suspicious > 0) {
      allFindings.unshift({
        severity: 'medium',
        category: 'reputation',
        message: `${virusTotalResult.suspicious} of ${virusTotalResult.totalEngines} security engines flagged this URL as suspicious.`,
      });
    }
  } else if (virusTotalResult && virusTotalResult.available === false) {
    allFindings.push({
      severity: 'info',
      category: 'reputation',
      message: `VirusTotal reputation data unavailable (${virusTotalResult.status}).`,
    });
  }

  
  if (threatFeedResult?.available && threatFeedResult.status === 'completed') {
    if (threatFeedResult.isMalicious) {
      allFindings.unshift({
        severity: 'critical',
        category: 'threat-feed',
        message: `Threat feed flagged this URL${threatFeedResult.threatType ? ` as ${threatFeedResult.threatType}` : ''}.`,
      });
    }
  } else if (threatFeedResult && threatFeedResult.available === false) {
    allFindings.push({
      severity: 'info',
      category: 'threat-feed',
      message: `Threat Feed reputation data unavailable (${threatFeedResult.status}).`,
    });
  }

  const recommendations = buildRecommendations(riskLevel, allFindings, virusTotalResult, threatFeedResult);

  return {
    riskScore: finalScore,
    riskLevel,
    verdict,
    findings: allFindings,
    recommendations,
  };
}

function buildFileRecommendations(level, findings, vt) {
  const recs = [];

  if (level === 'CRITICAL' || level === 'HIGH') {
    recs.push('Do not open, run, or extract this file.');
    recs.push('Delete this file immediately from your system.');
    recs.push('Report this file to your IT/security team if you received it through a work channel.');
  } else if (level === 'MEDIUM') {
    recs.push('Proceed with caution. Do not run this file unless you absolutely trust the source.');
    recs.push('Scan this file locally using an up-to-date antivirus software before opening.');
  } else {
    recs.push('No threats detected by VirusTotal, but always exercise caution when opening unknown files.');
  }

  if (vt && vt.available === false) {
    recs.push('VirusTotal reputation data was unavailable for this scan.');
  }

  return recs;
}

/**
 * Computes risk metrics (score, level, verdict, findings, recommendations)
 * specifically for a file scan using its VirusTotal reputation result.
 * Since there is no local static threat engine for binaries, VirusTotal has 100% weight.
 * @param {Object} virusTotalResult - output of virusTotalService.scanFileWithVirusTotal
 */
function computeFileRisk(virusTotalResult) {
  const vtScore = scoreFromVirusTotal(virusTotalResult);

  let finalScore;
  if (vtScore === null) {
    // VirusTotal unusable - we don't have local file analysis so we report 0 score with info status.
    finalScore = 0;
  } else {
    finalScore = vtScore;
  }

  finalScore = Math.round(clamp(finalScore, 0, 100));
  const riskLevel = levelFromScore(finalScore);
  const verdict = verdictFromLevel(riskLevel);

  const findings = [];
  if (virusTotalResult?.available && virusTotalResult.status === 'completed') {
    if (virusTotalResult.malicious > 0) {
      findings.push({
        severity: 'critical',
        category: 'reputation',
        message: `${virusTotalResult.malicious} of ${virusTotalResult.totalEngines} security engines flagged this file as malicious.`,
      });
    } else if (virusTotalResult.suspicious > 0) {
      findings.push({
        severity: 'medium',
        category: 'reputation',
        message: `${virusTotalResult.suspicious} of ${virusTotalResult.totalEngines} security engines flagged this file as suspicious.`,
      });
    }
  } else if (virusTotalResult && virusTotalResult.available === false) {
    findings.push({
      severity: 'info',
      category: 'reputation',
      message: `VirusTotal reputation data unavailable (${virusTotalResult.status}).`,
    });
  }

  const recommendations = buildFileRecommendations(riskLevel, findings, virusTotalResult);

  return {
    riskScore: finalScore,
    riskLevel,
    verdict,
    findings,
    recommendations,
  };
}

module.exports = {
  computeRisk,
  computeFileRisk,
  scoreFromVirusTotal,
  scoreFromThreatFeed,
  levelFromScore,
  verdictFromLevel,
};
