'use strict';

const { validateAndAnalyzeUrl } = require('../services/urlAnalysisService');
const { runThreatEngine } = require('../services/threatEngine');
const { scanUrlWithVirusTotal, scanFileWithVirusTotal, isConfigured: vtConfigured } = require('../services/virusTotalService');
const { scanUrlWithThreatFeed, isConfigured: threatFeedConfigured } = require('../services/threatFeedService');
const { lookupWhois, isConfigured: whoisConfigured } = require('../services/whoisService');
const { computeRisk, computeFileRisk } = require('../services/riskEngine');
const { generateScanId, log } = require('../utils/helpers');


async function scanUrl(req, res, next) {
  const scanId = generateScanId();
  const rawUrl = req.body?.url;

  try {
    log('info', 'scan.started', { scanId });

    // Step 1 + 2a: validation, SSRF protection, and static analysis all
    // happen inside validateAndAnalyzeUrl (throws on any block/invalid input).
    const analysis = await validateAndAnalyzeUrl(rawUrl);

    
    const [threatEngineSettled, virusTotalSettled, threatFeedSettled, whoisSettled] = await Promise.allSettled([
      Promise.resolve(runThreatEngine(analysis.findings, analysis.features)),
      scanUrlWithVirusTotal(analysis.normalizedUrl, { scanId }),
      scanUrlWithThreatFeed(analysis.normalizedUrl, { scanId }),
      lookupWhois(analysis.hostname, { scanId }),
    ]);

    const threatEngineResult = threatEngineSettled.status === 'fulfilled'
      ? threatEngineSettled.value
      : { engine: 'local-threat-engine', score: 0, classification: 'unknown', signalsDetected: 0, categoryCounts: {}, error: 'Threat engine failed to execute.' };

    const virusTotalResult = virusTotalSettled.status === 'fulfilled'
      ? virusTotalSettled.value
      : { available: false, status: 'error', message: 'VirusTotal lookup failed unexpectedly.' };

    const threatFeedResult = threatFeedSettled.status === 'fulfilled'
      ? threatFeedSettled.value
      : { available: false, status: 'error', message: 'Threat Feed lookup failed unexpectedly.' };

    const whoisResult = whoisSettled.status === 'fulfilled'
      ? whoisSettled.value
      : { available: false, status: 'error', message: 'WHOIS lookup failed unexpectedly.' };

    if (virusTotalSettled.status === 'rejected') {
      log('error', 'scan.virustotal_error', { scanId, message: virusTotalSettled.reason?.message });
    }

    if (threatFeedSettled.status === 'rejected') {
      log('error', 'scan.threatfeed_error', { scanId, message: threatFeedSettled.reason?.message });
    }

    if (whoisSettled.status === 'rejected') {
      log('error', 'scan.whois_error', { scanId, message: whoisSettled.reason?.message });
    }

   
    const risk = computeRisk(threatEngineResult, virusTotalResult, analysis.findings, threatFeedResult);

    const responseData = {
      scanId,
      userId: req.user?.id || null,
      url: rawUrl,
      normalizedUrl: analysis.normalizedUrl,
      scannedAt: new Date().toISOString(),
      riskScore: risk.riskScore,
      riskLevel: risk.riskLevel,
      verdict: risk.verdict,
      findings: risk.findings,
      threatEngine: threatEngineResult,
      virusTotal: virusTotalResult,
      threatFeed: threatFeedResult,
      whois: whoisResult,
      urlAnalysis: {
        hostname: analysis.hostname,
        hostType: analysis.hostType,
        usesHttps: analysis.features.usesHttps,
        port: analysis.features.port,
        pathDepth: analysis.features.pathDepth,
        queryParamCount: analysis.features.queryParamCount,
        isShortener: analysis.features.isShortener,
        suspiciousTld: analysis.features.suspiciousTld,
        suspiciousKeywords: analysis.features.suspiciousKeywordMatches,
      },
      recommendations: risk.recommendations,
    };

    log('info', 'scan.completed', { scanId, riskLevel: risk.riskLevel, riskScore: risk.riskScore });

    return res.status(200).json({ success: true, data: responseData });
  } catch (err) {
    log('error', 'scan.failed', { scanId, message: err.message });
    return next(err);
  }
}


async function scanFile(req, res, next) {
  const scanId = generateScanId();
  const file = req.file;

  if (!file) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_FILE',
        message: 'A "file" is required in the request body.',
      },
    });
  }

  try {
    log('info', 'scan.file_started', { scanId, filename: file.originalname });

    const virusTotalResult = await scanFileWithVirusTotal(file.buffer, file.originalname, { scanId });

    if (virusTotalResult.status === 'rejected') {
      log('error', 'scan.virustotal_error', { scanId, message: virusTotalResult.reason?.message });
    }

    const risk = computeFileRisk(virusTotalResult);

    const responseData = {
      scanId,
      userId: req.user?.id || null,
      filename: file.originalname,
      scannedAt: new Date().toISOString(),
      riskScore: risk.riskScore,
      riskLevel: risk.riskLevel,
      verdict: risk.verdict,
      findings: risk.findings,
      virusTotal: virusTotalResult,
      recommendations: risk.recommendations,
    };

    log('info', 'scan.file_completed', { scanId, riskLevel: risk.riskLevel, riskScore: risk.riskScore });

    return res.status(200).json({ success: true, data: responseData });
  } catch (err) {
    log('error', 'scan.file_failed', { scanId, message: err.message });
    return next(err);
  }
}

function healthCheck(req, res) {
  res.status(200).json({
    success: true,
    status: 'ok',
    service: 'link-scanner-backend',
    virusTotalConfigured: vtConfigured(),
    threatFeedConfigured: threatFeedConfigured(),
    whoisConfigured: whoisConfigured(),
    timestamp: new Date().toISOString(),
  });
}

module.exports = { scanUrl, scanFile, healthCheck };
