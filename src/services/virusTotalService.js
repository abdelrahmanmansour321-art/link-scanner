'use strict';



const axios = require('axios');
const crypto = require('crypto');
const { log } = require('../utils/helpers');

const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

function isConfigured() {
  return Boolean(process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY.trim().length > 0);
}

function getTimeoutMs() {
  const parsed = Number(process.env.REQUEST_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 15000;
}


function vtUrlId(targetUrl) {
  return Buffer.from(targetUrl).toString('base64url').replace(/=+$/, '');
}

function client() {
  return axios.create({
    baseURL: VT_BASE_URL,
    timeout: getTimeoutMs(),
    headers: {
      'x-apikey': process.env.VIRUSTOTAL_API_KEY,
      Accept: 'application/json',
    },
  });
}

function unavailableResult(status, message) {
  return {
    available: false,
    status,
    message,
  };
}

function normalizeAnalysisStats(stats = {}) {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;
  const timeout = stats.timeout ?? 0;
  const totalEngines = malicious + suspicious + harmless + undetected + timeout;

  let verdict = 'Clean';
  if (malicious > 0) verdict = 'Malicious';
  else if (suspicious > 0) verdict = 'Suspicious';
  else if (totalEngines === 0) verdict = 'Unknown';

  return {
    malicious,
    suspicious,
    harmless,
    undetected,
    timeout,
    totalEngines,
    detectionRatio: `${malicious}/${totalEngines}`,
    verdict,
  };
}


async function scanUrlWithVirusTotal(targetUrl, { scanId } = {}) {
  if (!isConfigured()) {
    log('info', 'virustotal.unconfigured', { scanId });
    return unavailableResult('not_configured', 'VirusTotal API key is not configured on the server.');
  }

  const http = client();
  const id = vtUrlId(targetUrl);

  try {
    // 1. Try to fetch an existing report first (fast path, avoids re-submitting).
    const existing = await http.get(`/urls/${id}`).catch((err) => {
      if (err.response && err.response.status === 404) return null;
      throw err;
    });

    let analysisData = existing?.data?.data;

    if (!analysisData) {
      // 2. No existing report - submit the URL for analysis.
      const submission = await http.post('/urls', new URLSearchParams({ url: targetUrl }).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });

      const analysisId = submission.data?.data?.id;
      if (!analysisId) {
        return unavailableResult('error', 'VirusTotal did not return an analysis ID.');
      }

      // 3. Poll briefly for completion (VirusTotal analyses are usually fast
      // for previously-seen or simple URLs, but may remain queued).
      const maxAttempts = 4;
      const delayMs = 2000;
      let analysisResult = null;

      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        // eslint-disable-next-line no-await-in-loop
        const analysisResp = await http.get(`/analyses/${analysisId}`);
        const attrs = analysisResp.data?.data?.attributes;
        if (attrs?.status === 'completed') {
          analysisResult = attrs;
          break;
        }
        if (attempt < maxAttempts - 1) {
          // eslint-disable-next-line no-await-in-loop
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }

      if (!analysisResult) {
        return {
          available: true,
          status: 'pending',
          message: 'VirusTotal analysis is still in progress. Try again shortly.',
        };
      }

      const stats = normalizeAnalysisStats(analysisResult.stats);
      return {
        available: true,
        status: 'completed',
        ...stats,
        analysisId,
        permalink: `https://www.virustotal.com/gui/url/${id}`,
      };
    }

    
    const attrs = analysisData.attributes || {};
    const stats = normalizeAnalysisStats(attrs.last_analysis_stats);
    return {
      available: true,
      status: 'completed',
      ...stats,
      analysisId: analysisData.id,
      permalink: `https://www.virustotal.com/gui/url/${id}`,
    };
  } catch (err) {
    return handleVirusTotalError(err, scanId);
  }
}

function handleVirusTotalError(err, scanId) {
  if (err.code === 'ECONNABORTED') {
    log('error', 'virustotal.timeout', { scanId });
    return unavailableResult('timeout', 'VirusTotal request timed out.');
  }

  if (err.response) {
    const { status } = err.response;
    if (status === 401 || status === 403) {
      log('error', 'virustotal.auth_error', { scanId, status });
      return unavailableResult('auth_error', 'VirusTotal API key is invalid or unauthorized.');
    }
    if (status === 429) {
      log('error', 'virustotal.rate_limited', { scanId });
      return unavailableResult('rate_limited', 'VirusTotal rate limit reached.');
    }
    log('error', 'virustotal.api_error', { scanId, status });
    return unavailableResult('api_error', `VirusTotal returned an error (HTTP ${status}).`);
  }

  if (err.request) {
    log('error', 'virustotal.network_error', { scanId, message: err.message });
    return unavailableResult('network_error', 'Could not reach VirusTotal.');
  }

  log('error', 'virustotal.unknown_error', { scanId, message: err.message });
  return unavailableResult('error', 'An unexpected error occurred while contacting VirusTotal.');
}


async function scanFileWithVirusTotal(fileBuffer, fileName, { scanId } = {}) {
  if (!isConfigured()) {
    log('info', 'virustotal.unconfigured', { scanId });
    return unavailableResult('not_configured', 'VirusTotal API key is not configured on the server.');
  }

  const http = client();
  
  const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  try {
    // 2. Try to fetch an existing report first (fast path, avoids re-submitting).
    const existing = await http.get(`/files/${sha256}`).catch((err) => {
      if (err.response && err.response.status === 404) return null;
      throw err;
    });

    let analysisData = existing?.data?.data;

    if (!analysisData) {
      log('info', 'virustotal.file_not_found_locally', { scanId, sha256 });
      
      // 3. No existing report - submit the file for analysis.
      const formData = new FormData();
      const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
      formData.append('file', blob, fileName || 'file');

      const submission = await http.post('/files', formData);

      const analysisId = submission.data?.data?.id;
      if (!analysisId) {
        return unavailableResult('error', 'VirusTotal did not return an analysis ID.');
      }

      // 4. Poll briefly for completion
      const maxAttempts = 4;
      const delayMs = 2000;
      let analysisResult = null;

      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        // eslint-disable-next-line no-await-in-loop
        const analysisResp = await http.get(`/analyses/${analysisId}`);
        const attrs = analysisResp.data?.data?.attributes;
        if (attrs?.status === 'completed') {
          analysisResult = attrs;
          break;
        }
        if (attempt < maxAttempts - 1) {
          // eslint-disable-next-line no-await-in-loop
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }

      if (!analysisResult) {
        return {
          available: true,
          status: 'pending',
          message: 'VirusTotal file analysis is still in progress. Try again shortly.',
          sha256,
        };
      }

      const stats = normalizeAnalysisStats(analysisResult.stats);
      return {
        available: true,
        status: 'completed',
        ...stats,
        analysisId,
        sha256,
        permalink: `https://www.virustotal.com/gui/file/${sha256}`,
      };
    }

    // We had an existing report.
    const attrs = analysisData.attributes || {};
    const stats = normalizeAnalysisStats(attrs.last_analysis_stats);
    return {
      available: true,
      status: 'completed',
      ...stats,
      analysisId: analysisData.id,
      sha256,
      permalink: `https://www.virustotal.com/gui/file/${sha256}`,
    };
  } catch (err) {
    return handleVirusTotalError(err, scanId);
  }
}

module.exports = {
  isConfigured,
  scanUrlWithVirusTotal,
  scanFileWithVirusTotal,
  vtUrlId,
  normalizeAnalysisStats,
};
