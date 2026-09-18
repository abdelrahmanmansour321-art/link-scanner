'use strict';



const axios = require('axios');
const { log } = require('../utils/helpers');

const THREAT_FEED_BASE_URL =
  process.env.THREAT_FEED_BASE_URL || 'https://urlhaus-api.abuse.ch';

function isConfigured() {
  return Boolean(
    process.env.THREAT_FEED_API_KEY &&
    process.env.THREAT_FEED_API_KEY.trim().length > 0
  );
}

function getTimeoutMs() {
  const parsed = Number(process.env.REQUEST_TIMEOUT_MS);

  return Number.isFinite(parsed) && parsed > 0
    ? parsed
    : 15000;
}

function client() {
  return axios.create({
    baseURL: THREAT_FEED_BASE_URL,
    timeout: getTimeoutMs(),

    headers: {
      'Auth-Key': process.env.THREAT_FEED_API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
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


function normalizeThreatFeedResponse(data = {}) {
  

  if (data.query_status === 'ok') {
    return {
      available: true,
      status: 'completed',
      isMalicious: true,
      threatType: data.threat || 'malware_download',
      source: 'URLhaus',
      message: 'URLhaus has this URL listed as malicious.',
      details: {
        urlhausId: data.id,
        urlStatus: data.url_status,
        host: data.host,
        dateAdded: data.date_added,
        lastOnline: data.last_online,
        tags: data.tags || [],
        urlhausReference: data.urlhaus_reference,
      },
    };
  }

  if (data.query_status === 'no_results') {
    return {
      available: true,
      status: 'completed',
      isMalicious: false,
      threatType: null,
      source: 'URLhaus',
      message: 'URLhaus has no record of this URL.',
      details: null,
    };
  }

  return unavailableResult(
    'api_error',
    data.query_status || 'Unexpected response from URLhaus.'
  );
}


async function scanUrlWithThreatFeed(targetUrl, { scanId } = {}) {
  if (!isConfigured()) {
    log('info', 'threatfeed.unconfigured', { scanId });

    return unavailableResult(
      'not_configured',
      'URLhaus API key is not configured on the server.'
    );
  }

  const http = client();

  try {
    const response = await http.post(
      '/v1/url/',
      new URLSearchParams({
        url: targetUrl,
      }).toString()
    );

    return normalizeThreatFeedResponse(response.data);

  } catch (err) {
    return handleThreatFeedError(err, scanId);
  }
}

function handleThreatFeedError(err, scanId) {
  if (err.code === 'ECONNABORTED') {
    log('error', 'threatfeed.timeout', { scanId });

    return unavailableResult(
      'timeout',
      'URLhaus request timed out.'
    );
  }

  if (err.response) {
    const { status } = err.response;

    if (status === 401 || status === 403) {
      log('error', 'threatfeed.auth_error', {
        scanId,
        status,
      });

      return unavailableResult(
        'auth_error',
        'URLhaus Auth-Key is invalid or unauthorized.'
      );
    }

    if (status === 429) {
      log('error', 'threatfeed.rate_limited', { scanId });

      return unavailableResult(
        'rate_limited',
        'URLhaus rate limit reached.'
      );
    }

    log('error', 'threatfeed.api_error', {
      scanId,
      status,
      response: err.response.data,
    });

    return unavailableResult(
      'api_error',
      `URLhaus returned an error (HTTP ${status}).`
    );
  }

  if (err.request) {
    log('error', 'threatfeed.network_error', {
      scanId,
      message: err.message,
    });

    return unavailableResult(
      'network_error',
      'Could not reach the URLhaus API.'
    );
  }

  log('error', 'threatfeed.unknown_error', {
    scanId,
    message: err.message,
  });

  return unavailableResult(
    'error',
    'An unexpected error occurred while contacting URLhaus.'
  );
}

module.exports = {
  isConfigured,
  scanUrlWithThreatFeed,
  normalizeThreatFeedResponse,
};