'use strict';



const axios = require('axios');
const { log } = require('../utils/helpers');

const WHOIS_BASE_URL =
  process.env.WHOIS_BASE_URL || 'https://www.whoisxmlapi.com/whoisserver/WhoisService';

function isConfigured() {
  return Boolean(
    process.env.WHOIS_API_KEY &&
    process.env.WHOIS_API_KEY.trim().length > 0
  );
}

function getTimeoutMs() {
  const parsed = Number(process.env.REQUEST_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 15000;
}

function client() {
  return axios.create({
    timeout: getTimeoutMs(),
    headers: {
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


function normalizeWhoisResponse(data = {}) {
  const record = data.WhoisRecord || data;

  if (!record || Object.keys(record).length === 0) {
    return {
      available: true,
      status: 'no_data',
      message: 'No WHOIS data found for this domain.',
      domainName: null,
      registrar: null,
      createdDate: null,
      expiresDate: null,
      updatedDate: null,
      domainStatus: null,
      nameServers: null,
      registrant: null,
      administrativeContact: null,
      technicalContact: null,
    };
  }

  const registryData = record.registryData || {};

  const domainName = record.domainName || registryData.domainName || null;
  const registrar = record.registrarName || registryData.registrarName || record.registrar || null;
  const createdDate = record.createdDate || registryData.createdDate || record.creationDate || null;
  const expiresDate = record.expiresDate || registryData.expiresDate || record.registryExpireDate || null;
  const updatedDate = record.updatedDate || registryData.updatedDate || null;

  let domainStatus = record.domainStatus || registryData.domainStatus || null;
  if (typeof domainStatus === 'string') {
    domainStatus = [domainStatus];
  }

  let nameServers =
    record.nameServers?.hostNames ||
    registryData.nameServers?.hostNames ||
    record.nameServers ||
    null;

  const registrant = record.registrant || registryData.registrant || null;
  const administrativeContact =
    record.administrativeContact || registryData.administrativeContact || null;
  const technicalContact =
    record.technicalContact || registryData.technicalContact || null;

  return {
    available: true,
    status: 'completed',
    domainName,
    registrar,
    createdDate,
    expiresDate,
    updatedDate,
    domainStatus,
    nameServers,
    registrant,
    administrativeContact,
    technicalContact,
  };
}


async function lookupWhois(domainName, { scanId } = {}) {
  if (!isConfigured()) {
    log('info', 'whois.unconfigured', { scanId });
    return unavailableResult(
      'not_configured',
      'WhoisXML API key is not configured on the server.'
    );
  }

  const http = client();

  try {
    const response = await http.get(WHOIS_BASE_URL, {
      params: {
        apiKey: process.env.WHOIS_API_KEY,
        domainName,
        outputFormat: 'JSON',
      },
    });

    return normalizeWhoisResponse(response.data);
  } catch (err) {
    return handleWhoisError(err, scanId);
  }
}

function handleWhoisError(err, scanId) {
  if (err.code === 'ECONNABORTED') {
    log('error', 'whois.timeout', { scanId });
    return unavailableResult('timeout', 'WhoisXML request timed out.');
  }

  if (err.response) {
    const { status } = err.response;

    if (status === 401 || status === 403) {
      log('error', 'whois.auth_error', { scanId, status });
      return unavailableResult(
        'auth_error',
        'WhoisXML API key is invalid or unauthorized.'
      );
    }

    if (status === 429) {
      log('error', 'whois.rate_limited', { scanId });
      return unavailableResult(
        'rate_limited',
        'WhoisXML rate limit or quota exceeded.'
      );
    }

    log('error', 'whois.api_error', {
      scanId,
      status,
      response: err.response.data,
    });

    return unavailableResult(
      'api_error',
      `WhoisXML returned an error (HTTP ${status}).`
    );
  }

  if (err.request) {
    log('error', 'whois.network_error', { scanId, message: err.message });
    return unavailableResult(
      'network_error',
      'Could not reach WhoisXML API.'
    );
  }

  log('error', 'whois.unknown_error', { scanId, message: err.message });
  return unavailableResult(
    'error',
    'An unexpected error occurred while contacting WhoisXML.'
  );
}

module.exports = {
  isConfigured,
  lookupWhois,
  normalizeWhoisResponse,
};
