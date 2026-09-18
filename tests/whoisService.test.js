'use strict';

jest.mock('axios');
const axios = require('axios');
const { isConfigured, lookupWhois } = require('../src/services/whoisService');

describe('whoisService', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    process.env = { ...ORIGINAL_ENV };
    jest.clearAllMocks();
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  describe('isConfigured', () => {
    test('returns false when WHOIS_API_KEY is not set', () => {
      delete process.env.WHOIS_API_KEY;
      expect(isConfigured()).toBe(false);
    });

    test('returns false when WHOIS_API_KEY is blank', () => {
      process.env.WHOIS_API_KEY = '   ';
      expect(isConfigured()).toBe(false);
    });

    test('returns true when WHOIS_API_KEY is set', () => {
      process.env.WHOIS_API_KEY = 'test-whois-key-123';
      expect(isConfigured()).toBe(true);
    });
  });

  describe('lookupWhois', () => {
    test('returns not_configured result when no API key is present', async () => {
      delete process.env.WHOIS_API_KEY;

      const result = await lookupWhois('example.com', { scanId: 'scan_1' });

      expect(result).toEqual({
        available: false,
        status: 'not_configured',
        message: expect.any(String),
      });
      expect(axios.create).not.toHaveBeenCalled();
    });

    test('normalizes a successful WHOIS response', async () => {
      process.env.WHOIS_API_KEY = 'test-whois-key-123';
      const mockGet = jest.fn().mockResolvedValue({
        data: {
          WhoisRecord: {
            domainName: 'example.com',
            registrarName: 'Example Registrar LLC',
            createdDate: '1995-08-14T04:00:00Z',
            expiresDate: '2028-08-13T04:00:00Z',
            domainStatus: ['clientTransferProhibited'],
            nameServers: { hostNames: ['ns1.example.com', 'ns2.example.com'] },
          },
        },
      });
      axios.create.mockReturnValue({ get: mockGet });

      const result = await lookupWhois('example.com', { scanId: 'scan_2' });

      expect(mockGet).toHaveBeenCalledWith(
        'https://www.whoisxmlapi.com/whoisserver/WhoisService',
        {
          params: {
            apiKey: 'test-whois-key-123',
            domainName: 'example.com',
            outputFormat: 'JSON',
          },
        }
      );
      expect(result).toEqual({
        available: true,
        status: 'completed',
        domainName: 'example.com',
        registrar: 'Example Registrar LLC',
        createdDate: '1995-08-14T04:00:00Z',
        expiresDate: '2028-08-13T04:00:00Z',
        updatedDate: null,
        domainStatus: ['clientTransferProhibited'],
        nameServers: ['ns1.example.com', 'ns2.example.com'],
        registrant: null,
        administrativeContact: null,
        technicalContact: null,
      });
    });

    test('handles a request timeout', async () => {
      process.env.WHOIS_API_KEY = 'test-whois-key-123';
      const timeoutError = Object.assign(new Error('timeout of 15000ms exceeded'), { code: 'ECONNABORTED' });
      const mockGet = jest.fn().mockRejectedValue(timeoutError);
      axios.create.mockReturnValue({ get: mockGet });

      const result = await lookupWhois('example.com', { scanId: 'scan_3' });

      expect(result).toEqual({
        available: false,
        status: 'timeout',
        message: expect.any(String),
      });
    });

    test('handles a 401/403 auth error', async () => {
      process.env.WHOIS_API_KEY = 'bad-key';
      const authError = { response: { status: 401 } };
      const mockGet = jest.fn().mockRejectedValue(authError);
      axios.create.mockReturnValue({ get: mockGet });

      const result = await lookupWhois('example.com', { scanId: 'scan_4' });

      expect(result).toEqual({
        available: false,
        status: 'auth_error',
        message: expect.any(String),
      });
    });

    test('handles a 429 rate-limit error', async () => {
      process.env.WHOIS_API_KEY = 'test-whois-key-123';
      const rateLimitError = { response: { status: 429 } };
      const mockGet = jest.fn().mockRejectedValue(rateLimitError);
      axios.create.mockReturnValue({ get: mockGet });

      const result = await lookupWhois('example.com', { scanId: 'scan_5' });

      expect(result).toEqual({
        available: false,
        status: 'rate_limited',
        message: expect.any(String),
      });
    });

    test('handles a generic network error', async () => {
      process.env.WHOIS_API_KEY = 'test-whois-key-123';
      const networkError = { request: {}, message: 'socket hang up' };
      const mockGet = jest.fn().mockRejectedValue(networkError);
      axios.create.mockReturnValue({ get: mockGet });

      const result = await lookupWhois('example.com', { scanId: 'scan_6' });

      expect(result).toEqual({
        available: false,
        status: 'network_error',
        message: expect.any(String),
      });
    });

    test('handles an unexpected error', async () => {
      process.env.WHOIS_API_KEY = 'test-whois-key-123';
      const unknownError = new Error('unexpected error');
      const mockGet = jest.fn().mockRejectedValue(unknownError);
      axios.create.mockReturnValue({ get: mockGet });

      const result = await lookupWhois('example.com', { scanId: 'scan_7' });

      expect(result).toEqual({
        available: false,
        status: 'error',
        message: expect.any(String),
      });
    });
  });
});
