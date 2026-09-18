'use strict';

jest.mock('axios');
const axios = require('axios');
const { isConfigured, scanUrlWithThreatFeed } = require('../src/services/threatFeedService');

describe('threatFeedService', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    process.env = { ...ORIGINAL_ENV };
    jest.clearAllMocks();
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  describe('isConfigured', () => {
    test('returns false when THREAT_FEED_API_KEY is not set', () => {
      delete process.env.THREAT_FEED_API_KEY;
      expect(isConfigured()).toBe(false);
    });

    test('returns false when THREAT_FEED_API_KEY is blank', () => {
      process.env.THREAT_FEED_API_KEY = '   ';
      expect(isConfigured()).toBe(false);
    });

    test('returns true when THREAT_FEED_API_KEY is set', () => {
      process.env.THREAT_FEED_API_KEY = 'test-key-123';
      expect(isConfigured()).toBe(true);
    });
  });

  describe('scanUrlWithThreatFeed', () => {
    test('returns not_configured result when no API key is present', async () => {
      delete process.env.THREAT_FEED_API_KEY;

      const result = await scanUrlWithThreatFeed('https://example.com', { scanId: 'scan_1' });

      expect(result).toEqual({
        available: false,
        status: 'not_configured',
        message: expect.any(String),
      });
      expect(axios.create).not.toHaveBeenCalled();
    });

    test('normalizes a malicious detection', async () => {
      process.env.THREAT_FEED_API_KEY = 'test-key-123';
      const mockPost = jest.fn().mockResolvedValue({
        data: { query_status: 'ok', id: '123', threat: 'malware_download', url_status: 'online', host: 'evil.example.com' },
      });
      axios.create.mockReturnValue({ post: mockPost });

      const result = await scanUrlWithThreatFeed('https://evil.example.com', { scanId: 'scan_2' });

      expect(mockPost).toHaveBeenCalledWith('/v1/url/', 'url=https%3A%2F%2Fevil.example.com');
      expect(result).toEqual({
        available: true,
        status: 'completed',
        isMalicious: true,
        threatType: 'malware_download',
        source: 'URLhaus',
        message: 'URLhaus has this URL listed as malicious.',
        details: {
          urlhausId: '123',
          urlStatus: 'online',
          host: 'evil.example.com',
          dateAdded: undefined,
          lastOnline: undefined,
          tags: [],
          urlhausReference: undefined,
        },
      });
    });

    test('normalizes a clean/safe detection', async () => {
      process.env.THREAT_FEED_API_KEY = 'test-key-123';
      const mockPost = jest.fn().mockResolvedValue({
        data: { query_status: 'no_results' },
      });
      axios.create.mockReturnValue({ post: mockPost });

      const result = await scanUrlWithThreatFeed('https://safe.example.com', { scanId: 'scan_3' });

      expect(result).toEqual({
        available: true,
        status: 'completed',
        isMalicious: false,
        threatType: null,
        source: 'URLhaus',
        message: 'URLhaus has no record of this URL.',
        details: null,
      });
    });

    test('handles a request timeout', async () => {
      process.env.THREAT_FEED_API_KEY = 'test-key-123';
      const timeoutError = Object.assign(new Error('timeout of 15000ms exceeded'), { code: 'ECONNABORTED' });
      const mockPost = jest.fn().mockRejectedValue(timeoutError);
      axios.create.mockReturnValue({ post: mockPost });

      const result = await scanUrlWithThreatFeed('https://slow.example.com', { scanId: 'scan_4' });

      expect(result).toEqual({
        available: false,
        status: 'timeout',
        message: expect.any(String),
      });
    });

    test('handles a 401/403 auth error', async () => {
      process.env.THREAT_FEED_API_KEY = 'bad-key';
      const authError = { response: { status: 401 } };
      const mockPost = jest.fn().mockRejectedValue(authError);
      axios.create.mockReturnValue({ post: mockPost });

      const result = await scanUrlWithThreatFeed('https://example.com', { scanId: 'scan_5' });

      expect(result).toEqual({
        available: false,
        status: 'auth_error',
        message: expect.any(String),
      });
    });

    test('handles a 429 rate-limit error', async () => {
      process.env.THREAT_FEED_API_KEY = 'test-key-123';
      const rateLimitError = { response: { status: 429 } };
      const mockPost = jest.fn().mockRejectedValue(rateLimitError);
      axios.create.mockReturnValue({ post: mockPost });

      const result = await scanUrlWithThreatFeed('https://example.com', { scanId: 'scan_6' });

      expect(result).toEqual({
        available: false,
        status: 'rate_limited',
        message: expect.any(String),
      });
    });

    test('handles a generic network error (no response received)', async () => {
      process.env.THREAT_FEED_API_KEY = 'test-key-123';
      const networkError = { request: {}, message: 'socket hang up' };
      const mockPost = jest.fn().mockRejectedValue(networkError);
      axios.create.mockReturnValue({ post: mockPost });

      const result = await scanUrlWithThreatFeed('https://example.com', { scanId: 'scan_7' });

      expect(result).toEqual({
        available: false,
        status: 'network_error',
        message: expect.any(String),
      });
    });

    test('handles an unexpected/unknown error', async () => {
      process.env.THREAT_FEED_API_KEY = 'test-key-123';
      const unknownError = new Error('something exploded');
      const mockPost = jest.fn().mockRejectedValue(unknownError);
      axios.create.mockReturnValue({ post: mockPost });

      const result = await scanUrlWithThreatFeed('https://example.com', { scanId: 'scan_8' });

      expect(result).toEqual({
        available: false,
        status: 'error',
        message: expect.any(String),
      });
    });
  });
});
