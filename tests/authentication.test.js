'use strict';

const request = require('supertest');
const createApp = require('../src/app');


jest.mock('../src/services/supabaseClient', () => ({
  getSupabaseClient: jest.fn(() => ({
    auth: {
      getUser: jest.fn(async (token) => {
        if (token === 'valid-token') {
          return {
            data: { user: { id: 'user-123', email: 'test@example.com' } },
            error: null,
          };
        }
        return {
          data: { user: null },
          error: { message: 'Invalid token' },
        };
      }),
    },
  })),
}));

describe('Authentication and Protected Endpoints', () => {
  let app;

  beforeEach(() => {
    app = createApp();
  });

  test('POST /api/scan without token returns 401 Unauthorized', async () => {
    const response = await request(app)
      .post('/api/scan')
      .send({ url: 'https://example.com' });

    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  test('POST /api/scan with invalid token returns 401 Unauthorized', async () => {
    const response = await request(app)
      .post('/api/scan')
      .set('Authorization', 'Bearer invalid-token')
      .send({ url: 'https://example.com' });

    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  test('GET /api/auth/me with valid token returns user info', async () => {
    const response = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer valid-token');

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.user.id).toBe('user-123');
    expect(response.body.user.email).toBe('test@example.com');
  });

  test('POST /api/scan/file without token returns 401 Unauthorized', async () => {
    const response = await request(app)
      .post('/api/scan/file')
      .attach('file', Buffer.from('test file content'), 'test.txt');

    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });
});
