'use strict';

const request = require('supertest');
const createApp = require('../src/app');

describe('Contact Form API', () => {
  let app;

  beforeEach(() => {
    app = createApp();
  });

  test('POST /api/contact with valid data returns success', async () => {
    const response = await request(app)
      .post('/api/contact')
      .send({
        name: 'John Doe',
        email: 'john@example.com',
        message: 'Hello, I have a question about your link scanner.',
      });

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.message).toContain('Thank you for your message');
  });

  test('POST /api/contact with missing name returns 400', async () => {
    const response = await request(app)
      .post('/api/contact')
      .send({
        email: 'john@example.com',
        message: 'Hello!',
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('MISSING_NAME');
  });

  test('POST /api/contact with invalid email returns 400', async () => {
    const response = await request(app)
      .post('/api/contact')
      .send({
        name: 'John Doe',
        email: 'not-an-email',
        message: 'Hello!',
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('INVALID_EMAIL');
  });

  test('POST /api/contact with missing message returns 400', async () => {
    const response = await request(app)
      .post('/api/contact')
      .send({
        name: 'John Doe',
        email: 'john@example.com',
        message: '',
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('MISSING_MESSAGE');
  });
});
