const request = require('supertest');
const app = require('../src/app');

describe('Security Headers', () => {
    test('should have security headers', async () => {
        const response = await request(app).get('/');
        expect(response.headers['x-frame-options']).toBe('DENY');
        expect(response.headers['content-security-policy']).toBeDefined();
        expect(response.headers['x-content-type-options']).toBe('nosniff');
    });

    test('should rate limit excessive requests', async () => {
        const requests = Array(105).fill().map(() => request(app).get('/'));
        const responses = await Promise.all(requests);
        expect(responses[103].status).toBe(429); // Should be rate limited
    });
});