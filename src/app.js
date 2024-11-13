const express = require('express');
const helmet = require('helmet');

const app = express();
const port = process.env.PORT || 3000;

// Security middleware
app.use(helmet());

// Rate limiting
const rateLimit = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_REQUESTS = 100;

app.use((req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!rateLimit.has(ip)) {
        rateLimit.set(ip, {
            count: 1,
            resetTime: now + WINDOW_MS
        });
        return next();
    }

    const client = rateLimit.get(ip);
    if (now > client.resetTime) {
        client.count = 1;
        client.resetTime = now + WINDOW_MS;
        return next();
    }

    client.count++;
    if (client.count > MAX_REQUESTS) {
        return res.status(429).json({ error: 'Too many requests' });
    }

    next();
});

// Routes
app.get('/', (req, res) => {
    res.set({
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY'
    });
    res.send('DevSecOps Portfolio Demo');
});

module.exports = app;