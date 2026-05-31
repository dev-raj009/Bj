#!/usr/bin/env node

/**
 * # APPX V2 SECURE VIDEO PROXY SERVER
 * # Render.com Deployment Ready
 * # 
 * # Ye server AppX v2 ke encrypted videos ko decrypt karta hai aur stream karta hai
 * # XOR decryption (first 28 bytes only) - bilkul aapke original method jaisa
 * # 
 * # Kaise use karein:
 * # 1. Is file ko Render pe Web Service ke roop me deploy karein
 * # 2. Server start hoga to /player pe ek demo player milega
 * # 3. API endpoint: /video?url=ENCODED_URL&key=appx-pdf-keyset
 */

// ==================== LIBRARIES ====================
const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

// ==================== SERVER SETUP ====================
const app = express();
const PORT = process.env.PORT || 3000;  // # Render automatically provides PORT

// # Middlewares
app.use(cors());                         // # Sabhi domains se allow
app.use(helmet({                         // # Security headers
    contentSecurityPolicy: false        // # Video streaming ke liye thoda loose
}));
app.use(morgan('combined'));             // # Logging
app.use(compression());                  // # Response compress
app.use(express.json());                 // # JSON body parser
app.use(express.static('public'));       // # Static files (agar public folder ho)

// # Rate limiting - har IP se 100 requests per 15 minutes
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.'
});
app.use('/video', limiter);
app.use('/pdf', limiter);

// ==================== CONSTANTS ====================
// # Ye headers bahut IMPORTANT hain - inke bina AppX server 403 dega
const REQUIRED_HEADERS = {
    'Referer': 'https://appx-play.akamai.net.in/',
    'Origin': 'https://appx-play.akamai.net.in',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
};

// ==================== CORE DECRYPTION FUNCTION ====================
/**
 * # decryptVideoHeader - First 28 bytes ko XOR se decrypt karta hai
 * # @param {Buffer} buffer - Encrypted bytes ka buffer
 * # @param {string} key - Decryption key (jaise 'appx-pdf-keyset')
 */
function decryptVideoHeader(buffer, key) {
    for (let i = 0; i < 28 && i < buffer.length; i++) {
        const keyByte = (i < key.length) ? key.charCodeAt(i) : i;
        buffer[i] ^= keyByte;
    }
    return buffer;
}

// ==================== HELPER FUNCTIONS ====================
function isValidUrl(string) {
    try { new URL(string); return true; } catch(e) { return false; }
}

function extractKeyFromUrl(url) {
    const match = url.match(/[?&]KeyName=([^&]+)/);
    return match ? match[1] : null;
}

// ==================== VIDEO STREAMING ENDPOINT ====================
/**
 * # GET /video - Main proxy endpoint
 * # Query params: url (encrypted video URL), key (optional if in URL)
 */
app.get('/video', async (req, res) => {
    let videoUrl = req.query.url;
    let key = req.query.key;

    // # Validation
    if (!videoUrl) {
        return res.status(400).json({ error: 'Missing "url" parameter' });
    }

    try {
        videoUrl = decodeURIComponent(videoUrl);
    } catch(e) {
        return res.status(400).json({ error: 'Invalid URL encoding' });
    }

    if (!isValidUrl(videoUrl)) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }

    if (!key) {
        key = extractKeyFromUrl(videoUrl);
        if (!key) {
            return res.status(400).json({ error: 'Missing decryption key' });
        }
    }

    const rangeHeader = req.headers.range || 'bytes=0-';
    const urlObj = new URL(videoUrl);
    const hostname = urlObj.hostname;

    try {
        // # Fetch encrypted video from AppX
        const upstream = await axios({
            method: 'GET',
            url: videoUrl,
            responseType: 'stream',
            headers: {
                ...REQUIRED_HEADERS,
                'Host': hostname,
                'Range': rangeHeader
            },
            validateStatus: () => true,
            timeout: 30000
        });

        // # Handle forbidden/not found
        if (upstream.status === 403) {
            return res.status(403).json({ error: 'Forbidden - URL expired or invalid headers' });
        }
        if (upstream.status === 404) {
            return res.status(404).json({ error: 'Video not found' });
        }

        // # Set response headers
        res.status(upstream.status);
        res.setHeader('Content-Type', 'video/mp4');
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'public, max-age=3600');
        if (upstream.headers['content-range']) {
            res.setHeader('Content-Range', upstream.headers['content-range']);
        }
        if (upstream.headers['content-length']) {
            res.setHeader('Content-Length', upstream.headers['content-length']);
        }

        // # Decryption logic - sirf full request ke liye (bytes=0-)
        const isFullRequest = rangeHeader === 'bytes=0-';
        
        if (!isFullRequest) {
            // # Seek request hai - bina decryption ke pipe karo
            return upstream.data.pipe(res);
        }

        // # Full request - first 28 bytes decrypt karo
        let headerBuffer = Buffer.alloc(0);
        let headerDone = false;

        upstream.data.on('data', (chunk) => {
            if (!headerDone) {
                headerBuffer = Buffer.concat([headerBuffer, chunk]);
                if (headerBuffer.length >= 28) {
                    decryptVideoHeader(headerBuffer, key);
                    res.write(headerBuffer);
                    headerDone = true;
                }
            } else {
                res.write(chunk);
            }
        });

        upstream.data.on('end', () => res.end());
        upstream.data.on('error', (err) => {
            console.error('Stream error:', err.message);
            if (!res.headersSent) res.status(500).end();
            else res.end();
        });

    } catch (error) {
        console.error('Proxy error:', error.message);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
});

// ==================== PDF ENDPOINT ====================
app.get('/pdf', async (req, res) => {
    let pdfUrl = req.query.url;
    let key = req.query.key;

    if (!pdfUrl) return res.status(400).json({ error: 'Missing "url"' });
    try { pdfUrl = decodeURIComponent(pdfUrl); } catch(e) { return res.status(400).json({ error: 'Invalid URL' }); }
    if (!key) key = extractKeyFromUrl(pdfUrl);
    if (!key) return res.status(400).json({ error: 'Missing key' });

    const urlObj = new URL(pdfUrl);
    try {
        const upstream = await axios({
            method: 'GET',
            url: pdfUrl,
            responseType: 'stream',
            headers: { ...REQUIRED_HEADERS, 'Host': urlObj.hostname },
            validateStatus: () => true
        });
        if (upstream.status === 403) return res.status(403).json({ error: 'Forbidden' });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'inline; filename="document.pdf"');
        
        let headerBuffer = Buffer.alloc(0);
        let headerDone = false;
        upstream.data.on('data', chunk => {
            if (!headerDone) {
                headerBuffer = Buffer.concat([headerBuffer, chunk]);
                if (headerBuffer.length >= 28) {
                    decryptVideoHeader(headerBuffer, key);
                    res.write(headerBuffer);
                    headerDone = true;
                }
            } else {
                res.write(chunk);
            }
        });
        upstream.data.on('end', () => res.end());
        upstream.data.on('error', () => res.end());
    } catch(e) {
        res.status(500).json({ error: 'PDF proxy error' });
    }
});

// ==================== DEMO PLAYER (HTML) ====================
app.get('/player', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>AppX Video Player</title><meta name="viewport" content="width=device-width,initial-scale=1">
        <style>body{font-family:sans-serif;background:#0a0a0a;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}.container{max-width:1000px;width:100%;background:#000;border-radius:20px;overflow:hidden}video{width:100%}.controls{padding:20px;background:#111;display:flex;gap:10px;flex-wrap:wrap}button,.quality{background:#333;border:none;color:white;padding:10px 20px;border-radius:30px;cursor:pointer}.quality{background:#2a2a40}input{flex:1;padding:10px;border-radius:30px;border:none;background:#222;color:white}</style>
        </head>
        <body>
        <div class="container">
        <video id="video" controls playsinline></video>
        <div class="controls">
        <input type="text" id="urlInput" placeholder="Enter encrypted video URL here...">
        <button id="loadBtn">Load Video</button>
        <select id="qualitySelect" class="quality"><option>720p</option><option>480p</option><option>360p</option></select>
        <button id="playBtn">Play</button><button id="pauseBtn">Pause</button>
        </div>
        </div>
        <script>
        const video = document.getElementById('video');
        const urlInput = document.getElementById('urlInput');
        const loadBtn = document.getElementById('loadBtn');
        const qualitySelect = document.getElementById('qualitySelect');
        const playBtn = document.getElementById('playBtn');
        const pauseBtn = document.getElementById('pauseBtn');
        const key = 'appx-pdf-keyset';
        const videoUrls = {
            '720p': '${req.protocol}://${req.get('host')}/proxy-placeholder-720p',
            '480p': '${req.protocol}://${req.get('host')}/proxy-placeholder-480p',
            '360p': '${req.protocol}://${req.get('host')}/proxy-placeholder-360p'
        };
        function loadVideo(url) { if(!url) return; const encoded = encodeURIComponent(url); video.src = '/video?url='+encoded+'&key='+key; video.load(); }
        loadBtn.onclick = () => loadVideo(urlInput.value);
        qualitySelect.onchange = () => { if(videoUrls[qualitySelect.value]) loadVideo(videoUrls[qualitySelect.value]); };
        playBtn.onclick = () => video.play();
        pauseBtn.onclick = () => video.pause();
        console.log('Player ready. Use /video?url=...&key=...');
        </script>
        </body>
        </html>
    `);
});

// ==================== HEALTH CHECK ====================
app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// ==================== 404 HANDLER ====================
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found', available: ['/video', '/pdf', '/player', '/health'] });
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ AppX Proxy Server running on port ${PORT}`);
    console.log(`🎥 Player: http://localhost:${PORT}/player`);
    console.log(`💚 Health: http://localhost:${PORT}/health`);
});

module.exports = app;  // # For testing purposes
