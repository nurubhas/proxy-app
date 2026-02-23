const express = require('express');
const session = require('express-session');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const PORT = process.env.PORT || 8080;
const BACKEND_URL = process.env.BACKEND_URL;
const BACKEND_PROBE_PATH = process.env.BACKEND_PROBE_PATH;
const AUTH_USER = process.env.AUTH_USER;
const AUTH_PASS = process.env.AUTH_PASS;

const MAINTENANCE_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Service Unavailable</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)), url('/auth/bg.jpg') no-repeat center center fixed; background-size: cover; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .container { background-color: #ffffff; padding: 50px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); max-width: 500px; text-align: center; border-top: 6px solid #dc3545; }
    h1 { font-size: 32px; color: #dc3545; margin-top: 0; margin-bottom: 15px; }
    p { font-size: 16px; line-height: 1.6; color: #555; margin-bottom: 0; }
    .icon { margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">
      <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#dc3545" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
    </div>
    <h1>503 - Service Unavailable</h1>
    <p>The backend service is temporarily unavailable.</p>
    <p>Please contact the Cloud Platform Team for assistance.</p>
  </div>
</body>
</html>`;

if (!BACKEND_URL) {
  console.error('Missing BACKEND_URL environment variable');
  process.exit(1);
}

if (!AUTH_USER || !AUTH_PASS) {
  console.error('Missing AUTH_USER and/or AUTH_PASS environment variables');
  process.exit(1);
}

const app = express();

// Trust the first proxy (Ingress/Load Balancer) to get correct protocol/IP
app.set('trust proxy', 1);

// Session middleware (simple, not for production secrets)
app.use(session({
  secret: process.env.SESSION_SECRET || 'proxy-secret-key',
  resave: false,
  saveUninitialized: true,
  rolling: true, // Reset maxAge on every response (keep session alive if active)
  cookie: { maxAge: 7200000 } // 2 hours
}));

app.use(express.urlencoded({ extended: false }));

// Logging middleware
app.use((req, res, next) => {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const user = req.session && req.session.authenticated ? AUTH_USER : 'Guest';
  const logEntry = {
    timestamp: new Date().toISOString(),
    host: clientIp,
    user: user,
    method: req.method,
    url: req.url
  };
  console.log(JSON.stringify(logEntry));
  next();
});

// Endpoint to extend session (called by client-side script)
app.get('/keep-alive', (req, res) => {
  res.sendStatus(200);
});

// Health endpoint for Kubernetes liveness
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Readiness probe: check backend reachable
const http = require('http');
const https = require('https');
const { URL } = require('url');

function checkBackend() {
  return new Promise((resolve) => {
    try {
      const url = new URL(BACKEND_URL);
      if (BACKEND_PROBE_PATH) {
        url.pathname = BACKEND_PROBE_PATH;
      }
      const lib = url.protocol === 'https:' ? https : http;
      const req = lib.request(url, { method: 'GET', timeout: 3000 }, (resp) => {
        resolve(resp.statusCode >= 200 && resp.statusCode < 400);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    } catch (e) {
      resolve(false);
    }
  });
}

app.get('/ready', async (req, res) => {
  const ok = await checkBackend();
  if (ok) return res.json({ ready: true });
  return res.status(503).json({ ready: false });
});

// Background health check to toggle maintenance mode
let isBackendUp = true;
// Initial check
checkBackend().then(up => isBackendUp = up);
setInterval(async () => {
  isBackendUp = await checkBackend();
}, 5000); // Check every 5 seconds

// Serve auth static assets under /auth to avoid clashing with backend paths
app.use('/auth', express.static(path.join(__dirname, 'public')));

// Login page
app.get('/login', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Handle login form submission
app.post('/login', (req, res) => {
  let username, password;

  // 1. Check Authorization header (Payload-free method)
  if (req.headers.authorization && req.headers.authorization.startsWith('Basic ')) {
    const b64 = req.headers.authorization.split(' ')[1];
    try {
      const decoded = Buffer.from(b64, 'base64').toString('utf-8');
      const idx = decoded.indexOf(':');
      if (idx !== -1) {
        username = decoded.substring(0, idx);
        password = decoded.substring(idx + 1);
      }
    } catch (e) {}
  } 
  // 2. Fallback to body (legacy support)
  else {
    const body = req.body || {};
    username = body.username;
    password = body.password;
    try {
      if (username) username = Buffer.from(username, 'base64').toString('utf-8');
      if (password) password = Buffer.from(password, 'base64').toString('utf-8');
    } catch (e) {}
  }

  if (username === AUTH_USER && password === AUTH_PASS) {
    req.session.authenticated = true;
    // If AJAX request, return JSON success
    if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
      return res.json({ success: true });
    }
    return res.redirect('/');
  }
  
  // Auth failed
  if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
    return res.status(401).json({ success: false });
  }
  // On invalid credentials, redirect back with error flag so login page can show message
  return res.redirect('/login?error=1');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.authenticated = false;
  res.redirect('/login');
});

// Allow auth static assets and login without session
const publicWhitelist = ['/login', '/auth/style.css', '/auth/bg.jpg', '/auth/script.js', '/favicon.ico'];

// Authentication middleware
app.use((req, res, next) => {
  // Allow whitelisted public paths
  if (publicWhitelist.includes(req.path) || req.path.startsWith('/auth/') || req.path.startsWith('/assets/')) {
    return next();
  }
  // If authenticated, proceed to the proxy
  if (req.session.authenticated) {
    return next();
  }
  // For unauthenticated users, redirect to login irrespective of the path
  return res.redirect('/login');
});

// Profile page
app.get('/profile', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>User Profile</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)), url('/auth/bg.jpg') no-repeat center center fixed; background-size: cover; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .container { background-color: #ffffff; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        h1 { margin-top: 0; color: #333; }
        .avatar { font-size: 64px; margin-bottom: 10px; }
        .info { text-align: left; background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .info p { margin: 5px 0; color: #555; }
        .btn { display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 5px; }
        .btn:hover { background-color: #0056b3; }
        .btn-logout { background-color: #dc3545; }
        .btn-logout:hover { background-color: #c82333; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="avatar">👤</div>
        <h1>${AUTH_USER}</h1>
        <div class="info">
          <p><strong>Username:</strong> ${AUTH_USER}</p>
          <p><strong>Role:</strong> Administrator</p>
        </div>
        <a href="/" class="btn">Back to Home</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      </div>
    </body>
    </html>
  `);
});

// Check backend health before proxying
app.use((req, res, next) => {
  if (!isBackendUp) {
    res.writeHead(503, { 'Content-Type': 'text/html' });
    return res.end(MAINTENANCE_HTML);
  }
  next();
});

// Proxy everything else to BACKEND_URL
app.use('/', createProxyMiddleware({
  target: BACKEND_URL,
  changeOrigin: true,
  secure: false,
  selfHandleResponse: true, // Let us handle the response so we can modify it
  pathRewrite: (path) => path,
  onProxyReq(proxyReq) {
    proxyReq.removeHeader('origin');
    proxyReq.removeHeader('referer');
  },
  onError(err, req, res) {
    res.writeHead(503, {
      'Content-Type': 'text/html',
    });
    res.end(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Service Unavailable</title>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)), url('/auth/bg.jpg') no-repeat center center fixed; background-size: cover; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
          .container { background-color: #ffffff; padding: 50px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); max-width: 500px; text-align: center; border-top: 6px solid #dc3545; }
          h1 { font-size: 32px; color: #dc3545; margin-top: 0; margin-bottom: 15px; }
          p { font-size: 16px; line-height: 1.6; color: #555; margin-bottom: 0; }
          .icon { margin-bottom: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#dc3545" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
          </div>
          <h1>503 - Service Unavailable</h1>
          <p>The backend service is temporarily unavailable.</p>
          <p>Please contact the Cloud Platform Team for assistance.</p>
        </div>
      </body>
      </html>
    `);
    res.end(MAINTENANCE_HTML);
  },
  onProxyRes(proxyRes, req, res) {
    // Handle redirects (Location header)
    if (proxyRes.headers && proxyRes.headers.location) {
      try {
        const url = new URL(proxyRes.headers.location);
        url.host = req.headers.host;
        url.protocol = req.protocol + ':';
        proxyRes.headers.location = url.toString();
      } catch (e) {}
    }

    const isHtml = (proxyRes.headers['content-type'] || '').includes('text/html');

    // If the backend response is HTML, we want to inject our logout button
    if (isHtml) {
      let body = Buffer.from([]);
      proxyRes.on('data', (chunk) => {
        body = Buffer.concat([body, chunk]);
      });
      proxyRes.on('end', () => {
        let html = body.toString('utf8');
        const logoutDiv = `
<!-- Injected by proxy -->
<style>
  #proxy-user-menu {
    position: fixed; top: 10px; right: 10px; z-index: 99999; font-family: sans-serif; font-size: 14px;
  }
  .proxy-user-btn {
    background-color: #f8f9fa; /* Light grey background */
    color: #212529; /* Dark text for visibility */
    border: 1px solid #dee2e6;
    padding: 8px 12px; border-radius: 4px;
    cursor: pointer; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 8px;
  }
  .proxy-user-btn:hover { background: #f0f0f0; }
  .proxy-dropdown-content {
    display: none; position: absolute; right: 0; top: 100%; background-color: #fff;
    min-width: 140px; box-shadow: 0 8px 16px rgba(0,0,0,0.2); z-index: 1; border-radius: 4px;
    border: 1px solid #ddd; margin-top: 4px;
  }
  /* Bridge the gap so mouse doesn't leave hover area */
  .proxy-dropdown-content::before {
    content: "";
    position: absolute;
    top: -10px;
    left: 0;
    width: 100%;
    height: 10px;
  }
  #proxy-user-menu:hover .proxy-dropdown-content { display: block; }
  .proxy-dropdown-content a {
    color: #333; padding: 10px 12px; text-decoration: none; display: block;
  }
  .proxy-dropdown-content a:hover { background-color: #f1f1f1; }

  /* Session Warning Modal */
  #session-modal {
    display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%;
    background-color: rgba(0,0,0,0.5); align-items: center; justify-content: center;
  }
  .session-modal-content {
    background-color: #fff; width: 350px; border-radius: 8px; text-align: center;
    font-family: sans-serif; box-shadow: 0 5px 15px rgba(0,0,0,0.3); overflow: hidden; padding: 0;
  }
  .session-modal-header {
    background-color: #f0ad4e; /* Warning Yellow */
    color: white;
    padding: 15px;
    font-size: 18px;
  }
  .session-modal-body {
    padding: 20px;
    color: #333; /* Dark grey text */
  }
  .session-progress-container {
    width: 100%; background-color: #ddd; height: 10px; margin: 15px 0; border-radius: 5px; overflow: hidden;
  }
  #session-progress-bar {
    width: 100%; height: 100%; background-color: #4CAF50; transition: width 1s linear;
  }
  .session-btn {
    padding: 8px 16px; margin: 0 5px; cursor: pointer; border: none; border-radius: 4px; font-size: 14px;
  }
  .session-btn:hover {
    opacity: 0.9;
  }
  .btn-continue { background-color: #4CAF50; color: white; }
  .btn-logout { background-color: #f44336; color: white; }
</style>

<div id="proxy-user-menu">
  <div class="proxy-user-btn">
    <span id="statusbar-countdown" style="display:none; color: #d9534f; font-weight: bold; margin-right: 8px;"></span>
    <span>👤 ${AUTH_USER}</span>
    <span style="font-size: 10px;">▼</span>
  </div>
  <div class="proxy-dropdown-content">
    <a href="/profile">Profile</a>
    <a href="/logout">Logout</a>
  </div>
</div>

<div id="session-modal">
  <div class="session-modal-content">
    <div class="session-modal-header">
      <h3>&#9200; Session Timeout</h3>
    </div>
    <div class="session-modal-body">
      <p>Your session is about to terminate.</p>
      <p>Time remaining: <strong id="session-countdown">30</strong> seconds.</p>
      <div class="session-progress-container">
        <div id="session-progress-bar"></div>
      </div>
      <button class="session-btn btn-continue" onclick="extendSession()">Continue Session</button>
      <button class="session-btn btn-logout" onclick="location.href='/logout'">Logout</button>
    </div>
  </div>
</div>

<script>
  (function() {
    var idleTime = 60 * 60 * 1000; // 60 minutes
    var warningTime = 5 * 60; // 5 minutes countdown
    var idleTimer, countdownInterval;

    function startIdleTimer() {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(showWarning, idleTime);
    }

    function showWarning() {
      var modal = document.getElementById('session-modal');
      var bar = document.getElementById('session-progress-bar');
      var countSpan = document.getElementById('session-countdown');
      var statusSpan = document.getElementById('statusbar-countdown');
      var remaining = warningTime;
      
      modal.style.display = 'flex';
      if (statusSpan) {
        statusSpan.style.display = 'inline';
        statusSpan.innerText = remaining;
      }
      bar.style.width = '100%';
      bar.style.backgroundColor = '#4CAF50';
      countSpan.innerText = remaining;

      countdownInterval = setInterval(function() {
        remaining--;
        countSpan.innerText = remaining;
        if (statusSpan) statusSpan.innerText = remaining;
        bar.style.width = (remaining / warningTime * 100) + '%';
        
        if (remaining < 10) bar.style.backgroundColor = '#f44336'; // Red when low

        if (remaining <= 0) {
          clearInterval(countdownInterval);
          window.location.href = '/logout';
        }
      }, 1000);
    }

    window.extendSession = function() {
      clearInterval(countdownInterval);
      document.getElementById('session-modal').style.display = 'none';
      var statusSpan = document.getElementById('statusbar-countdown');
      if (statusSpan) statusSpan.style.display = 'none';
      fetch('/keep-alive'); // Ping server to extend cookie
      startIdleTimer(); // Restart 3 min timer
    };

    // Reset idle timer on user activity (if modal is not showing)
    function resetIdle() {
      if (document.getElementById('session-modal').style.display === 'none') {
        startIdleTimer();
      }
    }
    document.onmousemove = resetIdle;
    document.onkeypress = resetIdle;
    document.onclick = resetIdle;

    startIdleTimer(); // Start on load
  })();
</script>
<!-- End of proxy injection -->`;

        // Inject the logout button right before the closing body tag
        html = html.replace('</body>', `${logoutDiv}</body>`);

        delete proxyRes.headers['content-length'];

        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        res.end(html);
      });
    } else {
      // For all other content types (JS, CSS, images), just stream them back.
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  }
}));

app.listen(PORT, () => {
  console.log(`Proxy running on port ${PORT} -> ${BACKEND_URL}`);
});
