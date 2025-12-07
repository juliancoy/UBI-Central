const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GithubStrategy = require('passport-github2').Strategy;
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-access-secret-change-me';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'dev-refresh-secret-change-me';
const ACCESS_EXPIRES_IN = process.env.ACCESS_EXPIRES_IN || '15m';
const REFRESH_EXPIRES_IN = process.env.REFRESH_EXPIRES_IN || '7d';
const CLIENT_BASE_URL = process.env.CLIENT_BASE_URL || `http://localhost:${PORT}`;
const GOOGLE_ENABLED = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const GITHUB_ENABLED = Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || CLIENT_BASE_URL;
const CPP_BASE_URL = process.env.CPP_BASE_URL || 'http://ubi-backend-cpp:4002';
const CPP_ADMIN_KEY = process.env.CPP_ADMIN_KEY || '';

const dataDir = path.join(__dirname, 'data');
const USERS_PATH = path.join(dataDir, 'users.json');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

if (!fs.existsSync(USERS_PATH)) {
  fs.writeFileSync(USERS_PATH, '[]', 'utf8');
}

function loadUsers() {
  try {
    const raw = fs.readFileSync(USERS_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('Failed to read users file, starting fresh', err);
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2));
}

let users = loadUsers();

function findUserByEmail(email) {
  return users.find((u) => u.email === email.toLowerCase());
}

function sanitizeUser(user) {
  const { passwordHash, refreshTokens, ...rest } = user;
  return rest;
}

function issueTokens(user) {
  const payload = { sub: user.id, email: user.email, name: user.name };
  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES_IN });
  const refreshToken = jwt.sign(
    { sub: user.id, email: user.email, type: 'refresh' },
    REFRESH_SECRET,
    { expiresIn: REFRESH_EXPIRES_IN }
  );
  user.refreshTokens.push(refreshToken);
  saveUsers(users);
  return { accessToken, refreshToken };
}

function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ message: 'Missing access token' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

app.use(
  cors({
    origin: CLIENT_BASE_URL,
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());
app.use(express.static(path.join(__dirname, 'public')));

if (GOOGLE_ENABLED) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL:
          process.env.GOOGLE_CALLBACK_URL || `${SERVER_BASE_URL}/auth/google/callback`,
      },
      (accessToken, refreshToken, profile, done) => {
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        if (!email) {
          return done(new Error('No email returned from Google'));
        }
        let user = findUserByEmail(email.toLowerCase());
        if (!user) {
          user = {
            id: uuid(),
            name: profile.displayName || 'Google User',
            email: email.toLowerCase(),
            provider: 'google',
            passwordHash: null,
            refreshTokens: [],
          };
          users.push(user);
        } else {
          user.name = user.name || profile.displayName;
          user.provider = user.provider || 'google';
        }
        saveUsers(users);
        return done(null, user);
      }
    )
  );

  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

  app.get(
    '/auth/google/callback',
    passport.authenticate('google', {
      session: false,
      failureRedirect: '/?provider=google&status=failure',
    }),
    (req, res) => {
      const { accessToken, refreshToken } = issueTokens(req.user);
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
      });
      res.redirect(
        `http://localhost:8080/?provider=google&accessToken=${encodeURIComponent(
          accessToken
        )}&refreshToken=${encodeURIComponent(refreshToken)}`
      );
    }
  );
} else {
  app.get('/auth/google', (req, res) =>
    res.status(501).json({ message: 'Google Sign-In not configured' })
  );
  app.get('/auth/google/callback', (req, res) =>
    res.status(501).json({ message: 'Google Sign-In not configured' })
  );
}

if (GITHUB_ENABLED) {
  passport.use(
    new GithubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL:
          process.env.GITHUB_CALLBACK_URL || `${SERVER_BASE_URL}/auth/github/callback`,
        scope: ['user:email'],
      },
      (accessToken, refreshToken, profile, done) => {
        const email =
          (profile.emails && profile.emails[0] && profile.emails[0].value) || null;
        if (!email) {
          return done(new Error('No email returned from GitHub'));
        }
        let user = findUserByEmail(email.toLowerCase());
        if (!user) {
          user = {
            id: uuid(),
            name: profile.displayName || profile.username || 'GitHub User',
            email: email.toLowerCase(),
            provider: 'github',
            passwordHash: null,
            refreshTokens: [],
          };
          users.push(user);
        } else {
          user.name = user.name || profile.displayName || profile.username;
          user.provider = user.provider || 'github';
        }
        saveUsers(users);
        return done(null, user);
      }
    )
  );

  app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

  app.get(
    '/auth/github/callback',
    passport.authenticate('github', {
      session: false,
      failureRedirect: '/?provider=github&status=failure',
    }),
    (req, res) => {
      const { accessToken, refreshToken } = issueTokens(req.user);
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
      });
      res.redirect(
        `http://localhost:8080/?provider=github&accessToken=${encodeURIComponent(
          accessToken
        )}&refreshToken=${encodeURIComponent(refreshToken)}`
      );
    }
  );
} else {
  app.get('/auth/github', (req, res) =>
    res.status(501).json({ message: 'GitHub Sign-In not configured' })
  );
  app.get('/auth/github/callback', (req, res) =>
    res.status(501).json({ message: 'GitHub Sign-In not configured' })
  );
}

app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || !name) {
    return res.status(400).json({ message: 'Name, email, and password are required' });
  }
  const normalizedEmail = email.toLowerCase();
  if (findUserByEmail(normalizedEmail)) {
    return res.status(409).json({ message: 'Email already in use' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uuid(),
    name,
    email: normalizedEmail,
    provider: 'local',
    passwordHash,
    refreshTokens: [],
  };
  users.push(user);
  const tokens = issueTokens(user);
  res.status(201).json({ user: sanitizeUser(user), ...tokens });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  const user = findUserByEmail(email.toLowerCase());
  if (!user || user.provider !== 'local') {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const tokens = issueTokens(user);
  res.json({ user: sanitizeUser(user), ...tokens });
});

app.post('/api/auth/refresh', (req, res) => {
  const incomingToken = req.body.refreshToken || req.cookies.refreshToken;
  if (!incomingToken) {
    return res.status(400).json({ message: 'Refresh token required' });
  }
  try {
    const decoded = jwt.verify(incomingToken, REFRESH_SECRET);
    const user = users.find((u) => u.id === decoded.sub);
    if (!user || !user.refreshTokens.includes(incomingToken)) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    user.refreshTokens = user.refreshTokens.filter((t) => t !== incomingToken);
    const tokens = issueTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    });
    res.json({ user: sanitizeUser(user), ...tokens });
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired refresh token' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const incomingToken = req.body.refreshToken || req.cookies.refreshToken;
  if (incomingToken) {
    try {
      const decoded = jwt.verify(incomingToken, REFRESH_SECRET);
      const user = users.find((u) => u.id === decoded.sub);
      if (user) {
        user.refreshTokens = user.refreshTokens.filter((t) => t !== incomingToken);
        saveUsers(users);
      }
    } catch (err) {
      // ignore bad token on logout
    }
  }
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out' });
});

app.get('/api/auth/me', authenticateJWT, (req, res) => {
  const user = users.find((u) => u.id === req.user.sub);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  res.json({ user: sanitizeUser(user) });
});

app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    const headers = CPP_ADMIN_KEY ? { 'x-admin-key': CPP_ADMIN_KEY } : {};
    const response = await fetch(`${CPP_BASE_URL}/admin/users`, { headers });
    if (!response.ok) {
      return res
        .status(502)
        .json({ message: 'Failed to fetch users from C++ backend' });
    }
    const data = await response.json().catch(() => []);
    res.json({ users: data });
  } catch (err) {
    console.error('Admin users fetch failed', err);
    res.status(500).json({ message: 'Unable to reach C++ backend' });
  }
});

async function fetchAdminUserDetail(req, res) {
  const email = req.params.email;
  try {
    const headers = CPP_ADMIN_KEY ? { 'x-admin-key': CPP_ADMIN_KEY } : {};
    const response = await fetch(`${CPP_BASE_URL}/admin/users/${encodeURIComponent(email)}`, {
      headers,
    });
    if (response.status === 404) {
      return res.status(404).json({ message: 'User not found' });
    }
    if (!response.ok) {
      return res
        .status(502)
        .json({ message: 'Failed to fetch user details from C++ backend' });
    }
    const data = await response.json().catch(() => ({}));
    res.json({ user: data });
  } catch (err) {
    console.error('Admin user detail fetch failed', err);
    res.status(500).json({ message: 'Unable to reach C++ backend' });
  }
}

app.get('/api/admin/users/:email', authenticateJWT, fetchAdminUserDetail);
app.get('/api/admin/user/:email', authenticateJWT, fetchAdminUserDetail);

app.post('/api/admin/clear', authenticateJWT, async (req, res) => {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (CPP_ADMIN_KEY) {
      headers['x-admin-key'] = CPP_ADMIN_KEY;
    }
    const response = await fetch(`${CPP_BASE_URL}/admin/clear`, {
      method: 'POST',
      headers,
    });
    if (!response.ok) {
      return res.status(502).json({ message: 'Failed to clear data in C++ backend' });
    }
    const data = await response.json().catch(() => ({}));
    res.json(data);
  } catch (err) {
    console.error('Admin clear failed', err);
    res.status(500).json({ message: 'Unable to reach C++ backend' });
  }
});

app.post('/api/admin/grant', authenticateJWT, async (req, res) => {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (CPP_ADMIN_KEY) {
      headers['x-admin-key'] = CPP_ADMIN_KEY;
    }
    const response = await fetch(`${CPP_BASE_URL}/admin/grant`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ amount: req.body?.amount }),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      return res
        .status(502)
        .json({ message: data.message || 'Failed to grant funds in C++ backend' });
    }
    const data = await response.json().catch(() => ({}));
    res.json(data);
  } catch (err) {
    console.error('Admin grant failed', err);
    res.status(500).json({ message: 'Unable to reach C++ backend' });
  }
});

app.post('/api/transfer', authenticateJWT, async (req, res) => {
  try {
    const headers = {
      'Content-Type': 'application/json',
      Authorization: req.headers.authorization || '',
    };
    const response = await fetch(`${CPP_BASE_URL}/transfer`, {
      method: 'POST',
      headers,
      body: JSON.stringify(req.body || {}),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = data.message || 'Failed to record transfer';
      return res.status(response.status).json({ message });
    }
    res.json(data);
  } catch (err) {
    console.error('Transfer proxy failed', err);
    res.status(500).json({ message: 'Unable to reach C++ backend' });
  }
});

app.get('/api/record', authenticateJWT, async (req, res) => {
  try {
    const headers = {
      Authorization: req.headers.authorization || '',
    };
    const response = await fetch(`${CPP_BASE_URL}/record`, { headers });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = data.message || 'Failed to fetch record';
      return res.status(response.status).json({ message });
    }
    res.json(data);
  } catch (err) {
    console.error('Record proxy failed', err);
    res.status(500).json({ message: 'Unable to reach C++ backend' });
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Unexpected server error' });
});

app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
});
