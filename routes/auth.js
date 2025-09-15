// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken
} = require('../utils/token');

const router = express.Router();

// Helpers
const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  // secure: true, // enable in production (HTTPS)
  maxAge: undefined, // we'll set when sending
  domain: process.env.COOKIE_DOMAIN || undefined,
};

// Register
router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'username and password required' });

  const existing = await User.findOne({ username: username.toLowerCase() });
  if (existing) return res.status(409).json({ message: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = await User.create({ username: username.toLowerCase(), password: hashed });
  res.status(201).json({ id: newUser._id, username: newUser.username });
});

// Login — returns access token and sets refresh token cookie
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'username and password required' });

  const user = await User.findOne({ username: username.toLowerCase() });
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: 'Invalid credentials' });

  const payload = { sub: user._id, username: user.username };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);

  // store refresh token (rotate strategy recommended)
  user.refreshToken = refreshToken;
  await user.save();

  // set refresh token as httpOnly cookie
  res.cookie('refreshToken', refreshToken, {
    ...COOKIE_OPTIONS,
    maxAge: 7 * 24 * 60 * 60 * 1000 // match REFRESH_TOKEN_EXPIRES (7d)
  });

  return res.json({ accessToken });
});

// Refresh access token
router.post('/refresh', async (req, res) => {
  // read refresh token from cookie
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token' });

  try {
    const payload = verifyRefreshToken(token);
    const user = await User.findById(payload.sub);
    if (!user || user.refreshToken !== token) {
      // token mismatch or user removed
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // rotate: issue new tokens
    const newPayload = { sub: user._id, username: user.username };
    const accessToken = signAccessToken(newPayload);
    const refreshToken = signRefreshToken(newPayload);

    // save new refresh token (rotate)
    user.refreshToken = refreshToken;
    await user.save();

    // update cookie
    res.cookie('refreshToken', refreshToken, {
      ...COOKIE_OPTIONS,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ accessToken });
  } catch (err) {
    return res.status(401).json({ message: 'Refresh token invalid or expired' });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  const token = req.cookies.refreshToken;
  if (token) {
    try {
      const payload = verifyRefreshToken(token);
      await User.findByIdAndUpdate(payload.sub, { $unset: { refreshToken: 1 } });
    } catch (err) {
      // ignore
    }
  }
  res.clearCookie('refreshToken', COOKIE_OPTIONS);
  return res.json({ message: 'Logged out' });
});

module.exports = router;
