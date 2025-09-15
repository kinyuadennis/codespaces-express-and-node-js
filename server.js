// server.js
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');

const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const authenticate = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(cookieParser());

// routes
app.use('/auth', authRoutes);

// protected example route
app.get('/protected', authenticate, (req, res) => {
  // req.user set by middleware from access token
  res.json({ message: `Hello ${req.user.username}`, user: req.user });
});

// start
(async () => {
  await connectDB(process.env.MONGO_URI);
  app.listen(PORT, () => console.log('Server running on port', PORT));
})();
