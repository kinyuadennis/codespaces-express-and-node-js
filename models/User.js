// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true }, // hashed
  refreshToken: { type: String }, // store current refresh token (or hashed value) for rotation
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
