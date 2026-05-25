const mongoose = require('mongoose');

// Connect to MongoDB
const DB_URI = process.env.DB_URI || 'mongodb://127.0.0.1:27017/University';

mongoose.connect(DB_URI)
  .then(() => {
    console.log('Database Connected Successfully to University DB');
  })
  .catch((err) => {
    console.error('Error: Database connection failed!', err.message);
  });

// User Schema
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['User', 'Admin'],
    default: 'User'
  },
  twoFactorSecret: {
    type: String, // Encrypted TOTP secret
    default: null
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  personalNote: {
    type: String, // Encrypted sensitive user note (AES-256-GCM)
    default: ''
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Security/Audit Log Schema
const SecurityLogSchema = new mongoose.Schema({
  eventType: {
    type: String,
    required: true,
    enum: [
      'LOGIN_SUCCESS',
      'LOGIN_FAILURE',
      'MFA_SETUP',
      'MFA_VERIFIED',
      'MFA_FAILED',
      'MFA_DISABLED',
      'LOGOUT',
      'UNAUTHORIZED_ACCESS',
      'ROLE_CHANGE',
      'USER_DELETED',
      'NOTE_UPDATE',
      'RATE_LIMIT_EXCEEDED'
    ]
  },
  username: {
    type: String,
    default: 'Anonymous'
  },
  ipAddress: {
    type: String,
    default: 'Unknown'
  },
  userAgent: {
    type: String,
    default: 'Unknown'
  },
  details: {
    type: String,
    default: ''
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const UserModel = mongoose.model('User', UserSchema);
const SecurityLogModel = mongoose.model('SecurityLog', SecurityLogSchema);

module.exports = {
  mongoose,
  UserModel,
  SecurityLogModel
};
