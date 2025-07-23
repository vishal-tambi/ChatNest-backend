// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters'],
    minlength: [2, 'Name must be at least 2 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please enter a valid email'
    ]
  },
  username: {
    type: String,
    unique: true,
    sparse: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [20, 'Username cannot exceed 20 characters'],
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false // Don't include password in queries by default
  },
  avatar: {
    public_id: String,
    secure_url: String
  },
  bio: {
    type: String,
    maxlength: [200, 'Bio cannot exceed 200 characters'],
    trim: true
  },
  status: {
    type: String,
    enum: ['Available', 'Busy', 'Away', 'Do not disturb'],
    default: 'Available'
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  friends: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'blocked'],
      default: 'pending'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  friendRequests: [{
    from: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    message: String,
    sentAt: {
      type: Date,
      default: Date.now
    }
  }],
  blockedUsers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  settings: {
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      },
      sound: {
        type: Boolean,
        default: true
      }
    },
    privacy: {
      showOnlineStatus: {
        type: Boolean,
        default: true
      },
      showLastSeen: {
        type: Boolean,
        default: true
      },
      allowFriendRequests: {
        type: Boolean,
        default: true
      }
    },
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'auto'
    }
  },
  verificationToken: String,
  isVerified: {
    type: Boolean,
    default: false
  },
  passwordResetToken: String,
  passwordResetExpires: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  deviceTokens: [{
    token: String,
    device: String,
    platform: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
// userSchema.index({ email: 1 });
// userSchema.index({ username: 1 });
userSchema.index({ isOnline: 1 });
userSchema.index({ 'friends.user': 1 });
userSchema.index({ createdAt: -1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash password if it's been modified
  if (!this.isModified('password')) return next();

  try {
    // Hash password with cost of 12
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Pre-save middleware to generate username if not provided
userSchema.pre('save', function(next) {
  if (!this.username && this.email) {
    const emailPrefix = this.email.split('@')[0];
    this.username = emailPrefix.toLowerCase().replace(/[^a-zA-Z0-9]/g, '') + Math.floor(Math.random() * 1000);
  }
  next();
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method to generate JWT token
userSchema.methods.generateToken = function() {
  return jwt.sign(
    { 
      id: this._id, 
      email: this.email,
      username: this.username 
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: {
        lockUntil: 1,
      },
      $set: {
        loginAttempts: 1,
      }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // If we're at max attempts and not already locked, lock the account
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours
  
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
  }
  
  return this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: {
      loginAttempts: 1,
      lockUntil: 1
    }
  });
};

// Static method to find users for search
userSchema.statics.searchUsers = function(query, currentUserId, limit = 10) {
  const searchRegex = new RegExp(query, 'i');
  
  return this.find({
    _id: { $ne: currentUserId },
    $or: [
      { name: searchRegex },
      { username: searchRegex },
      { email: searchRegex }
    ]
  })
  .select('name username email avatar bio isOnline lastSeen')
  .limit(limit)
  .lean();
};

// Static method to get mutual friends
userSchema.statics.getMutualFriends = async function(userId1, userId2) {
  const user1 = await this.findById(userId1).select('friends');
  const user2 = await this.findById(userId2).select('friends');
  
  if (!user1 || !user2) return [];
  
  const user1Friends = user1.friends.filter(f => f.status === 'accepted').map(f => f.user.toString());
  const user2Friends = user2.friends.filter(f => f.status === 'accepted').map(f => f.user.toString());
  
  const mutualFriendIds = user1Friends.filter(id => user2Friends.includes(id));
  
  return this.find({ _id: { $in: mutualFriendIds } })
    .select('name username avatar')
    .lean();
};

// Method to get full user profile with privacy settings
userSchema.methods.getPublicProfile = function(requestingUserId = null) {
  const profile = {
    _id: this._id,
    name: this.name,
    username: this.username,
    avatar: this.avatar,
    bio: this.bio,
    status: this.status,
    createdAt: this.createdAt
  };

  // Add privacy-controlled fields
  if (requestingUserId) {
    const isFriend = this.friends.some(f => 
      f.user.toString() === requestingUserId.toString() && f.status === 'accepted'
    );
    
    if (this.settings.privacy.showOnlineStatus || isFriend) {
      profile.isOnline = this.isOnline;
    }
    
    if (this.settings.privacy.showLastSeen || isFriend) {
      profile.lastSeen = this.lastSeen;
    }
  }

  return profile;
};

module.exports = mongoose.model('User', userSchema);