// models/Chat.js
const mongoose = require('mongoose');

const chatSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    maxlength: [50, 'Chat name cannot exceed 50 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [200, 'Description cannot exceed 200 characters']
  },
  type: {
    type: String,
    enum: ['private', 'group'],
    required: true,
    default: 'private'
  },
  avatar: {
    public_id: String,
    secure_url: String
  },
  participants: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    role: {
      type: String,
      enum: ['admin', 'moderator', 'member'],
      default: 'member'
    },
    joinedAt: {
      type: Date,
      default: Date.now
    },
    leftAt: Date,
    isActive: {
      type: Boolean,
      default: true
    },
    permissions: {
      canSendMessages: {
        type: Boolean,
        default: true
      },
      canSendMedia: {
        type: Boolean,
        default: true
      },
      canAddMembers: {
        type: Boolean,
        default: false
      },
      canRemoveMembers: {
        type: Boolean,
        default: false
      },
      canEditInfo: {
        type: Boolean,
        default: false
      }
    },
    notifications: {
      type: String,
      enum: ['all', 'mentions', 'none'],
      default: 'all'
    },
    customName: String, // Custom name for this chat (user-specific)
    isPinned: {
      type: Boolean,
      default: false
    },
    isMuted: {
      type: Boolean,
      default: false
    },
    muteUntil: Date
  }],
  lastMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  lastActivity: {
    type: Date,
    default: Date.now
  },
  settings: {
    isEncrypted: {
      type: Boolean,
      default: false
    },
    messageRetention: {
      type: Number,
      default: 0 // 0 means forever, otherwise days
    },
    allowFileSharing: {
      type: Boolean,
      default: true
    },
    maxFileSize: {
      type: Number,
      default: 10 * 1024 * 1024 // 10MB in bytes
    },
    allowedFileTypes: [{
      type: String
    }],
    requireApprovalForNewMembers: {
      type: Boolean,
      default: false
    }
  },
  inviteCode: {
    type: String,
    unique: true,
    sparse: true
  },
  inviteExpires: Date,
  isArchived: {
    type: Boolean,
    default: false
  },
  archivedBy: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    archivedAt: {
      type: Date,
      default: Date.now
    }
  }],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  metadata: {
    messageCount: {
      type: Number,
      default: 0
    },
    mediaCount: {
      type: Number,
      default: 0
    },
    totalSize: {
      type: Number,
      default: 0 // in bytes
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
chatSchema.index({ participants: 1 });
chatSchema.index({ type: 1 });
chatSchema.index({ lastActivity: -1 });
chatSchema.index({ createdBy: 1 });
chatSchema.index({ inviteCode: 1 });
chatSchema.index({ 'participants.user': 1, 'participants.isActive': 1 });

// Compound indexes
chatSchema.index({ type: 1, lastActivity: -1 });
chatSchema.index({ 'participants.user': 1, lastActivity: -1 });

// Virtual for active participants count
chatSchema.virtual('activeParticipantsCount').get(function() {
  return this.participants.filter(p => p.isActive && !p.leftAt).length;
});

// Virtual for admin users
chatSchema.virtual('admins').get(function() {
  return this.participants.filter(p => p.role === 'admin' && p.isActive);
});

// Pre-save middleware
chatSchema.pre('save', function(next) {
  // Update lastActivity when chat is modified
  this.lastActivity = new Date();
  
  // Auto-generate name for private chats
  if (this.type === 'private' && !this.name && this.participants.length === 2) {
    this.name = 'Private Chat';
  }
  
  next();
});

// Generate invite code
chatSchema.methods.generateInviteCode = function() {
  const crypto = require('crypto');
  this.inviteCode = crypto.randomBytes(16).toString('hex');
  this.inviteExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  return this.inviteCode;
};

// Check if user is participant
chatSchema.methods.hasParticipant = function(userId) {
  return this.participants.some(p => 
    p.user.toString() === userId.toString() && p.isActive
  );
};

// Check if user is admin
chatSchema.methods.isAdmin = function(userId) {
  const participant = this.participants.find(p => 
    p.user.toString() === userId.toString() && p.isActive
  );
  return participant && participant.role === 'admin';
};

// Get participant by user ID
chatSchema.methods.getParticipant = function(userId) {
  return this.participants.find(p => 
    p.user.toString() === userId.toString() && p.isActive
  );
};

// Add participant
chatSchema.methods.addParticipant = function(userId, role = 'member', addedBy = null) {
  const existingIndex = this.participants.findIndex(p => 
    p.user.toString() === userId.toString()
  );

  if (existingIndex !== -1) {
    // Reactivate if they were previously removed
    this.participants[existingIndex].isActive = true;
    this.participants[existingIndex].leftAt = undefined;
    this.participants[existingIndex].joinedAt = new Date();
    this.participants[existingIndex].role = role;
  } else {
    this.participants.push({
      user: userId,
      role: role,
      joinedAt: new Date(),
      isActive: true
    });
  }

  this.lastActivity = new Date();
  return this.save();
};

// Remove participant
chatSchema.methods.removeParticipant = function(userId, removedBy = null) {
  const participant = this.participants.find(p => 
    p.user.toString() === userId.toString()
  );

  if (participant) {
    participant.isActive = false;
    participant.leftAt = new Date();
    this.lastActivity = new Date();
  }

  return this.save();
};

// Update participant role
chatSchema.methods.updateParticipantRole = function(userId, newRole) {
  const participant = this.participants.find(p => 
    p.user.toString() === userId.toString() && p.isActive
  );

  if (participant) {
    participant.role = newRole;
    this.lastActivity = new Date();
    return this.save();
  }

  throw new Error('Participant not found');
};

// Archive chat for specific user
chatSchema.methods.archiveForUser = function(userId) {
  const existingArchive = this.archivedBy.find(a => 
    a.user.toString() === userId.toString()
  );

  if (!existingArchive) {
    this.archivedBy.push({
      user: userId,
      archivedAt: new Date()
    });
    return this.save();
  }
};

// Unarchive chat for specific user
chatSchema.methods.unarchiveForUser = function(userId) {
  this.archivedBy = this.archivedBy.filter(a => 
    a.user.toString() !== userId.toString()
  );
  return this.save();
};

// Static method to find user's chats
chatSchema.statics.findUserChats = function(userId, options = {}) {
  const {
    limit = 20,
    skip = 0,
    includeArchived = false,
    type = null
  } = options;

  const query = {
    'participants.user': userId,
    'participants.isActive': true
  };

  if (!includeArchived) {
    query['archivedBy.user'] = { $ne: userId };
  }

  if