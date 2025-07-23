// models/Chat.js - Complete File
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
    customName: String,
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
      default: 0
    },
    allowFileSharing: {
      type: Boolean,
      default: true
    },
    maxFileSize: {
      type: Number,
      default: 10 * 1024 * 1024
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
      default: 0
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
// chatSchema.index({ inviteCode: 1 });
chatSchema.index({ 'participants.user': 1, 'participants.isActive': 1 });
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
  this.lastActivity = new Date();
  
  if (this.type === 'private' && !this.name && this.participants.length === 2) {
    this.name = 'Private Chat';
  }
  
  next();
});

// Generate invite code
chatSchema.methods.generateInviteCode = function() {
  const crypto = require('crypto');
  this.inviteCode = crypto.randomBytes(16).toString('hex');
  this.inviteExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
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

  if (type) {
    query.type = type;
  }

  return this.find(query)
    .populate('lastMessage', 'content type sender createdAt')
    .populate('participants.user', 'name username avatar isOnline lastSeen')
    .sort({ lastActivity: -1 })
    .limit(limit)
    .skip(skip)
    .lean();
};

// Static method to create private chat
chatSchema.statics.createPrivateChat = async function(user1Id, user2Id) {
  const existingChat = await this.findOne({
    type: 'private',
    'participants.user': { $all: [user1Id, user2Id] },
    'participants.isActive': true
  });

  if (existingChat && existingChat.activeParticipantsCount === 2) {
    return existingChat;
  }

  const chat = new this({
    type: 'private',
    participants: [
      { user: user1Id, role: 'member' },
      { user: user2Id, role: 'member' }
    ],
    createdBy: user1Id
  });

  return await chat.save();
};

// Static method to create group chat
chatSchema.statics.createGroupChat = async function(creatorId, name, description, participantIds = []) {
  const chat = new this({
    name,
    description,
    type: 'group',
    participants: [
      { user: creatorId, role: 'admin' },
      ...participantIds.map(id => ({ user: id, role: 'member' }))
    ],
    createdBy: creatorId
  });

  return await chat.save();
};

// Method to get chat info for a specific user
chatSchema.methods.getChatInfo = function(userId) {
  const participant = this.getParticipant(userId);
  if (!participant) return null;

  const chatInfo = {
    _id: this._id,
    name: participant.customName || this.name,
    description: this.description,
    type: this.type,
    avatar: this.avatar,
    lastActivity: this.lastActivity,
    activeParticipantsCount: this.activeParticipantsCount,
    isPinned: participant.isPinned,
    isMuted: participant.isMuted,
    muteUntil: participant.muteUntil,
    notifications: participant.notifications,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt
  };

  const isArchived = this.archivedBy.some(a => 
    a.user.toString() === userId.toString()
  );
  chatInfo.isArchived = isArchived;

  if (this.type === 'private') {
    const otherParticipant = this.participants.find(p => 
      p.user._id && p.user._id.toString() !== userId.toString() && p.isActive
    );
    if (otherParticipant && otherParticipant.user) {
      chatInfo.otherParticipant = {
        _id: otherParticipant.user._id,
        name: otherParticipant.user.name,
        username: otherParticipant.user.username,
        avatar: otherParticipant.user.avatar,
        isOnline: otherParticipant.user.isOnline,
        lastSeen: otherParticipant.user.lastSeen
      };
    }
  }

  return chatInfo;
};

// Method to update chat settings
chatSchema.methods.updateSettings = function(newSettings) {
  this.settings = { ...this.settings, ...newSettings };
  this.lastActivity = new Date();
  return this.save();
};

// Method to increment message count
chatSchema.methods.incrementMessageCount = function() {
  this.metadata.messageCount += 1;
  this.lastActivity = new Date();
  return this.save();
};

module.exports = mongoose.model('Chat', chatSchema);