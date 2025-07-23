// models/Message.js
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  chat: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Chat',
    required: true,
    index: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  content: {
    type: String,
    trim: true,
    maxlength: [5000, 'Message content cannot exceed 5000 characters']
  },
  type: {
    type: String,
    enum: ['text', 'image', 'file', 'audio', 'video', 'system', 'call'],
    default: 'text',
    required: true
  },
  attachments: [{
    type: {
      type: String,
      enum: ['image', 'file', 'audio', 'video'],
      required: true
    },
    name: {
      type: String,
      required: true
    },
    size: {
      type: Number,
      required: true
    },
    mimeType: String,
    url: {
      type: String,
      required: true
    },
    thumbnailUrl: String, // For images and videos
    duration: Number, // For audio and video files
    publicId: String, // Cloudinary public ID for deletion
    metadata: {
      width: Number,
      height: Number,
      format: String
    }
  }],
  replyTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  reactions: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    emoji: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  mentions: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    startIndex: Number,
    length: Number
  }],
  readBy: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    readAt: {
      type: Date,
      default: Date.now
    }
  }],
  deliveredTo: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    deliveredAt: {
      type: Date,
      default: Date.now
    }
  }],
  edited: {
    isEdited: {
      type: Boolean,
      default: false
    },
    editedAt: Date,
    editHistory: [{
      content: String,
      editedAt: {
        type: Date,
        default: Date.now
      }
    }]
  },
  deleted: {
    isDeleted: {
      type: Boolean,
      default: false
    },
    deletedAt: Date,
    deletedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    deletedFor: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }] // For "delete for me" vs "delete for everyone"
  },
  forwarded: {
    isForwarded: {
      type: Boolean,
      default: false
    },
    originalMessage: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Message'
    },
    forwardedFrom: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Chat'
    }
  },
  callData: {
    type: {
      type: String,
      enum: ['voice', 'video'],
    },
    duration: Number, // in seconds
    status: {
      type: String,
      enum: ['missed', 'declined', 'completed', 'failed']
    },
    participants: [{
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      joinedAt: Date,
      leftAt: Date
    }]
  },
  systemData: {
    action: {
      type: String,
      enum: [
        'user_joined', 'user_left', 'user_added', 'user_removed',
        'chat_created', 'chat_renamed', 'chat_description_changed',
        'avatar_changed', 'admin_promoted', 'admin_demoted'
      ]
    },
    targetUser: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    oldValue: String,
    newValue: String
  },
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal'
  },
  expiresAt: Date, // For disappearing messages
  pinned: {
    isPinned: {
      type: Boolean,
      default: false
    },
    pinnedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    pinnedAt: Date
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
messageSchema.index({ chat: 1, createdAt: -1 });
// messageSchema.index({ sender: 1 });
messageSchema.index({ 'readBy.user': 1 });
messageSchema.index({ 'deliveredTo.user': 1 });
messageSchema.index({ type: 1 });
messageSchema.index({ 'deleted.isDeleted': 1 });
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Compound indexes
messageSchema.index({ chat: 1, type: 1, createdAt: -1 });
messageSchema.index({ chat: 1, 'deleted.isDeleted': 1, createdAt: -1 });

// Virtual for reaction counts
messageSchema.virtual('reactionCounts').get(function() {
  const counts = {};
  this.reactions.forEach(reaction => {
    if (counts[reaction.emoji]) {
      counts[reaction.emoji]++;
    } else {
      counts[reaction.emoji] = 1;
    }
  });
  return counts;
});

// Virtual for total reactions
messageSchema.virtual('totalReactions').get(function() {
  return this.reactions.length;
});

// Virtual for read status
messageSchema.virtual('isRead').get(function() {
  return this.readBy.length > 0;
});

// Pre-save middleware
messageSchema.pre('save', function(next) {
  // Auto-expire messages if set
  if (this.type === 'text' && this.chat && this.chat.settings && this.chat.settings.messageRetention) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + this.chat.settings.messageRetention);
    this.expiresAt = expiryDate;
  }

  next();
});

// Post-save middleware to update chat's last message
messageSchema.post('save', async function(doc) {
  if (!doc.deleted.isDeleted) {
    await mongoose.model('Chat').findByIdAndUpdate(
      doc.chat,
      { 
        lastMessage: doc._id,
        lastActivity: doc.createdAt,
        $inc: { 'metadata.messageCount': 1 }
      }
    );
  }
});

// Method to mark as read by user
messageSchema.methods.markAsRead = function(userId) {
  const existingRead = this.readBy.find(r => r.user.toString() === userId.toString());
  
  if (!existingRead) {
    this.readBy.push({
      user: userId,
      readAt: new Date()
    });
    return this.save();
  }
  
  return Promise.resolve(this);
};

// Method to mark as delivered to user
messageSchema.methods.markAsDelivered = function(userId) {
  const existingDelivered = this.deliveredTo.find(d => d.user.toString() === userId.toString());
  
  if (!existingDelivered) {
    this.deliveredTo.push({
      user: userId,
      deliveredAt: new Date()
    });
    return this.save();
  }
  
  return Promise.resolve(this);
};

// Method to add reaction
messageSchema.methods.addReaction = function(userId, emoji) {
  // Remove existing reaction from this user
  this.reactions = this.reactions.filter(r => r.user.toString() !== userId.toString());
  
  // Add new reaction
  this.reactions.push({
    user: userId,
    emoji: emoji,
    createdAt: new Date()
  });
  
  return this.save();
};

// Method to remove reaction
messageSchema.methods.removeReaction = function(userId, emoji = null) {
  if (emoji) {
    this.reactions = this.reactions.filter(r => 
      !(r.user.toString() === userId.toString() && r.emoji === emoji)
    );
  } else {
    // Remove all reactions from this user
    this.reactions = this.reactions.filter(r => r.user.toString() !== userId.toString());
  }
  
  return this.save();
};

// Method to edit message
messageSchema.methods.editContent = function(newContent, editedBy) {
  // Store original content in edit history
  if (!this.edited.isEdited) {
    this.edited.editHistory.push({
      content: this.content,
      editedAt: this.createdAt
    });
  }
  
  this.content = newContent;
  this.edited.isEdited = true;
  this.edited.editedAt = new Date();
  
  return this.save();
};

// Method to soft delete message
messageSchema.methods.softDelete = function(deletedBy, deleteFor = 'me') {
  this.deleted.isDeleted = true;
  this.deleted.deletedAt = new Date();
  this.deleted.deletedBy = deletedBy;
  
  if (deleteFor === 'everyone') {
    this.deleted.deletedFor = [];
  } else {
    this.deleted.deletedFor.push(deletedBy);
  }
  
  return this.save();
};

// Method to pin/unpin message
messageSchema.methods.togglePin = function(userId) {
  if (this.pinned.isPinned) {
    this.pinned.isPinned = false;
    this.pinned.pinnedBy = undefined;
    this.pinned.pinnedAt = undefined;
  } else {
    this.pinned.isPinned = true;
    this.pinned.pinnedBy = userId;
    this.pinned.pinnedAt = new Date();
  }
  
  return this.save();
};

// Static method to get chat messages with pagination
messageSchema.statics.getChatMessages = function(chatId, userId, options = {}) {
  const {
    limit = 50,
    skip = 0,
    before = null, // Get messages before this date
    after = null,  // Get messages after this date
    type = null
  } = options;

  const query = {
    chat: chatId,
    $or: [
      { 'deleted.isDeleted': false },
      { 
        'deleted.isDeleted': true,
        'deleted.deletedFor': { $ne: userId }
      }
    ]
  };

  if (before) {
    query.createdAt = { $lt: new Date(before) };
  }

  if (after) {
    query.createdAt = { ...query.createdAt, $gt: new Date(after) };
  }

  if (type) {
    query.type = type;
  }

  return this.find(query)
    .populate('sender', 'name username avatar')
    .populate('replyTo', 'content sender type createdAt')
    .populate('reactions.user', 'name username')
    .sort({ createdAt: -1 })
    .limit(limit)
    .skip(skip)
    .lean();
};

// Static method to get unread message count for user
messageSchema.statics.getUnreadCount = async function(chatId, userId) {
  return this.countDocuments({
    chat: chatId,
    sender: { $ne: userId },
    'readBy.user': { $ne: userId },
    'deleted.isDeleted': false
  });
};

// Static method for message search
messageSchema.statics.searchMessages = function(chatId, query, userId, options = {}) {
  const { limit = 20, skip = 0 } = options;
  
  const searchQuery = {
    chat: chatId,
    content: new RegExp(query, 'i'),
    type: 'text',
    $or: [
      { 'deleted.isDeleted': false },
      { 
        'deleted.isDeleted': true,
        'deleted.deletedFor': { $ne: userId }
      }
    ]
  };

  return this.find(searchQuery)
    .populate('sender', 'name username avatar')
    .sort({ createdAt: -1 })
    .limit(limit)
    .skip(skip)
    .lean();
};

// Method to get message with context (previous and next messages)
messageSchema.statics.getMessageWithContext = async function(messageId, contextSize = 5) {
  const message = await this.findById(messageId)
    .populate('sender', 'name username avatar')
    .populate('replyTo');

  if (!message) return null;

  const [previousMessages, nextMessages] = await Promise.all([
    this.find({
      chat: message.chat,
      createdAt: { $lt: message.createdAt },
      'deleted.isDeleted': false
    })
    .populate('sender', 'name username avatar')
    .sort({ createdAt: -1 })
    .limit(contextSize)
    .lean(),

    this.find({
      chat: message.chat,
      createdAt: { $gt: message.createdAt },
      'deleted.isDeleted': false
    })
    .populate('sender', 'name username avatar')
    .sort({ createdAt: 1 })
    .limit(contextSize)
    .lean()
  ]);

  return {
    message: message.toObject(),
    previousMessages: previousMessages.reverse(),
    nextMessages
  };
};

module.exports = mongoose.model('Message', messageSchema);