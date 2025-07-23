// middleware/auth.js - Complete File
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Chat = require('../models/Chat');
const logger = require('../utils/logger');

// Authenticate JWT token
const authenticate = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // Get token from cookies (if using cookie-based auth)
    else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user from database
      const user = await User.findById(decoded.id)
        .select('-password')
        .lean();

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token. User not found.'
        });
      }

      // Check if user account is locked
      if (user.lockUntil && user.lockUntil > Date.now()) {
        return res.status(423).json({
          success: false,
          message: 'Account is temporarily locked due to too many failed login attempts.'
        });
      }

      // Check if user is verified (if verification is required)
      if (!user.isVerified && process.env.REQUIRE_EMAIL_VERIFICATION === 'true') {
        return res.status(401).json({
          success: false,
          message: 'Please verify your email address to continue.'
        });
      }

      // Attach user to request object
      req.user = user;
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Token has expired. Please login again.'
        });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: 'Invalid token format.'
        });
      } else {
        throw error;
      }
    }
  } catch (error) {
    logger.error('Authentication error:', error);
    return res.status(500).json({
      success: false,
      message: 'Authentication failed.'
    });
  }
};

// Optional authentication (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password').lean();
        if (user && (!user.lockUntil || user.lockUntil <= Date.now())) {
          req.user = user;
        }
      } catch (error) {
        // Invalid token, but we continue without user
        logger.warn('Invalid token in optional auth:', error.message);
      }
    }

    next();
  } catch (error) {
    logger.error('Optional authentication error:', error);
    next();
  }
};

// Check if user has specific role
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions.'
      });
    }

    next();
  };
};

// Check if user can access chat
const canAccessChat = async (req, res, next) => {
  try {
    const chatId = req.params.chatId || req.params.id || req.body.chatId;
    
    if (!chatId) {
      return res.status(400).json({
        success: false,
        message: 'Chat ID is required.'
      });
    }

    const chat = await Chat.findById(chatId);

    if (!chat) {
      return res.status(404).json({
        success: false,
        message: 'Chat not found.'
      });
    }

    // Check if user is a participant
    const isParticipant = chat.hasParticipant(req.user._id);
    
    if (!isParticipant) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. You are not a participant in this chat.'
      });
    }

    // Attach chat to request
    req.chat = chat;
    next();
  } catch (error) {
    logger.error('Chat access check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify chat access.'
    });
  }
};

// Check if user can modify chat (admin or owner)
const canModifyChat = async (req, res, next) => {
  try {
    const chat = req.chat; // Assumes canAccessChat middleware ran first
    
    if (!chat) {
      return res.status(400).json({
        success: false,
        message: 'Chat information not available.'
      });
    }

    // Check if user is admin or creator
    const isAdmin = chat.isAdmin(req.user._id);
    const isCreator = chat.createdBy.toString() === req.user._id.toString();
    
    if (!isAdmin && !isCreator) {
      return res.status(403).json({
        success: false,
        message: 'Only chat administrators can perform this action.'
      });
    }

    next();
  } catch (error) {
    logger.error('Chat modification check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify modification permissions.'
    });
  }
};

// Rate limiting for specific actions
const createActionLimiter = (windowMs, max, message) => {
  const attempts = new Map();
  
  return (req, res, next) => {
    const key = req.user._id.toString();
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old attempts
    if (attempts.has(key)) {
      const userAttempts = attempts.get(key).filter(time => time > windowStart);
      attempts.set(key, userAttempts);
    }
    
    const userAttempts = attempts.get(key) || [];
    
    if (userAttempts.length >= max) {
      return res.status(429).json({
        success: false,
        message: message || 'Too many requests. Please try again later.',
        retryAfter: Math.ceil((userAttempts[0] + windowMs - now) / 1000)
      });
    }
    
    userAttempts.push(now);
    attempts.set(key, userAttempts);
    
    next();
  };
};

// Specific limiters
const messageRateLimit = createActionLimiter(
  60 * 1000, // 1 minute
  30, // 30 messages per minute
  'Message rate limit exceeded. Please slow down.'
);

const fileUploadRateLimit = createActionLimiter(
  5 * 60 * 1000, // 5 minutes
  10, // 10 uploads per 5 minutes
  'File upload rate limit exceeded. Please try again later.'
);

const friendRequestRateLimit = createActionLimiter(
  60 * 60 * 1000, // 1 hour
  20, // 20 friend requests per hour
  'Friend request rate limit exceeded. Please try again later.'
);

const chatCreationRateLimit = createActionLimiter(
  60 * 60 * 1000, // 1 hour
  50, // 50 chats per hour
  'Chat creation rate limit exceeded. Please try again later.'
);

const searchRateLimit = createActionLimiter(
  60 * 1000, // 1 minute
  60, // 60 searches per minute
  'Search rate limit exceeded. Please slow down.'
);

// Validate request data middleware
const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, { 
      abortEarly: false,
      stripUnknown: true 
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));
      
      return res.status(400).json({
        success: false,
        message: 'Validation failed.',
        errors
      });
    }
    
    next();
  };
};

// Check user online status middleware
const updateUserActivity = async (req, res, next) => {
  try {
    if (req.user && req.user._id) {
      // Update user's last seen and online status
      await User.findByIdAndUpdate(
        req.user._id,
        { 
          lastSeen: new Date(),
          isOnline: true 
        },
        { new: true }
      );
    }
    next();
  } catch (error) {
    logger.error('Failed to update user activity:', error);
    // Don't fail the request if activity update fails
    next();
  }
};

// Check if user owns resource
const checkOwnership = (resourceField = 'user') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.'
      });
    }

    // Get resource from different sources
    let resourceUserId;
    
    if (req.resource && req.resource[resourceField]) {
      resourceUserId = req.resource[resourceField];
    } else if (req.params.userId) {
      resourceUserId = req.params.userId;
    } else if (req.body[resourceField]) {
      resourceUserId = req.body[resourceField];
    }

    if (!resourceUserId) {
      return res.status(400).json({
        success: false,
        message: 'Resource ownership cannot be determined.'
      });
    }

    if (resourceUserId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. You can only access your own resources.'
      });
    }

    next();
  };
};

// Check if user can moderate chat (admin or moderator)
const canModerateChat = async (req, res, next) => {
  try {
    const chat = req.chat; // Assumes canAccessChat middleware ran first
    
    if (!chat) {
      return res.status(400).json({
        success: false,
        message: 'Chat information not available.'
      });
    }

    const participant = chat.getParticipant(req.user._id);
    
    if (!participant || !['admin', 'moderator'].includes(participant.role)) {
      return res.status(403).json({
        success: false,
        message: 'Only chat administrators and moderators can perform this action.'
      });
    }

    next();
  } catch (error) {
    logger.error('Chat moderation check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify moderation permissions.'
    });
  }
};

// Check if user can send messages in chat
const canSendMessages = async (req, res, next) => {
  try {
    const chat = req.chat; // Assumes canAccessChat middleware ran first
    
    if (!chat) {
      return res.status(400).json({
        success: false,
        message: 'Chat information not available.'
      });
    }

    const participant = chat.getParticipant(req.user._id);
    
    if (!participant || !participant.permissions.canSendMessages) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to send messages in this chat.'
      });
    }

    next();
  } catch (error) {
    logger.error('Send message permission check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify message permissions.'
    });
  }
};

// Check if user can send media in chat
const canSendMedia = async (req, res, next) => {
  try {
    const chat = req.chat; // Assumes canAccessChat middleware ran first
    
    if (!chat) {
      return res.status(400).json({
        success: false,
        message: 'Chat information not available.'
      });
    }

    const participant = chat.getParticipant(req.user._id);
    
    if (!participant || !participant.permissions.canSendMedia) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to send media in this chat.'
      });
    }

    next();
  } catch (error) {
    logger.error('Send media permission check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify media permissions.'
    });
  }
};

// Check if user can add members to chat
const canAddMembers = async (req, res, next) => {
  try {
    const chat = req.chat; // Assumes canAccessChat middleware ran first
    
    if (!chat) {
      return res.status(400).json({
        success: false,
        message: 'Chat information not available.'
      });
    }

    if (chat.type === 'private') {
      return res.status(400).json({
        success: false,
        message: 'Cannot add members to private chat.'
      });
    }

    const participant = chat.getParticipant(req.user._id);
    
    if (!participant || (!participant.permissions.canAddMembers && participant.role !== 'admin')) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to add members to this chat.'
      });
    }

    next();
  } catch (error) {
    logger.error('Add members permission check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify add members permissions.'
    });
  }
};

// Check if user is blocked by another user
const checkBlocked = async (req, res, next) => {
  try {
    const { userId } = req.params;
    
    if (!userId) {
      return next();
    }

    const targetUser = await User.findById(userId).select('blockedUsers');
    
    if (targetUser && targetUser.blockedUsers.includes(req.user._id)) {
      return res.status(403).json({
        success: false,
        message: 'You have been blocked by this user.'
      });
    }

    // Check if current user has blocked the target user
    const currentUser = await User.findById(req.user._id).select('blockedUsers');
    
    if (currentUser && currentUser.blockedUsers.includes(userId)) {
      return res.status(403).json({
        success: false,
        message: 'You have blocked this user.'
      });
    }

    next();
  } catch (error) {
    logger.error('Block check error:', error);
    next(); // Continue if block check fails
  }
};

// Middleware to prevent self-targeting actions
const preventSelfTarget = (req, res, next) => {
  const { userId } = req.params;
  
  if (userId && userId === req.user._id.toString()) {
    return res.status(400).json({
      success: false,
      message: 'You cannot perform this action on yourself.'
    });
  }
  
  next();
};

// Advanced rate limiting with different limits for different user types
const createAdvancedRateLimit = (config) => {
  const attempts = new Map();
  
  return (req, res, next) => {
    const userId = req.user._id.toString();
    const userType = req.user.role || 'user';
    const limits = config[userType] || config.default;
    
    if (!limits) {
      return next();
    }
    
    const { windowMs, max, message } = limits;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old attempts
    if (attempts.has(userId)) {
      const userAttempts = attempts.get(userId).filter(time => time > windowStart);
      attempts.set(userId, userAttempts);
    }
    
    const userAttempts = attempts.get(userId) || [];
    
    if (userAttempts.length >= max) {
      return res.status(429).json({
        success: false,
        message: message || 'Rate limit exceeded.',
        retryAfter: Math.ceil((userAttempts[0] + windowMs - now) / 1000)
      });
    }
    
    userAttempts.push(now);
    attempts.set(userId, userAttempts);
    
    next();
  };
};

module.exports = {
  authenticate,
  optionalAuth,
  authorize,
  canAccessChat,
  canModifyChat,
  canModerateChat,
  canSendMessages,
  canSendMedia,
  canAddMembers,
  messageRateLimit,
  fileUploadRateLimit,
  friendRequestRateLimit,
  chatCreationRateLimit,
  searchRateLimit,
  validateRequest,
  updateUserActivity,
  createActionLimiter,
  createAdvancedRateLimit,
  checkOwnership,
  checkBlocked,
  preventSelfTarget
};