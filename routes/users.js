// routes/users.js - Complete Version
const express = require('express');
const { query, body, validationResult } = require('express-validator');
const User = require('../models/User');
const Chat = require('../models/Chat');
const Message = require('../models/Message');
const logger = require('../utils/logger');

const router = express.Router();

// @route   GET /api/users/all
// @desc    Get all users (for testing/demo purposes)
// @access  Private
router.get('/all', async (req, res) => {
  try {
    const { limit = 50, page = 1 } = req.query;
    const skip = (page - 1) * limit;

    const users = await User.find({ _id: { $ne: req.user._id } })
      .select('name username email avatar bio isOnline lastSeen status createdAt')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip)
      .lean();

    const total = await User.countDocuments({ _id: { $ne: req.user._id } });

    res.json({
      success: true,
      users,
      total,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / limit)
    });

  } catch (error) {
    logger.error('Get all users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
});

// @route   GET /api/users/search
// @desc    Search for users
// @access  Private
router.get('/search', [
  query('q')
    .notEmpty()
    .trim()
    .isLength({ min: 2 })
    .withMessage('Search query must be at least 2 characters'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 50 })
    .withMessage('Limit must be between 1 and 50')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { q: query, limit = 10 } = req.query;

    const users = await User.searchUsers(query, req.user._id, parseInt(limit));

    // Get mutual friends count and friendship status for each user
    const usersWithDetails = await Promise.all(
      users.map(async (user) => {
        const mutualFriends = await User.getMutualFriends(req.user._id, user._id);
        
        // Check friendship status
        const currentUser = await User.findById(req.user._id).select('friends friendRequests');
        const friendship = currentUser.friends.find(f => f.user.toString() === user._id.toString());
        const receivedRequest = currentUser.friendRequests.find(r => r.from.toString() === user._id.toString());
        
        let friendshipStatus = 'none';
        if (friendship) {
          friendshipStatus = friendship.status;
        } else if (receivedRequest) {
          friendshipStatus = 'received';
        }

        return {
          ...user,
          mutualFriendsCount: mutualFriends.length,
          friendshipStatus
        };
      })
    );

    res.json({
      success: true,
      users: usersWithDetails,
      total: usersWithDetails.length
    });

  } catch (error) {
    logger.error('Search users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search users'
    });
  }
});

// @route   GET /api/users/profile/:userId
// @desc    Get user profile
// @access  Private
router.get('/profile/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const profile = user.getPublicProfile(req.user._id);
    
    // Get mutual friends
    const mutualFriends = await User.getMutualFriends(req.user._id, userId);
    profile.mutualFriends = mutualFriends.slice(0, 5); // Show only first 5
    profile.mutualFriendsCount = mutualFriends.length;

    // Check friendship status
    const currentUser = await User.findById(req.user._id);
    const friendship = currentUser.friends.find(f => f.user.toString() === userId);
    const sentRequest = currentUser.friends.find(f => f.user.toString() === userId && f.status === 'pending');
    const receivedRequest = currentUser.friendRequests.find(r => r.from.toString() === userId);
    
    if (friendship && friendship.status === 'accepted') {
      profile.friendshipStatus = 'accepted';
      profile.friendSince = friendship.addedAt;
    } else if (sentRequest) {
      profile.friendshipStatus = 'sent';
    } else if (receivedRequest) {
      profile.friendshipStatus = 'received';
    } else {
      profile.friendshipStatus = 'none';
    }

    // Get common chats
    const commonChats = await Chat.find({
      type: 'group',
      'participants.user': { $all: [req.user._id, userId] },
      'participants.isActive': true
    }).select('name avatar type participants').limit(5);

    profile.commonChats = commonChats.map(chat => ({
      _id: chat._id,
      name: chat.name,
      avatar: chat.avatar,
      participantCount: chat.participants.filter(p => p.isActive).length
    }));

    res.json({
      success: true,
      profile
    });

  } catch (error) {
    logger.error('Get user profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user profile'
    });
  }
});

// @route   PUT /api/users/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be between 3 and 20 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Bio cannot exceed 200 characters'),
  
  body('status')
    .optional()
    .isIn(['Available', 'Busy', 'Away', 'Do not disturb'])
    .withMessage('Invalid status')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { name, username, bio, status } = req.body;

    // Check if username is already taken
    if (username) {
      const existingUser = await User.findOne({
        username,
        _id: { $ne: req.user._id }
      });
      
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Username is already taken'
        });
      }
    }

    // Update user
    const updateData = {};
    if (name) updateData.name = name;
    if (username) updateData.username = username;
    if (bio !== undefined) updateData.bio = bio;
    if (status) updateData.status = status;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password -loginAttempts -lockUntil');

    logger.info(`Profile updated for user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user
    });

  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile'
    });
  }
});

// @route   PUT /api/users/settings
// @desc    Update user settings
// @access  Private
router.put('/settings', [
  body('notifications.email')
    .optional()
    .isBoolean()
    .withMessage('Email notifications must be boolean'),
  
  body('notifications.push')
    .optional()
    .isBoolean()
    .withMessage('Push notifications must be boolean'),
  
  body('notifications.sound')
    .optional()
    .isBoolean()
    .withMessage('Sound notifications must be boolean'),
  
  body('privacy.showOnlineStatus')
    .optional()
    .isBoolean()
    .withMessage('Show online status must be boolean'),
  
  body('privacy.showLastSeen')
    .optional()
    .isBoolean()
    .withMessage('Show last seen must be boolean'),
  
  body('privacy.allowFriendRequests')
    .optional()
    .isBoolean()
    .withMessage('Allow friend requests must be boolean'),
  
  body('theme')
    .optional()
    .isIn(['light', 'dark', 'auto'])
    .withMessage('Theme must be light, dark, or auto')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { notifications, privacy, theme } = req.body;

    const user = await User.findById(req.user._id);
    
    // Update settings
    if (notifications) {
      user.settings.notifications = { ...user.settings.notifications.toObject(), ...notifications };
    }
    
    if (privacy) {
      user.settings.privacy = { ...user.settings.privacy.toObject(), ...privacy };
    }
    
    if (theme) {
      user.settings.theme = theme;
    }

    await user.save();

    logger.info(`Settings updated for user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Settings updated successfully',
      settings: user.settings
    });

  } catch (error) {
    logger.error('Update settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update settings'
    });
  }
});

// @route   GET /api/users/me
// @desc    Get current user's profile
// @access  Private
router.get('/me', async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -loginAttempts -lockUntil')
      .populate('friends.user', 'name username avatar isOnline lastSeen')
      .lean();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get friend counts
    const friendCounts = {
      total: user.friends.filter(f => f.status === 'accepted').length,
      online: user.friends.filter(f => f.status === 'accepted' && f.user.isOnline).length,
      pending: user.friends.filter(f => f.status === 'pending').length,
      requests: user.friendRequests.length
    };

    // Get chat count
    const chatCount = await Chat.countDocuments({
      'participants.user': req.user._id,
      'participants.isActive': true
    });

    res.json({
      success: true,
      user: {
        ...user,
        friendCounts,
        chatCount
      }
    });

  } catch (error) {
    logger.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user profile'
    });
  }
});

// @route   GET /api/users/online
// @desc    Get online users from user's contacts
// @access  Private
router.get('/online', async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate({
        path: 'friends.user',
        select: 'name username avatar isOnline lastSeen status',
        match: { isOnline: true }
      });

    const onlineFriends = user.friends
      .filter(friend => friend.status === 'accepted' && friend.user && friend.user.isOnline)
      .map(friend => ({
        _id: friend.user._id,
        name: friend.user.name,
        username: friend.user.username,
        avatar: friend.user.avatar,
        status: friend.user.status,
        lastSeen: friend.user.lastSeen
      }));

    res.json({
      success: true,
      onlineUsers: onlineFriends,
      total: onlineFriends.length
    });

  } catch (error) {
    logger.error('Get online users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get online users'
    });
  }
});

// @route   POST /api/users/block
// @desc    Block/unblock a user
// @access  Private
router.post('/block', [
  body('userId')
    .isMongoId()
    .withMessage('Invalid user ID'),
  
  body('block')
    .isBoolean()
    .withMessage('Block status must be boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { userId, block } = req.body;

    if (userId === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        message: 'Cannot block yourself'
      });
    }

    const targetUser = await User.findById(userId);
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = await User.findById(req.user._id);

    if (block) {
      // Block user
      if (!user.blockedUsers.includes(userId)) {
        user.blockedUsers.push(userId);
      }
      
      // Remove from friends if they are friends
      user.friends = user.friends.filter(f => f.user.toString() !== userId);
      user.friendRequests = user.friendRequests.filter(r => r.from.toString() !== userId);
      
      // Remove from target user's friends as well
      targetUser.friends = targetUser.friends.filter(f => f.user.toString() !== req.user._id.toString());
      
      await Promise.all([user.save(), targetUser.save()]);
      
      logger.info(`User blocked: ${userId} by user: ${req.user._id}`);
      
      res.json({
        success: true,
        message: 'User blocked successfully'
      });
    } else {
      // Unblock user
      user.blockedUsers = user.blockedUsers.filter(id => id.toString() !== userId);
      await user.save();
      
      logger.info(`User unblocked: ${userId} by user: ${req.user._id}`);
      
      res.json({
        success: true,
        message: 'User unblocked successfully'
      });
    }

  } catch (error) {
    logger.error('Block/unblock user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to block/unblock user'
    });
  }
});

// @route   GET /api/users/blocked
// @desc    Get blocked users list
// @access  Private
router.get('/blocked', async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('blockedUsers', 'name username avatar')
      .lean();

    res.json({
      success: true,
      blockedUsers: user.blockedUsers || [],
      total: (user.blockedUsers || []).length
    });

  } catch (error) {
    logger.error('Get blocked users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get blocked users'
    });
  }
});

// @route   DELETE /api/users/account
// @desc    Delete user account
// @access  Private
router.delete('/account', [
  body('password')
    .notEmpty()
    .withMessage('Password is required for account deletion'),
  
  body('confirmDelete')
    .equals('DELETE')
    .withMessage('Please type DELETE to confirm account deletion')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { password } = req.body;

    // Get user with password for verification
    const user = await User.findById(req.user._id).select('+password');
    
    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid password'
      });
    }

    // Delete user's messages
    await Message.deleteMany({ sender: req.user._id });

    // Remove user from all chats
    await Chat.updateMany(
      { 'participants.user': req.user._id },
      { 
        $set: { 
          'participants.$.isActive': false,
          'participants.$.leftAt': new Date()
        }
      }
    );

    // Remove from other users' friend lists
    await User.updateMany(
      { 'friends.user': req.user._id },
      { $pull: { friends: { user: req.user._id } } }
    );

    // Remove friend requests
    await User.updateMany(
      { 'friendRequests.from': req.user._id },
      { $pull: { friendRequests: { from: req.user._id } } }
    );

    // Delete user account
    await User.findByIdAndDelete(req.user._id);

    logger.info(`User account deleted: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });

  } catch (error) {
    logger.error('Delete account error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete account'
    });
  }
});

// @route   GET /api/users/stats
// @desc    Get user statistics
// @access  Private
router.get('/stats', async (req, res) => {
  try {
    const userId = req.user._id;

    // Get message count
    const messageCount = await Message.countDocuments({ sender: userId });

    // Get chat count
    const chatCount = await Chat.countDocuments({
      'participants.user': userId,
      'participants.isActive': true
    });

    // Get friend count
    const user = await User.findById(userId).select('friends createdAt');
    const friendCount = user.friends.filter(f => f.status === 'accepted').length;

    // Get media count
    const mediaCount = await Message.countDocuments({
      sender: userId,
      type: { $in: ['image', 'video', 'audio', 'file'] }
    });

    // Get most active chat
    const mostActiveChat = await Message.aggregate([
      { $match: { sender: userId } },
      { $group: { _id: '$chat', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 1 },
      { $lookup: { from: 'chats', localField: '_id', foreignField: '_id', as: 'chat' } },
      { $unwind: '$chat' }
    ]);

    const stats = {
      messagesSent: messageCount,
      totalChats: chatCount,
      totalFriends: friendCount,
      mediaShared: mediaCount,
      mostActiveChat: mostActiveChat.length > 0 ? {
        name: mostActiveChat[0].chat.name,
        messageCount: mostActiveChat[0].count
      } : null,
      joinedAt: user.createdAt || new Date()
    };

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    logger.error('Get user stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user statistics'
    });
  }
});

// @route   POST /api/users/device-token
// @desc    Register device token for push notifications
// @access  Private
router.post('/device-token', [
  body('token')
    .notEmpty()
    .withMessage('Device token is required'),
  
  body('device')
    .notEmpty()
    .withMessage('Device name is required'),
  
  body('platform')
    .isIn(['ios', 'android', 'web'])
    .withMessage('Platform must be ios, android, or web')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { token, device, platform } = req.body;

    const user = await User.findById(req.user._id);

    // Remove existing token if it exists
    user.deviceTokens = user.deviceTokens.filter(dt => dt.token !== token);

    // Add new token
    user.deviceTokens.push({
      token,
      device,
      platform,
      createdAt: new Date()
    });

    // Keep only last 5 device tokens per user
    if (user.deviceTokens.length > 5) {
      user.deviceTokens = user.deviceTokens
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, 5);
    }

    await user.save();

    logger.info(`Device token registered for user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Device token registered successfully'
    });

  } catch (error) {
    logger.error('Register device token error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to register device token'
    });
  }
});

// @route   DELETE /api/users/device-token
// @desc    Remove device token
// @access  Private
router.delete('/device-token', [
  body('token')
    .notEmpty()
    .withMessage('Device token is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { token } = req.body;

    const user = await User.findById(req.user._id);
    user.deviceTokens = user.deviceTokens.filter(dt => dt.token !== token);
    await user.save();

    logger.info(`Device token removed for user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Device token removed successfully'
    });

  } catch (error) {
    logger.error('Remove device token error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove device token'
    });
  }
});

// @route   POST /api/users/avatar
// @desc    Upload user avatar
// @access  Private
router.post('/avatar', async (req, res) => {
  try {
    // This endpoint assumes you have file upload middleware configured
    // Example with multer: upload.single('avatar')
    
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const user = await User.findById(req.user._id);
    
    // Update user avatar (assuming you store file path or URL)
    user.avatar = req.file.path || req.file.location; // Adjust based on your storage solution
    await user.save();

    logger.info(`Avatar updated for user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Avatar updated successfully',
      avatar: user.avatar
    });

  } catch (error) {
    logger.error('Upload avatar error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload avatar'
    });
  }
});

// @route   DELETE /api/users/avatar
// @desc    Remove user avatar
// @access  Private
router.delete('/avatar', async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    // Remove avatar
    user.avatar = null;
    await user.save();

    logger.info(`Avatar removed for user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Avatar removed successfully'
    });

  } catch (error) {
    logger.error('Remove avatar error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove avatar'
    });
  }
});

// @route   GET /api/users/export-data
// @desc    Export user data (GDPR compliance)
// @access  Private
router.get('/export-data', async (req, res) => {
  try {
    const userId = req.user._id;

    // Get user data
    const user = await User.findById(userId)
      .select('-password -loginAttempts -lockUntil')
      .populate('friends.user', 'name username')
      .populate('blockedUsers', 'name username')
      .lean();

    // Get user's messages
    const messages = await Message.find({ sender: userId })
      .populate('chat', 'name type')
      .select('content type createdAt chat')
      .lean();

    // Get user's chats
    const chats = await Chat.find({
      'participants.user': userId,
      'participants.isActive': true
    }).select('name type createdAt participants').lean();

    const exportData = {
      profile: user,
      messages: messages,
      chats: chats,
      exportedAt: new Date(),
      totalMessages: messages.length,
      totalChats: chats.length
    };

    logger.info(`Data exported for user: ${req.user._id}`);

    res.json({
      success: true,
      data: exportData
    });

  } catch (error) {
    logger.error('Export user data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to export user data'
    });
  }
});

module.exports = router;