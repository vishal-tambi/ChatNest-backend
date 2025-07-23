// routes/messages.js
const express = require('express');
const { body, query, validationResult } = require('express-validator');
const Message = require('../models/Message');
const Chat = require('../models/Chat');
const { canAccessChat, messageRateLimit } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// @route   GET /api/messages/:chatId
// @desc    Get messages for a chat
// @access  Private
router.get('/:chatId', canAccessChat, [
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('skip').optional().isInt({ min: 0 }).withMessage('Skip must be non-negative'),
  query('before').optional().isISO8601().withMessage('Before must be a valid date'),
  query('after').optional().isISO8601().withMessage('After must be a valid date')
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

    const { chatId } = req.params;
    const { limit = 50, skip = 0, before, after } = req.query;

    const options = {
      limit: parseInt(limit),
      skip: parseInt(skip),
      ...(before && { before }),
      ...(after && { after })
    };

    const messages = await Message.getChatMessages(chatId, req.user._id, options);

    res.json({
      success: true,
      messages: messages.reverse(), // Return in chronological order
      pagination: {
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: messages.length === parseInt(limit)
      }
    });

  } catch (error) {
    logger.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch messages'
    });
  }
});

// @route   POST /api/messages/:chatId
// @desc    Send a message
// @access  Private
router.post('/:chatId', canAccessChat, messageRateLimit, [
  body('content')
    .optional()
    .trim()
    .isLength({ min: 1, max: 5000 })
    .withMessage('Message content must be between 1 and 5000 characters'),
  
  body('type')
    .optional()
    .isIn(['text', 'image', 'file', 'audio', 'video'])
    .withMessage('Invalid message type'),
  
  body('replyTo')
    .optional()
    .isMongoId()
    .withMessage('Invalid reply message ID')
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

    const { chatId } = req.params;
    const { content, type = 'text', replyTo, attachments } = req.body;

    // Validate that either content or attachments are provided
    if (!content && (!attachments || attachments.length === 0)) {
      return res.status(400).json({
        success: false,
        message: 'Message must have content or attachments'
      });
    }

    // Validate reply message if provided
    if (replyTo) {
      const replyMessage = await Message.findById(replyTo);
      if (!replyMessage || replyMessage.chat.toString() !== chatId) {
        return res.status(400).json({
          success: false,
          message: 'Reply message not found in this chat'
        });
      }
    }

    // Create message
    const message = new Message({
      chat: chatId,
      sender: req.user._id,
      content,
      type,
      ...(replyTo && { replyTo }),
      ...(attachments && { attachments })
    });

    await message.save();
    await message.populate('sender', 'name username avatar');
    
    if (replyTo) {
      await message.populate('replyTo', 'content sender type createdAt');
    }

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      data: message
    });

  } catch (error) {
    logger.error('Send message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send message'
    });
  }
});

// routes/friends.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { friendRequestRateLimit } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// @route   GET /api/friends
// @desc    Get user's friends
// @access  Private
router.get('/', async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('friends.user', 'name username avatar isOnline lastSeen status')
      .lean();

    const friends = user.friends
      .filter(friend => friend.status === 'accepted')
      .map(friend => ({
        _id: friend.user._id,
        name: friend.user.name,
        username: friend.user.username,
        avatar: friend.user.avatar,
        isOnline: friend.user.isOnline,
        lastSeen: friend.user.lastSeen,
        status: friend.user.status,
        addedAt: friend.addedAt
      }));

    res.json({
      success: true,
      friends,
      total: friends.length
    });

  } catch (error) {
    logger.error('Get friends error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch friends'
    });
  }
});

// @route   POST /api/friends/request
// @desc    Send friend request
// @access  Private
router.post('/request', friendRequestRateLimit, [
  body('userId').isMongoId().withMessage('Invalid user ID')
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

    const { userId } = req.body;

    if (userId === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        message: 'Cannot send friend request to yourself'
      });
    }

    const targetUser = await User.findById(userId);
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if already friends or request exists
    const currentUser = await User.findById(req.user._id);
    const existingFriend = currentUser.friends.find(f => f.user.toString() === userId);
    
    if (existingFriend) {
      return res.status(400).json({
        success: false,