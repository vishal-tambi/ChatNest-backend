// routes/messages.js - Complete File
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
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  
  query('skip')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Skip must be non-negative'),
  
  query('before')
    .optional()
    .isISO8601()
    .withMessage('Before must be a valid date'),
  
  query('after')
    .optional()
    .isISO8601()
    .withMessage('After must be a valid date'),
  
  query('type')
    .optional()
    .isIn(['text', 'image', 'file', 'audio', 'video', 'system', 'call'])
    .withMessage('Invalid message type')
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
    const { 
      limit = 50, 
      skip = 0, 
      before, 
      after, 
      type 
    } = req.query;

    const options = {
      limit: parseInt(limit),
      skip: parseInt(skip),
      ...(before && { before }),
      ...(after && { after }),
      ...(type && { type })
    };

    const messages = await Message.getChatMessages(chatId, req.user._id, options);

    // Get unread count
    const unreadCount = await Message.getUnreadCount(chatId, req.user._id);

    res.json({
      success: true,
      messages: messages.reverse(), // Return in chronological order
      unreadCount,
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
    .withMessage('Invalid reply message ID'),
  
  body('attachments')
    .optional()
    .isArray({ max: 5 })
    .withMessage('Maximum 5 attachments allowed'),
  
  body('attachments.*.type')
    .optional()
    .isIn(['image', 'file', 'audio', 'video'])
    .withMessage('Invalid attachment type'),
  
  body('attachments.*.name')
    .optional()
    .isString()
    .isLength({ min: 1, max: 255 })
    .withMessage('Attachment name must be between 1 and 255 characters'),
  
  body('attachments.*.url')
    .optional()
    .isURL()
    .withMessage('Invalid attachment URL'),
  
  body('attachments.*.size')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Invalid attachment size')
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
    const { 
      content, 
      type = 'text', 
      replyTo, 
      attachments,
      mentions 
    } = req.body;

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

    // Check user permissions
    const chat = req.chat;
    const participant = chat.getParticipant(req.user._id);
    
    if (!participant.permissions.canSendMessages) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to send messages in this chat'
      });
    }

    if (attachments && attachments.length > 0 && !participant.permissions.canSendMedia) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to send media in this chat'
      });
    }

    // Create message
    const messageData = {
      chat: chatId,
      sender: req.user._id,
      content: content || '',
      type,
      ...(replyTo && { replyTo }),
      ...(attachments && { attachments }),
      ...(mentions && { mentions })
    };

    const message = new Message(messageData);
    await message.save();

    // Populate message data
    await message.populate([
      { path: 'sender', select: 'name username avatar' },
      { path: 'replyTo', select: 'content sender type createdAt', populate: { path: 'sender', select: 'name username' } },
      { path: 'mentions.user', select: 'name username' }
    ]);

    // Update chat's last message and activity
    await Chat.findByIdAndUpdate(chatId, {
      lastMessage: message._id,
      lastActivity: message.createdAt,
      $inc: { 'metadata.messageCount': 1 }
    });

    logger.info(`Message sent: ${message._id} in chat: ${chatId} by user: ${req.user._id}`);

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

// @route   PUT /api/messages/:messageId
// @desc    Edit a message
// @access  Private
router.put('/:messageId', [
  body('content')
    .trim()
    .isLength({ min: 1, max: 5000 })
    .withMessage('Message content must be between 1 and 5000 characters')
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

    const { messageId } = req.params;
    const { content } = req.body;

    const message = await Message.findById(messageId);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Only allow sender to edit their own messages
    if (message.sender.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'You can only edit your own messages'
      });
    }

    // Check if message can be edited (not too old, not deleted, text type)
    if (message.type !== 'text') {
      return res.status(400).json({
        success: false,
        message: 'Only text messages can be edited'
      });
    }

    if (message.deleted.isDeleted) {
      return res.status(400).json({
        success: false,
        message: 'Cannot edit deleted message'
      });
    }

    // Check if message is too old to edit (48 hours)
    const editTimeLimit = 48 * 60 * 60 * 1000; // 48 hours
    if (Date.now() - message.createdAt.getTime() > editTimeLimit) {
      return res.status(400).json({
        success: false,
        message: 'Message is too old to edit'
      });
    }

    // Edit the message
    await message.editContent(content, req.user._id);
    await message.populate('sender', 'name username avatar');

    logger.info(`Message edited: ${messageId} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Message edited successfully',
      data: message
    });

  } catch (error) {
    logger.error('Edit message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to edit message'
    });
  }
});

// @route   DELETE /api/messages/:messageId
// @desc    Delete a message
// @access  Private
router.delete('/:messageId', [
  body('deleteFor')
    .optional()
    .isIn(['me', 'everyone'])
    .withMessage('deleteFor must be either "me" or "everyone"')
], async (req, res) => {
  try {
    const { messageId } = req.params;
    const { deleteFor = 'me' } = req.body;

    const message = await Message.findById(messageId);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Verify user has access to the chat
    const chat = await Chat.findById(message.chat);
    if (!chat || !chat.hasParticipant(req.user._id)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Check permissions for "delete for everyone"
    if (deleteFor === 'everyone') {
      const isOwner = message.sender.toString() === req.user._id.toString();
      const isAdmin = chat.isAdmin(req.user._id);
      
      if (!isOwner && !isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'You can only delete your own messages for everyone'
        });
      }

      // Check time limit for "delete for everyone" (1 hour for non-admins)
      if (!isAdmin) {
        const deleteTimeLimit = 60 * 60 * 1000; // 1 hour
        if (Date.now() - message.createdAt.getTime() > deleteTimeLimit) {
          return res.status(400).json({
            success: false,
            message: 'Message is too old to delete for everyone'
          });
        }
      }
    }

    // Perform soft delete
    await message.softDelete(req.user._id, deleteFor);

    logger.info(`Message deleted: ${messageId} by user: ${req.user._id} for: ${deleteFor}`);

    res.json({
      success: true,
      message: `Message deleted ${deleteFor === 'everyone' ? 'for everyone' : 'for you'}`
    });

  } catch (error) {
    logger.error('Delete message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete message'
    });
  }
});

// @route   POST /api/messages/:messageId/react
// @desc    Add reaction to message
// @access  Private
router.post('/:messageId/react', [
  body('emoji')
    .notEmpty()
    .withMessage('Emoji is required')
    .isLength({ min: 1, max: 10 })
    .withMessage('Invalid emoji')
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

    const { messageId } = req.params;
    const { emoji } = req.body;

    const message = await Message.findById(messageId);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Verify user has access to the chat
    const chat = await Chat.findById(message.chat);
    if (!chat || !chat.hasParticipant(req.user._id)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Add reaction
    await message.addReaction(req.user._id, emoji);
    await message.populate('reactions.user', 'name username');

    logger.info(`Reaction added: ${emoji} to message: ${messageId} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Reaction added successfully',
      reaction: {
        emoji,
        user: {
          _id: req.user._id,
          name: req.user.name,
          username: req.user.username
        },
        createdAt: new Date()
      },
      reactionCounts: message.reactionCounts
    });

  } catch (error) {
    logger.error('Add reaction error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add reaction'
    });
  }
});

// @route   DELETE /api/messages/:messageId/react
// @desc    Remove reaction from message
// @access  Private
router.delete('/:messageId/react', [
  body('emoji')
    .optional()
    .isLength({ min: 1, max: 10 })
    .withMessage('Invalid emoji')
], async (req, res) => {
  try {
    const { messageId } = req.params;
    const { emoji } = req.body;

    const message = await Message.findById(messageId);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Verify user has access to the chat
    const chat = await Chat.findById(message.chat);
    if (!chat || !chat.hasParticipant(req.user._id)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Remove reaction
    await message.removeReaction(req.user._id, emoji);

    logger.info(`Reaction removed: ${emoji || 'all'} from message: ${messageId} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Reaction removed successfully',
      reactionCounts: message.reactionCounts
    });

  } catch (error) {
    logger.error('Remove reaction error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove reaction'
    });
  }
});

// @route   POST /api/messages/:messageId/pin
// @desc    Pin/unpin a message
// @access  Private
router.post('/:messageId/pin', async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Verify user has access to the chat
    const chat = await Chat.findById(message.chat);
    if (!chat || !chat.hasParticipant(req.user._id)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Check if user is admin (only admins can pin messages in groups)
    if (chat.type === 'group' && !chat.isAdmin(req.user._id)) {
      return res.status(403).json({
        success: false,
        message: 'Only admins can pin messages in group chats'
      });
    }

    // Toggle pin status
    await message.togglePin(req.user._id);

    logger.info(`Message ${message.pinned.isPinned ? 'pinned' : 'unpinned'}: ${messageId} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: `Message ${message.pinned.isPinned ? 'pinned' : 'unpinned'} successfully`,
      data: {
        messageId: message._id,
        isPinned: message.pinned.isPinned,
        pinnedBy: message.pinned.pinnedBy,
        pinnedAt: message.pinned.pinnedAt
      }
    });

  } catch (error) {
    logger.error('Pin/unpin message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to pin/unpin message'
    });
  }
});

module.exports = router;