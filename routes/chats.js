// routes/chats.js
const express = require('express');
const { body, query, validationResult } = require('express-validator');
const Chat = require('../models/Chat');
const Message = require('../models/Message');
const User = require('../models/User');
const { canAccessChat, canModifyChat } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Validation schemas
const createChatValidation = [
  body('type')
    .isIn(['private', 'group'])
    .withMessage('Chat type must be either private or group'),
  
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Chat name must be between 1 and 50 characters'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Description cannot exceed 200 characters'),
  
  body('participants')
    .isArray({ min: 1 })
    .withMessage('At least one participant is required'),
  
  body('participants.*')
    .isMongoId()
    .withMessage('Invalid participant ID')
];

// @route   GET /api/chats
// @desc    Get user's chats
// @access  Private
router.get('/', [
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('skip').optional().isInt({ min: 0 }).withMessage('Skip must be a non-negative integer'),
  query('type').optional().isIn(['private', 'group']).withMessage('Type must be private or group'),
  query('archived').optional().isBoolean().withMessage('Archived must be a boolean')
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

    const {
      limit = 20,
      skip = 0,
      type,
      archived = false
    } = req.query;

    const options = {
      limit: parseInt(limit),
      skip: parseInt(skip),
      includeArchived: archived === 'true',
      ...(type && { type })
    };

    const chats = await Chat.findUserChats(req.user._id, options);

    // Get unread count for each chat
    const chatsWithUnreadCount = await Promise.all(
      chats.map(async (chat) => {
        const unreadCount = await Message.getUnreadCount(chat._id, req.user._id);
        const chatInfo = chat.getChatInfo ? chat.getChatInfo(req.user._id) : chat;
        
        return {
          ...chatInfo,
          unreadCount
        };
      })
    );

    res.json({
      success: true,
      chats: chatsWithUnreadCount,
      total: chatsWithUnreadCount.length
    });

  } catch (error) {
    logger.error('Get chats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch chats'
    });
  }
});

// @route   POST /api/chats
// @desc    Create a new chat
// @access  Private
router.post('/', createChatValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { type, name, description, participants } = req.body;

    // Validate participants exist
    const validParticipants = await User.find({
      _id: { $in: participants }
    }).select('_id');

    if (validParticipants.length !== participants.length) {
      return res.status(400).json({
        success: false,
        message: 'One or more participants not found'
      });
    }

    let chat;

    if (type === 'private') {
      // For private chats, ensure only 2 participants (current user + 1 other)
      if (participants.length !== 1) {
        return res.status(400).json({
          success: false,
          message: 'Private chat must have exactly one other participant'
        });
      }

      const otherUserId = participants[0];
      
      // Check if private chat already exists
      chat = await Chat.createPrivateChat(req.user._id, otherUserId);
      
    } else {
      // Group chat
      if (!name) {
        return res.status(400).json({
          success: false,
          message: 'Group name is required'
        });
      }

      chat = await Chat.createGroupChat(
        req.user._id,
        name,
        description,
        participants
      );
    }

    // Populate the chat data
    await chat.populate('participants.user', 'name username avatar isOnline lastSeen');

    // Create system message for group creation
    if (type === 'group') {
      const systemMessage = new Message({
        chat: chat._id,
        sender: req.user._id,
        content: `${req.user.name} created the group`,
        type: 'system',
        systemData: {
          action: 'chat_created'
        }
      });
      await systemMessage.save();
    }

    logger.info(`Chat created: ${chat._id} by user: ${req.user._id}`);

    res.status(201).json({
      success: true,
      message: 'Chat created successfully',
      chat: chat.getChatInfo(req.user._id)
    });

  } catch (error) {
    logger.error('Create chat error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create chat'
    });
  }
});

// @route   GET /api/chats/:id
// @desc    Get chat details
// @access  Private
router.get('/:id', canAccessChat, async (req, res) => {
  try {
    const chat = req.chat;
    
    // Populate participants with full user data
    await chat.populate('participants.user', 'name username avatar isOnline lastSeen status');
    await chat.populate('lastMessage', 'content type sender createdAt');

    const chatInfo = chat.getChatInfo(req.user._id);
    
    // Get unread message count
    const unreadCount = await Message.getUnreadCount(chat._id, req.user._id);
    
    res.json({
      success: true,
      chat: {
        ...chatInfo,
        unreadCount,
        participants: chat.participants.filter(p => p.isActive)
      }
    });

  } catch (error) {
    logger.error('Get chat details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch chat details'
    });
  }
});

// @route   PUT /api/chats/:id
// @desc    Update chat details
// @access  Private
router.put('/:id', canAccessChat, canModifyChat, [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Chat name must be between 1 and 50 characters'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Description cannot exceed 200 characters')
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

    const { name, description } = req.body;
    const chat = req.chat;

    const oldName = chat.name;
    const oldDescription = chat.description;

    // Update chat details
    if (name !== undefined) chat.name = name;
    if (description !== undefined) chat.description = description;

    await chat.save();

    // Create system messages for changes
    if (name && name !== oldName) {
      const systemMessage = new Message({
        chat: chat._id,
        sender: req.user._id,
        content: `${req.user.name} changed the group name to "${name}"`,
        type: 'system',
        systemData: {
          action: 'chat_renamed',
          oldValue: oldName,
          newValue: name
        }
      });
      await systemMessage.save();
    }

    if (description && description !== oldDescription) {
      const systemMessage = new Message({
        chat: chat._id,
        sender: req.user._id,
        content: `${req.user.name} updated the group description`,
        type: 'system',
        systemData: {
          action: 'chat_description_changed',
          oldValue: oldDescription,
          newValue: description
        }
      });
      await systemMessage.save();
    }

    logger.info(`Chat updated: ${chat._id} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Chat updated successfully',
      chat: chat.getChatInfo(req.user._id)
    });

  } catch (error) {
    logger.error('Update chat error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update chat'
    });
  }
});

// @route   POST /api/chats/:id/participants
// @desc    Add participants to chat
// @access  Private
router.post('/:id/participants', canAccessChat, canModifyChat, [
  body('participants')
    .isArray({ min: 1 })
    .withMessage('At least one participant is required'),
  
  body('participants.*')
    .isMongoId()
    .withMessage('Invalid participant ID')
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

    const { participants } = req.body;
    const chat = req.chat;

    if (chat.type === 'private') {
      return res.status(400).json({
        success: false,
        message: 'Cannot add participants to private chat'
      });
    }

    // Validate participants exist
    const validParticipants = await User.find({
      _id: { $in: participants }
    }).select('name username');

    if (validParticipants.length !== participants.length) {
      return res.status(400).json({
        success: false,
        message: 'One or more participants not found'
      });
    }

    // Add each participant
    const addedParticipants = [];
    for (const participantId of participants) {
      if (!chat.hasParticipant(participantId)) {
        await chat.addParticipant(participantId, 'member', req.user._id);
        const participant = validParticipants.find(p => p._id.toString() === participantId);
        addedParticipants.push(participant);

        // Create system message
        const systemMessage = new Message({
          chat: chat._id,
          sender: req.user._id,
          content: `${req.user.name} added ${participant.name} to the group`,
          type: 'system',
          systemData: {
            action: 'user_added',
            targetUser: participantId
          }
        });
        await systemMessage.save();
      }
    }

    logger.info(`Participants added to chat: ${chat._id} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Participants added successfully',
      addedParticipants
    });

  } catch (error) {
    logger.error('Add participants error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add participants'
    });
  }
});

// @route   DELETE /api/chats/:id/participants/:userId
// @desc    Remove participant from chat
// @access  Private
router.delete('/:id/participants/:userId', canAccessChat, canModifyChat, async (req, res) => {
  try {
    const { userId } = req.params;
    const chat = req.chat;

    if (chat.type === 'private') {
      return res.status(400).json({
        success: false,
        message: 'Cannot remove participants from private chat'
      });
    }

    if (!chat.hasParticipant(userId)) {
      return res.status(400).json({
        success: false,
        message: 'User is not a participant in this chat'
      });
    }

    // Get user info before removal
    const userToRemove = await User.findById(userId).select('name username');
    if (!userToRemove) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Remove participant
    await chat.removeParticipant(userId, req.user._id);

    // Create system message
    const systemMessage = new Message({
      chat: chat._id,
      sender: req.user._id,
      content: `${req.user.name} removed ${userToRemove.name} from the group`,
      type: 'system',
      systemData: {
        action: 'user_removed',
        targetUser: userId
      }
    });
    await systemMessage.save();

    logger.info(`Participant removed from chat: ${chat._id} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Participant removed successfully'
    });

  } catch (error) {
    logger.error('Remove participant error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove participant'
    });
  }
});

// @route   POST /api/chats/:id/leave
// @desc    Leave chat
// @access  Private
router.post('/:id/leave', canAccessChat, async (req, res) => {
  try {
    const chat = req.chat;

    if (chat.type === 'private') {
      return res.status(400).json({
        success: false,
        message: 'Cannot leave private chat. Archive it instead.'
      });
    }

    // Remove user from chat
    await chat.removeParticipant(req.user._id);

    // Create system message
    const systemMessage = new Message({
      chat: chat._id,
      sender: req.user._id,
      content: `${req.user.name} left the group`,
      type: 'system',
      systemData: {
        action: 'user_left',
        targetUser: req.user._id
      }
    });
    await systemMessage.save();

    logger.info(`User left chat: ${chat._id}, user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Left chat successfully'
    });

  } catch (error) {
    logger.error('Leave chat error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to leave chat'
    });
  }
});

// @route   POST /api/chats/:id/archive
// @desc    Archive/unarchive chat for user
// @access  Private
router.post('/:id/archive', canAccessChat, async (req, res) => {
  try {
    const chat = req.chat;
    const { archive = true } = req.body;

    if (archive) {
      await chat.archiveForUser(req.user._id);
    } else {
      await chat.unarchiveForUser(req.user._id);
    }

    logger.info(`Chat ${archive ? 'archived' : 'unarchived'}: ${chat._id} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: `Chat ${archive ? 'archived' : 'unarchived'} successfully`
    });

  } catch (error) {
    logger.error('Archive chat error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to archive chat'
    });
  }
});

// @route   PUT /api/chats/:id/settings
// @desc    Update user's chat settings
// @access  Private
router.put('/:id/settings', canAccessChat, [
  body('notifications')
    .optional()
    .isIn(['all', 'mentions', 'none'])
    .withMessage('Notifications must be all, mentions, or none'),
  
  body('customName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Custom name cannot exceed 50 characters'),
  
  body('isPinned')
    .optional()
    .isBoolean()
    .withMessage('isPinned must be a boolean'),
  
  body('isMuted')
    .optional()
    .isBoolean()
    .withMessage('isMuted must be a boolean')
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

    const { notifications, customName, isPinned, isMuted, muteUntil } = req.body;
    const chat = req.chat;

    // Find user's participant record
    const participantIndex = chat.participants.findIndex(p => 
      p.user.toString() === req.user._id.toString() && p.isActive
    );

    if (participantIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'User not found in chat participants'
      });
    }

    // Update settings
    if (notifications !== undefined) {
      chat.participants[participantIndex].notifications = notifications;
    }
    if (customName !== undefined) {
      chat.participants[participantIndex].customName = customName;
    }
    if (isPinned !== undefined) {
      chat.participants[participantIndex].isPinned = isPinned;
    }
    if (isMuted !== undefined) {
      chat.participants[participantIndex].isMuted = isMuted;
      if (isMuted && muteUntil) {
        chat.participants[participantIndex].muteUntil = new Date(muteUntil);
      } else if (!isMuted) {
        chat.participants[participantIndex].muteUntil = undefined;
      }
    }

    await chat.save();

    logger.info(`Chat settings updated: ${chat._id} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Chat settings updated successfully',
      settings: {
        notifications: chat.participants[participantIndex].notifications,
        customName: chat.participants[participantIndex].customName,
        isPinned: chat.participants[participantIndex].isPinned,
        isMuted: chat.participants[participantIndex].isMuted,
        muteUntil: chat.participants[participantIndex].muteUntil
      }
    });

  } catch (error) {
    logger.error('Update chat settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update chat settings'
    });
  }
});

// @route   POST /api/chats/:id/invite
// @desc    Generate invite link for group
// @access  Private
router.post('/:id/invite', canAccessChat, canModifyChat, async (req, res) => {
  try {
    const chat = req.chat;

    if (chat.type === 'private') {
      return res.status(400).json({
        success: false,
        message: 'Cannot create invite for private chat'
      });
    }

    const inviteCode = chat.generateInviteCode();
    await chat.save();

    const inviteLink = `${process.env.CLIENT_URL}/join/${inviteCode}`;

    logger.info(`Invite generated for chat: ${chat._id} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Invite link generated successfully',
      inviteCode,
      inviteLink,
      expiresAt: chat.inviteExpires
    });

  } catch (error) {
    logger.error('Generate invite error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate invite link'
    });
  }
});

// @route   POST /api/chats/join/:inviteCode
// @desc    Join chat using invite code
// @access  Private
router.post('/join/:inviteCode', async (req, res) => {
  try {
    const { inviteCode } = req.params;

    const chat = await Chat.findOne({
      inviteCode,
      inviteExpires: { $gt: new Date() }
    });

    if (!chat) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or expired invite link'
      });
    }

    if (chat.hasParticipant(req.user._id)) {
      return res.status(400).json({
        success: false,
        message: 'You are already a member of this chat'
      });
    }

    // Add user to chat
    await chat.addParticipant(req.user._id, 'member');

    // Create system message
    const systemMessage = new Message({
      chat: chat._id,
      sender: req.user._id,
      content: `${req.user.name} joined the group via invite link`,
      type: 'system',
      systemData: {
        action: 'user_joined'
      }
    });
    await systemMessage.save();

    logger.info(`User joined chat via invite: ${chat._id}, user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Joined chat successfully',
      chat: chat.getChatInfo(req.user._id)
    });

  } catch (error) {
    logger.error('Join chat error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to join chat'
    });
  }
});

// @route   DELETE /api/chats/:id
// @desc    Delete chat (admin only)
// @access  Private
router.delete('/:id', canAccessChat, canModifyChat, async (req, res) => {
  try {
    const chat = req.chat;

    // Delete all messages in the chat
    await Message.deleteMany({ chat: chat._id });

    // Delete the chat
    await Chat.findByIdAndDelete(chat._id);

    logger.info(`Chat deleted: ${chat._id} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Chat deleted successfully'
    });

  } catch (error) {
    logger.error('Delete chat error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete chat'
    });
  }
});

module.exports = router;