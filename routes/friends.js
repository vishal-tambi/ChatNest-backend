// routes/friends.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const logger = require('../utils/logger');

const router = express.Router();

// @route   POST /api/friends/request
// @desc    Send friend request
// @access  Private
router.post('/request', [
  body('userId')
    .isMongoId()
    .withMessage('Invalid user ID')
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

    // Check if target user exists
    const targetUser = await User.findById(userId);
    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if already friends or request already sent
    const currentUser = await User.findById(req.user._id);
    const existingFriend = currentUser.friends.find(f => f.user.toString() === userId);
    const existingRequest = targetUser.friendRequests.find(r => r.from.toString() === req.user._id.toString());

    if (existingFriend) {
      return res.status(400).json({
        success: false,
        message: existingFriend.status === 'accepted' ? 'Already friends' : 'Friend request already sent'
      });
    }

    if (existingRequest) {
      return res.status(400).json({
        success: false,
        message: 'Friend request already sent'
      });
    }

    // Check if target user allows friend requests
    if (!targetUser.settings?.privacy?.allowFriendRequests) {
      return res.status(400).json({
        success: false,
        message: 'User is not accepting friend requests'
      });
    }

    // Add friend request to target user
    targetUser.friendRequests.push({
      from: req.user._id,
      sentAt: new Date()
    });

    // Add pending friend to current user
    currentUser.friends.push({
      user: userId,
      status: 'pending',
      addedAt: new Date()
    });

    await Promise.all([targetUser.save(), currentUser.save()]);

    logger.info(`Friend request sent from ${req.user._id} to ${userId}`);

    res.json({
      success: true,
      message: 'Friend request sent successfully'
    });

  } catch (error) {
    logger.error('Send friend request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send friend request'
    });
  }
});

// @route   POST /api/friends/accept
// @desc    Accept friend request
// @access  Private
router.post('/accept', [
  body('userId')
    .isMongoId()
    .withMessage('Invalid user ID')
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

    const currentUser = await User.findById(req.user._id);
    const requestingUser = await User.findById(userId);

    if (!requestingUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Find the friend request
    const requestIndex = currentUser.friendRequests.findIndex(r => r.from.toString() === userId);
    if (requestIndex === -1) {
      return res.status(400).json({
        success: false,
        message: 'No friend request found from this user'
      });
    }

    // Remove the friend request
    currentUser.friendRequests.splice(requestIndex, 1);

    // Add to friends list for both users
    currentUser.friends.push({
      user: userId,
      status: 'accepted',
      addedAt: new Date()
    });

    // Update the requesting user's friend status from pending to accepted
    const requestingUserFriend = requestingUser.friends.find(f => f.user.toString() === req.user._id.toString());
    if (requestingUserFriend) {
      requestingUserFriend.status = 'accepted';
      requestingUserFriend.addedAt = new Date();
    } else {
      requestingUser.friends.push({
        user: req.user._id,
        status: 'accepted',
        addedAt: new Date()
      });
    }

    await Promise.all([currentUser.save(), requestingUser.save()]);

    logger.info(`Friend request accepted: ${userId} and ${req.user._id} are now friends`);

    res.json({
      success: true,
      message: 'Friend request accepted'
    });

  } catch (error) {
    logger.error('Accept friend request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to accept friend request'
    });
  }
});

// @route   POST /api/friends/decline
// @desc    Decline friend request
// @access  Private
router.post('/decline', [
  body('userId')
    .isMongoId()
    .withMessage('Invalid user ID')
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

    const currentUser = await User.findById(req.user._id);
    const requestingUser = await User.findById(userId);

    if (!requestingUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Find and remove the friend request
    const requestIndex = currentUser.friendRequests.findIndex(r => r.from.toString() === userId);
    if (requestIndex === -1) {
      return res.status(400).json({
        success: false,
        message: 'No friend request found from this user'
      });
    }

    currentUser.friendRequests.splice(requestIndex, 1);

    // Remove pending friend from requesting user
    requestingUser.friends = requestingUser.friends.filter(f => f.user.toString() !== req.user._id.toString());

    await Promise.all([currentUser.save(), requestingUser.save()]);

    logger.info(`Friend request declined: ${req.user._id} declined ${userId}`);

    res.json({
      success: true,
      message: 'Friend request declined'
    });

  } catch (error) {
    logger.error('Decline friend request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to decline friend request'
    });
  }
});

// @route   GET /api/friends
// @desc    Get user's friends list
// @access  Private
router.get('/', async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate({
        path: 'friends.user',
        select: 'name username email avatar bio isOnline lastSeen status'
      })
      .lean();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const friends = user.friends
      .filter(f => f.status === 'accepted')
      .map(f => ({
        ...f.user,
        friendSince: f.addedAt,
        isOnline: f.user.isOnline || false
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
      message: 'Failed to get friends list'
    });
  }
});

// @route   GET /api/friends/requests
// @desc    Get pending friend requests
// @access  Private
router.get('/requests', async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate({
        path: 'friendRequests.from',
        select: 'name username email avatar bio isOnline lastSeen'
      })
      .lean();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const requests = user.friendRequests.map(r => ({
      ...r.from,
      requestSentAt: r.sentAt
    }));

    res.json({
      success: true,
      requests,
      total: requests.length
    });

  } catch (error) {
    logger.error('Get friend requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get friend requests'
    });
  }
});

module.exports = router;