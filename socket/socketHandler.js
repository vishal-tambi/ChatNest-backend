// socket/socketHandler.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Chat = require('../models/Chat');
const Message = require('../models/Message');
const logger = require('../utils/logger');

// Store active users and their rooms
const activeUsers = new Map(); // userId -> { socketId, rooms: Set }
const typingUsers = new Map(); // chatId -> Set of userIds

const socketHandler = (io) => {
  // Authentication middleware for socket connections
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token;
      
      if (!token) {
        return next(new Error('Authentication error: No token provided'));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select('-password');
      
      if (!user) {
        return next(new Error('Authentication error: User not found'));
      }

      socket.userId = user._id.toString();
      socket.user = user;
      next();
    } catch (error) {
      logger.error('Socket authentication error:', error);
      next(new Error('Authentication error: Invalid token'));
    }
  });

  io.on('connection', async (socket) => {
    const userId = socket.userId;
    const user = socket.user;

    logger.info(`User connected: ${user.name} (${userId})`);

    try {
      // Update user online status
      await User.findByIdAndUpdate(userId, {
        isOnline: true,
        lastSeen: new Date()
      });

      // Store user connection
      activeUsers.set(userId, {
        socketId: socket.id,
        rooms: new Set()
      });

      // Join user to their chat rooms
      const userChats = await Chat.find({
        'participants.user': userId,
        'participants.isActive': true
      }).select('_id');

      for (const chat of userChats) {
        const roomId = chat._id.toString();
        socket.join(roomId);
        activeUsers.get(userId).rooms.add(roomId);
        
        // Notify other users in the room that this user is online
        socket.to(roomId).emit('user_online', {
          userId,
          user: {
            _id: user._id,
            name: user.name,
            username: user.username,
            avatar: user.avatar
          }
        });
      }

      // Send online users list to the connected user
      const onlineUsers = await getOnlineUsersForUser(userId);
      socket.emit('online_users', onlineUsers);

      // Handle joining a specific room
      socket.on('join_room', async (data) => {
        try {
          const { chatId } = data;
          
          // Verify user has access to this chat
          const chat = await Chat.findById(chatId);
          if (!chat || !chat.hasParticipant(userId)) {
            socket.emit('error', { message: 'Access denied to this chat' });
            return;
          }

          socket.join(chatId);
          activeUsers.get(userId).rooms.add(chatId);
          
          logger.info(`User ${userId} joined room ${chatId}`);
          
          // Mark messages as delivered
          await markMessagesAsDelivered(chatId, userId);
          
          socket.emit('joined_room', { chatId });
        } catch (error) {
          logger.error('Join room error:', error);
          socket.emit('error', { message: 'Failed to join room' });
        }
      });

      // Handle leaving a room
      socket.on('leave_room', (data) => {
        try {
          const { chatId } = data;
          socket.leave(chatId);
          activeUsers.get(userId).rooms.delete(chatId);
          
          // Stop typing if user was typing
          handleStopTyping(chatId, userId, socket);
          
          logger.info(`User ${userId} left room ${chatId}`);
          socket.emit('left_room', { chatId });
        } catch (error) {
          logger.error('Leave room error:', error);
        }
      });

      // Handle sending messages
      socket.on('send_message', async (data) => {
        try {
          const { chatId, content, type = 'text', replyTo, attachments } = data;
          
          // Verify chat access
          const chat = await Chat.findById(chatId);
          if (!chat || !chat.hasParticipant(userId)) {
            socket.emit('error', { message: 'Access denied to this chat' });
            return;
          }

          // Create message
          const message = new Message({
            chat: chatId,
            sender: userId,
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

          // Stop typing indicator
          handleStopTyping(chatId, userId, socket);

          // Mark as delivered for sender
          await message.markAsDelivered(userId);

          // Broadcast to all room members
          io.to(chatId).emit('receive_message', {
            message: message.toObject(),
            chatId
          });

          // Mark as delivered for online users in the room
          const roomMembers = io.sockets.adapter.rooms.get(chatId);
          if (roomMembers) {
            for (const socketId of roomMembers) {
              const memberSocket = io.sockets.sockets.get(socketId);
              if (memberSocket && memberSocket.userId !== userId) {
                await message.markAsDelivered(memberSocket.userId);
              }
            }
          }

          // Send push notifications to offline users
          await sendPushNotifications(chat, message, userId);

          logger.info(`Message sent: ${message._id} in chat: ${chatId}`);
        } catch (error) {
          logger.error('Send message error:', error);
          socket.emit('error', { message: 'Failed to send message' });
        }
      });

      // Handle message reactions
      socket.on('add_reaction', async (data) => {
        try {
          const { messageId, emoji } = data;
          
          const message = await Message.findById(messageId);
          if (!message) {
            socket.emit('error', { message: 'Message not found' });
            return;
          }

          // Verify user has access to the chat
          const chat = await Chat.findById(message.chat);
          if (!chat || !chat.hasParticipant(userId)) {
            socket.emit('error', { message: 'Access denied' });
            return;
          }

          await message.addReaction(userId, emoji);
          await message.populate('reactions.user', 'name username');

          // Broadcast reaction to room
          io.to(message.chat.toString()).emit('reaction_added', {
            messageId: message._id,
            reaction: {
              user: {
                _id: userId,
                name: user.name,
                username: user.username
              },
              emoji,
              createdAt: new Date()
            },
            reactionCounts: message.reactionCounts
          });

        } catch (error) {
          logger.error('Add reaction error:', error);
          socket.emit('error', { message: 'Failed to add reaction' });
        }
      });

      // Handle remove reaction
      socket.on('remove_reaction', async (data) => {
        try {
          const { messageId, emoji } = data;
          
          const message = await Message.findById(messageId);
          if (!message) return;

          const chat = await Chat.findById(message.chat);
          if (!chat || !chat.hasParticipant(userId)) return;

          await message.removeReaction(userId, emoji);

          io.to(message.chat.toString()).emit('reaction_removed', {
            messageId: message._id,
            userId,
            emoji,
            reactionCounts: message.reactionCounts
          });

        } catch (error) {
          logger.error('Remove reaction error:', error);
        }
      });

      // Handle typing indicators
      socket.on('typing', (data) => {
        try {
          const { chatId } = data;
          handleTyping(chatId, userId, user, socket);
        } catch (error) {
          logger.error('Typing error:', error);
        }
      });

      socket.on('stop_typing', (data) => {
        try {
          const { chatId } = data;
          handleStopTyping(chatId, userId, socket);
        } catch (error) {
          logger.error('Stop typing error:', error);
        }
      });

      // Handle message read status
      socket.on('mark_read', async (data) => {
        try {
          const { messageIds } = data;
          
          if (!Array.isArray(messageIds)) return;

          for (const messageId of messageIds) {
            const message = await Message.findById(messageId);
            if (message) {
              const chat = await Chat.findById(message.chat);
              if (chat && chat.hasParticipant(userId)) {
                await message.markAsRead(userId);
                
                // Notify sender about read status
                io.to(message.chat.toString()).emit('message_read', {
                  messageId: message._id,
                  readBy: userId,
                  readAt: new Date()
                });
              }
            }
          }
        } catch (error) {
          logger.error('Mark read error:', error);
        }
      });

      // Handle voice/video call events
      socket.on('initiate_call', async (data) => {
        try {
          const { chatId, type, offer } = data; // type: 'voice' or 'video'
          
          const chat = await Chat.findById(chatId);
          if (!chat || !chat.hasParticipant(userId)) {
            socket.emit('error', { message: 'Access denied' });
            return;
          }

          // For private chats, call the other participant
          if (chat.type === 'private') {
            const otherParticipant = chat.participants.find(p => 
              p.user.toString() !== userId && p.isActive
            );
            
            if (otherParticipant) {
              const otherUserSocket = getSocketByUserId(otherParticipant.user.toString());
              if (otherUserSocket) {
                otherUserSocket.emit('incoming_call', {
                  chatId,
                  type,
                  caller: {
                    _id: user._id,
                    name: user.name,
                    username: user.username,
                    avatar: user.avatar
                  },
                  offer
                });
              }
            }
          } else {
            // For group chats, notify all other participants
            socket.to(chatId).emit('incoming_call', {
              chatId,
              type,
              caller: {
                _id: user._id,
                name: user.name,
                username: user.username,
                avatar: user.avatar
              },
              offer
            });
          }

          // Create call message
          const callMessage = new Message({
            chat: chatId,
            sender: userId,
            content: `${type.charAt(0).toUpperCase() + type.slice(1)} call started`,
            type: 'call',
            callData: {
              type,
              status: 'initiated',
              participants: [{
                user: userId,
                joinedAt: new Date()
              }]
            }
          });
          await callMessage.save();

        } catch (error) {
          logger.error('Initiate call error:', error);
          socket.emit('error', { message: 'Failed to initiate call' });
        }
      });

      socket.on('call_response', (data) => {
        const { chatId, accepted, answer } = data;
        
        if (accepted) {
          socket.to(chatId).emit('call_accepted', {
            chatId,
            responder: userId,
            answer
          });
        } else {
          socket.to(chatId).emit('call_declined', {
            chatId,
            responder: userId
          });
        }
      });

      socket.on('call_ended', async (data) => {
        try {
          const { chatId, duration } = data;
          
          socket.to(chatId).emit('call_ended', {
            chatId,
            endedBy: userId,
            duration
          });

          // Update call message with duration
          const callMessage = await Message.findOne({
            chat: chatId,
            type: 'call',
            'callData.status': 'initiated'
          }).sort({ createdAt: -1 });

          if (callMessage) {
            callMessage.callData.status = 'completed';
            callMessage.callData.duration = duration;
            callMessage.content = `${callMessage.callData.type.charAt(0).toUpperCase() + callMessage.callData.type.slice(1)} call ended (${formatDuration(duration)})`;
            await callMessage.save();
          }

        } catch (error) {
          logger.error('Call ended error:', error);
        }
      });

      // WebRTC signaling
      socket.on('webrtc_signal', (data) => {
        const { chatId, signal, targetUserId } = data;
        
        if (targetUserId) {
          const targetSocket = getSocketByUserId(targetUserId);
          if (targetSocket) {
            targetSocket.emit('webrtc_signal', {
              signal,
              fromUserId: userId
            });
          }
        } else {
          socket.to(chatId).emit('webrtc_signal', {
            signal,
            fromUserId: userId
          });
        }
      });

      // Handle disconnect
      socket.on('disconnect', async () => {
        logger.info(`User disconnected: ${user.name} (${userId})`);
        
        try {
          // Update user offline status
          await User.findByIdAndUpdate(userId, {
            isOnline: false,
            lastSeen: new Date()
          });

          // Clear typing indicators
          const userRooms = activeUsers.get(userId)?.rooms || new Set();
          for (const roomId of userRooms) {
            handleStopTyping(roomId, userId, socket);
            
            // Notify room members that user went offline
            socket.to(roomId).emit('user_offline', {
              userId,
              lastSeen: new Date()
            });
          }

          // Remove user from active users
          activeUsers.delete(userId);

        } catch (error) {
          logger.error('Disconnect cleanup error:', error);
        }
      });

    } catch (error) {
      logger.error('Socket connection error:', error);
      socket.disconnect();
    }
  });

  // Helper functions
  function handleTyping(chatId, userId, user, socket) {
    if (!typingUsers.has(chatId)) {
      typingUsers.set(chatId, new Set());
    }
    
    const chatTypingUsers = typingUsers.get(chatId);
    if (!chatTypingUsers.has(userId)) {
      chatTypingUsers.add(userId);
      
      socket.to(chatId).emit('user_typing', {
        chatId,
        user: {
          _id: user._id,
          name: user.name,
          username: user.username,
          avatar: user.avatar
        }
      });
    }

    // Auto-clear typing after 3 seconds
    setTimeout(() => {
      handleStopTyping(chatId, userId, socket);
    }, 3000);
  }

  function handleStopTyping(chatId, userId, socket) {
    const chatTypingUsers = typingUsers.get(chatId);
    if (chatTypingUsers && chatTypingUsers.has(userId)) {
      chatTypingUsers.delete(userId);
      
      if (chatTypingUsers.size === 0) {
        typingUsers.delete(chatId);
      }
      
      socket.to(chatId).emit('user_stopped_typing', {
        chatId,
        userId
      });
    }
  }

  function getSocketByUserId(userId) {
    const userConnection = activeUsers.get(userId);
    if (userConnection) {
      return io.sockets.sockets.get(userConnection.socketId);
    }
    return null;
  }

  async function getOnlineUsersForUser(userId) {
    try {
      const userChats = await Chat.find({
        'participants.user': userId,
        'participants.isActive': true
      }).populate('participants.user', '_id name username avatar');

      const onlineUserIds = new Set();
      
      for (const chat of userChats) {
        for (const participant of chat.participants) {
          if (participant.isActive && 
              participant.user._id.toString() !== userId &&
              activeUsers.has(participant.user._id.toString())) {
            onlineUserIds.add(participant.user._id.toString());
          }
        }
      }

      return Array.from(onlineUserIds).map(id => {
        const chat = userChats.find(c => 
          c.participants.some(p => p.user._id.toString() === id)
        );
        const participant = chat.participants.find(p => p.user._id.toString() === id);
        return {
          _id: participant.user._id,
          name: participant.user.name,
          username: participant.user.username,
          avatar: participant.user.avatar
        };
      });
    } catch (error) {
      logger.error('Get online users error:', error);
      return [];
    }
  }

  async function markMessagesAsDelivered(chatId, userId) {
    try {
      const undeliveredMessages = await Message.find({
        chat: chatId,
        sender: { $ne: userId },
        'deliveredTo.user': { $ne: userId }
      });

      for (const message of undeliveredMessages) {
        await message.markAsDelivered(userId);
      }
    } catch (error) {
      logger.error('Mark delivered error:', error);
    }
  }

  async function sendPushNotifications(chat, message, senderId) {
    try {
      // Get offline participants
      const offlineParticipants = chat.participants.filter(p => 
        p.isActive && 
        p.user.toString() !== senderId &&
        !activeUsers.has(p.user.toString())
      );

      // TODO: Implement push notification service
      // This would integrate with Firebase Cloud Messaging, Apple Push Notifications, etc.
      
    } catch (error) {
      logger.error('Push notification error:', error);
    }
  }

  function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  }
};

module.exports = socketHandler;