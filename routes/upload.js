// routes/upload.js
const express = require('express');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { fileUploadRateLimit } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure multer for file uploads
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  // Allowed file types
  const allowedImageTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  const allowedDocTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain',
    'application/zip',
    'application/x-rar-compressed'
  ];
  const allowedAudioTypes = ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/m4a'];
  const allowedVideoTypes = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime'];

  const allAllowedTypes = [
    ...allowedImageTypes,
    ...allowedDocTypes,
    ...allowedAudioTypes,
    ...allowedVideoTypes
  ];

  if (allAllowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${file.mimetype} is not allowed`), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
    files: 5 // Maximum 5 files per request
  }
});

// Helper function to determine file category
const getFileCategory = (mimetype) => {
  if (mimetype.startsWith('image/')) return 'image';
  if (mimetype.startsWith('video/')) return 'video';
  if (mimetype.startsWith('audio/')) return 'audio';
  return 'document';
};

// Helper function to upload to Cloudinary
const uploadToCloudinary = (fileBuffer, options) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader.upload_stream(
      {
        ...options,
        resource_type: 'auto',
        quality: 'auto',
        fetch_format: 'auto'
      },
      (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result);
        }
      }
    ).end(fileBuffer);
  });
};

// @route   POST /api/upload/avatar
// @desc    Upload user avatar
// @access  Private
router.post('/avatar', fileUploadRateLimit, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const file = req.file;
    
    // Only allow images for avatars
    if (!file.mimetype.startsWith('image/')) {
      return res.status(400).json({
        success: false,
        message: 'Only image files are allowed for avatars'
      });
    }

    // Upload to Cloudinary
    const result = await uploadToCloudinary(file.buffer, {
      folder: 'chatnest/avatars',
      public_id: `avatar_${req.user._id}_${Date.now()}`,
      transformation: [
        { width: 500, height: 500, crop: 'fill', gravity: 'face' },
        { quality: 'auto' }
      ]
    });

    // Update user avatar in database
    const User = require('../models/User');
    const user = await User.findById(req.user._id);
    
    // Delete old avatar if exists
    if (user.avatar && user.avatar.public_id) {
      try {
        await cloudinary.uploader.destroy(user.avatar.public_id);
      } catch (error) {
        logger.warn('Failed to delete old avatar:', error);
      }
    }

    // Update user with new avatar
    user.avatar = {
      public_id: result.public_id,
      secure_url: result.secure_url
    };
    await user.save();

    logger.info(`Avatar uploaded for user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'Avatar uploaded successfully',
      avatar: {
        public_id: result.public_id,
        secure_url: result.secure_url
      }
    });

  } catch (error) {
    logger.error('Avatar upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload avatar'
    });
  }
});

// @route   POST /api/upload/chat/:chatId
// @desc    Upload files to chat
// @access  Private
router.post('/chat/:chatId', fileUploadRateLimit, upload.array('files', 5), async (req, res) => {
  try {
    const { chatId } = req.params;
    
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No files uploaded'
      });
    }

    // Verify chat access
    const Chat = require('../models/Chat');
    const chat = await Chat.findById(chatId);
    
    if (!chat || !chat.hasParticipant(req.user._id)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this chat'
      });
    }

    const uploadedFiles = [];
    const uploadPromises = req.files.map(async (file) => {
      try {
        const category = getFileCategory(file.mimetype);
        const folder = `chatnest/chats/${chatId}/${category}s`;
        
        const uploadOptions = {
          folder,
          public_id: `${category}_${Date.now()}_${Math.random().toString(36).substring(7)}`,
          resource_type: 'auto'
        };

        // Add transformations for images and videos
        if (category === 'image') {
          uploadOptions.transformation = [
            { width: 1920, height: 1080, crop: 'limit' },
            { quality: 'auto' }
          ];
        } else if (category === 'video') {
          uploadOptions.transformation = [
            { width: 1280, height: 720, crop: 'limit' },
            { quality: 'auto' }
          ];
        }

        const result = await uploadToCloudinary(file.buffer, uploadOptions);

        const fileData = {
          type: category,
          name: file.originalname,
          size: file.size,
          mimeType: file.mimetype,
          url: result.secure_url,
          publicId: result.public_id
        };

        // Add thumbnail for videos and additional metadata
        if (category === 'video') {
          fileData.thumbnailUrl = cloudinary.url(result.public_id, {
            resource_type: 'video',
            format: 'jpg',
            transformation: [
              { width: 300, height: 200, crop: 'fill' }
            ]
          });
          fileData.duration = result.duration;
        }

        if (category === 'image') {
          fileData.metadata = {
            width: result.width,
            height: result.height,
            format: result.format
          };
          
          // Create thumbnail for large images
          if (result.width > 500 || result.height > 500) {
            fileData.thumbnailUrl = cloudinary.url(result.public_id, {
              transformation: [
                { width: 300, height: 300, crop: 'fill' },
                { quality: 'auto' }
              ]
            });
          }
        }

        if (category === 'audio') {
          fileData.duration = result.duration;
        }

        uploadedFiles.push(fileData);
        return fileData;
      } catch (uploadError) {
        logger.error(`Upload error for file ${file.originalname}:`, uploadError);
        throw new Error(`Failed to upload ${file.originalname}: ${uploadError.message}`);
      }
    });

    const results = await Promise.allSettled(uploadPromises);
    
    // Check for failed uploads
    const failedUploads = results.filter(result => result.status === 'rejected');
    const successfulUploads = results
      .filter(result => result.status === 'fulfilled')
      .map(result => result.value);

    if (failedUploads.length > 0) {
      logger.warn(`${failedUploads.length} files failed to upload:`, failedUploads);
    }

    if (successfulUploads.length === 0) {
      return res.status(500).json({
        success: false,
        message: 'All file uploads failed',
        errors: failedUploads.map(f => f.reason.message)
      });
    }

    // Update chat metadata
    const totalSize = successfulUploads.reduce((acc, file) => acc + file.size, 0);
    await Chat.findByIdAndUpdate(chatId, {
      $inc: { 
        'metadata.mediaCount': successfulUploads.length,
        'metadata.totalSize': totalSize
      }
    });

    logger.info(`${successfulUploads.length} files uploaded to chat: ${chatId} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: `${successfulUploads.length} file(s) uploaded successfully`,
      files: successfulUploads,
      ...(failedUploads.length > 0 && {
        partialSuccess: true,
        failedCount: failedUploads.length,
        errors: failedUploads.map(f => f.reason.message)
      })
    });

  } catch (error) {
    logger.error('Chat file upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload files'
    });
  }
});

// @route   DELETE /api/upload/:publicId
// @desc    Delete uploaded file
// @access  Private
router.delete('/:publicId', async (req, res) => {
  try {
    const { publicId } = req.params;
    
    // Verify the file belongs to the user or they have permission to delete it
    // This would typically involve checking if the file is used in a message
    // the user sent or if they're an admin of the chat
    
    const Message = require('../models/Message');
    const message = await Message.findOne({
      'attachments.publicId': publicId,
      $or: [
        { sender: req.user._id },
        // Add admin check here if needed
      ]
    });

    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'File not found or access denied'
      });
    }

    // Delete from Cloudinary
    await cloudinary.uploader.destroy(publicId, { resource_type: 'auto' });

    // Remove from message attachments
    message.attachments = message.attachments.filter(
      attachment => attachment.publicId !== publicId
    );
    await message.save();

    logger.info(`File deleted: ${publicId} by user: ${req.user._id}`);

    res.json({
      success: true,
      message: 'File deleted successfully'
    });

  } catch (error) {
    logger.error('Delete file error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete file'
    });
  }
});

// @route   GET /api/upload/usage
// @desc    Get user's storage usage
// @access  Private
router.get('/usage', async (req, res) => {
  try {
    const Chat = require('../models/Chat');
    const Message = require('../models/Message');

    // Get user's chats
    const userChats = await Chat.find({
      'participants.user': req.user._id,
      'participants.isActive': true
    }).select('_id metadata');

    // Calculate total storage used
    let totalSize = 0;
    let mediaCount = 0;

    for (const chat of userChats) {
      totalSize += chat.metadata.totalSize || 0;
      mediaCount += chat.metadata.mediaCount || 0;
    }

    // Get user's messages with attachments
    const userMessages = await Message.find({
      sender: req.user._id,
      'attachments.0': { $exists: true }
    }).select('attachments');

    let userMediaSize = 0;
    let userMediaCount = 0;

    userMessages.forEach(message => {
      message.attachments.forEach(attachment => {
        userMediaSize += attachment.size || 0;
        userMediaCount++;
      });
    });

    const storageLimit = 5 * 1024 * 1024 * 1024; // 5GB limit per user
    const usagePercentage = (userMediaSize / storageLimit) * 100;

    res.json({
      success: true,
      usage: {
        totalSize: userMediaSize,
        mediaCount: userMediaCount,
        storageLimit,
        usagePercentage: Math.round(usagePercentage * 100) / 100,
        formattedSize: formatBytes(userMediaSize),
        formattedLimit: formatBytes(storageLimit)
      },
      chatStats: {
        totalChats: userChats.length,
        totalChatSize: totalSize,
        totalChatMedia: mediaCount
      }
    });

  } catch (error) {
    logger.error('Get storage usage error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get storage usage'
    });
  }
});

// Helper function to format bytes
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Error handling middleware for multer
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 50MB per file.'
      });
    } else if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Too many files. Maximum 5 files per upload.'
      });
    } else if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        message: 'Unexpected file field.'
      });
    }
  }
  
  if (error.message.includes('File type') && error.message.includes('not allowed')) {
    return res.status(400).json({
      success: false,
      message: error.message
    });
  }

  next(error);
});

module.exports = router;