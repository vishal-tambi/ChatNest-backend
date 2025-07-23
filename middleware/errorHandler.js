// middleware/errorHandler.js
const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log error
  logger.error(err.stack);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = {
      message,
      statusCode: 404
    };
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    let message = 'Duplicate field value entered';
    const field = Object.keys(err.keyValue)[0];
    
    if (field === 'email') {
      message = 'Email address is already registered';
    } else if (field === 'username') {
      message = 'Username is already taken';
    }
    
    error = {
      message,
      statusCode: 400,
      field
    };
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message).join(', ');
    error = {
      message,
      statusCode: 400,
      errors: Object.values(err.errors).map(val => ({
        field: val.path,
        message: val.message
      }))
    };
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = {
      message: 'Invalid token',
      statusCode: 401
    };
  }

  if (err.name === 'TokenExpiredError') {
    error = {
      message: 'Token expired',
      statusCode: 401
    };
  }

  // Multer errors (file upload)
  if (err.code === 'LIMIT_FILE_SIZE') {
    error = {
      message: 'File too large',
      statusCode: 400,
      maxSize: err.limit
    };
  }

  if (err.code === 'LIMIT_FILE_COUNT') {
    error = {
      message: 'Too many files',
      statusCode: 400,
      maxCount: err.limit
    };
  }

  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    error = {
      message: 'Unexpected file field',
      statusCode: 400,
      field: err.field
    };
  }

  // CORS errors
  if (err.message && err.message.includes('CORS')) {
    error = {
      message: 'Cross-Origin Request Blocked',
      statusCode: 403
    };
  }

  // Rate limiting errors
  if (err.status === 429) {
    error = {
      message: 'Too many requests',
      statusCode: 429,
      retryAfter: err.retryAfter
    };
  }

  // Database connection errors
  if (err.name === 'MongoNetworkError' || err.name === 'MongooseServerSelectionError') {
    error = {
      message: 'Database connection failed',
      statusCode: 503
    };
  }

  // Cloudinary errors
  if (err.name === 'CloudinaryError') {
    error = {
      message: 'File upload service error',
      statusCode: 500
    };
  }

  // Socket.IO errors
  if (err.type === 'SocketIOError') {
    error = {
      message: 'Real-time communication error',
      statusCode: 500
    };
  }

  const statusCode = error.statusCode || 500;
  const message = error.message || 'Server Error';

  const response = {
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack,
      originalError: err.name 
    })
  };

  // Add additional error details if available
  if (error.errors) response.errors = error.errors;
  if (error.field) response.field = error.field;
  if (error.retryAfter) response.retryAfter = error.retryAfter;
  if (error.maxSize) response.maxSize = error.maxSize;
  if (error.maxCount) response.maxCount = error.maxCount;

  res.status(statusCode).json(response);
};

module.exports = errorHandler;