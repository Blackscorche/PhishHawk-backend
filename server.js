import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import phishingRoutes from './routes/phishingRoutes.js';
import scrapingRoutes from './routes/scrapingRoutes.js';
import { logger } from './utils/logger.js';

// Get directory name for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env file from the backend directory
const envPath = path.join(__dirname, '.env');
const envResult = dotenv.config({ path: envPath });

// Check if .env file was loaded
if (envResult.error) {
  logger.warn('⚠️  Could not load .env file:', envResult.error.message);
  logger.warn(`   Looking for .env at: ${envPath}`);
  logger.warn('   Make sure .env file exists in PhishHawk-backend directory');
} else {
  logger.info('✓ .env file loaded successfully');
}

// Minimal env validation
const vtKey = process.env.VIRUSTOTAL_API_KEY;
if (!vtKey) {
  logger.warn('⚠️  VIRUSTOTAL_API_KEY not set - VirusTotal features disabled');
}

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB connection string is provided ONLY via environment variables
// Set MONGO_URI (or MONGODB_URI) in .env – do NOT hardcode credentials here
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

// MongoDB connection (modern, minimal, low-noise)
let mongoErrorLogged = false;
let isConnecting = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 5000; // 5 seconds

const connectDB = async (retryCount = 0) => {
  // Prevent multiple simultaneous connection attempts
  if (isConnecting) {
    return mongoose.connection.readyState === 1;
  }

  // Already connected
  if (mongoose.connection.readyState === 1) {
    return true;
  }

  if (!MONGO_URI) {
    if (!mongoErrorLogged) {
      logger.error('❌ MongoDB connection string not set. Define MONGO_URI in your .env file.');
      logger.error('   Example: MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname');
      mongoErrorLogged = true;
    }
    return false;
  }

  isConnecting = true;

  try {
    if (retryCount === 0) {
      logger.info('🔌 Connecting to MongoDB...');
    } else {
      logger.info(`🔄 Retrying MongoDB connection (attempt ${retryCount + 1})...`);
    }

    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 30000,
      connectTimeoutMS: 10000,
      maxPoolSize: 10
    });

    logger.info('✅ MongoDB connected successfully');
    mongoErrorLogged = false;
    reconnectAttempts = 0;
    isConnecting = false;
    return true;
  } catch (err) {
    isConnecting = false;
    reconnectAttempts++;

    // Log error details (only once or on final attempt)
    if (!mongoErrorLogged || retryCount >= MAX_RECONNECT_ATTEMPTS) {
      logger.error('❌ MongoDB connection failed');
      logger.error(`   Error: ${err.message}`);

      // Provide helpful error messages
      if (err.message.includes('authentication failed')) {
        logger.error('   → Check your username and password in MONGO_URI');
      } else if (err.message.includes('ENOTFOUND') || err.message.includes('getaddrinfo')) {
        logger.error('   → Check your MongoDB cluster hostname');
      } else if (err.message.includes('timeout')) {
        logger.error('   → Check your network connection and MongoDB Atlas IP whitelist');
        logger.error('   → Ensure your IP is whitelisted or use 0.0.0.0/0 for all IPs');
      }

      mongoErrorLogged = true;
    }

    // Auto-reconnect logic (up to MAX_RECONNECT_ATTEMPTS)
    if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      setTimeout(() => {
        connectDB(retryCount + 1);
      }, RECONNECT_DELAY);
    } else {
      logger.error(`   → Stopped retrying after ${MAX_RECONNECT_ATTEMPTS} attempts`);
      logger.error('   → Server will continue running but database features are disabled');
      logger.error('   → Fix the connection issue and restart the server');
    }

    return false;
  }
};

// Global mongoose options
mongoose.set('bufferCommands', false);
mongoose.set('strictQuery', false);

// Connection event handlers
mongoose.connection.on('connected', () => {
  logger.info('✅ MongoDB connection established');
  reconnectAttempts = 0;
  mongoErrorLogged = false;
});

mongoose.connection.on('disconnected', () => {
  logger.warn('⚠️  MongoDB disconnected - attempting to reconnect...');
  mongoErrorLogged = false; // Reset to allow new error messages
  // Attempt to reconnect after a delay
  setTimeout(() => {
    if (mongoose.connection.readyState === 0) {
      connectDB();
    }
  }, RECONNECT_DELAY);
});

mongoose.connection.on('error', (err) => {
  if (!mongoErrorLogged) {
    logger.error('❌ MongoDB connection error:', err.message);
    mongoErrorLogged = true;
  }
});

mongoose.connection.on('reconnected', () => {
  logger.info('✅ MongoDB reconnected');
  reconnectAttempts = 0;
});

// Kick off initial connection (non-blocking)
connectDB();

// Middleware
app.use(helmet());

// CORS configuration - allow both Vercel production and localhost for development
const allowedOrigins = [
  'https://phish-hawk.vercel.app',
  'http://localhost:5173',
  process.env.FRONTEND_URL
].filter(Boolean); // Remove any undefined values

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      // In development, allow localhost with any port
      if (process.env.NODE_ENV !== 'production' && origin.startsWith('http://localhost:')) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// API Routes
app.use('/api/phishing', phishingRoutes);
app.use('/api/scraping', scrapingRoutes);
// Aliases for compatibility
app.use('/api/collector', scrapingRoutes);
app.use('/api/reports', phishingRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

app.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT}`);
});

export default app;