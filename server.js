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

// Log environment variables status (without showing values)
logger.info('Environment variables status:');
const vtKey = process.env.VIRUSTOTAL_API_KEY;
const urlhausKey = process.env.URLHAUS_AUTH_KEY;
const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;

logger.info(`  VIRUSTOTAL_API_KEY: ${vtKey ? `✓ Set (${vtKey.length} characters)` : '✗ Not set'}`);
if (!vtKey) {
  logger.warn('     → Add this line to .env: VIRUSTOTAL_API_KEY=your_api_key_here');
  logger.warn('     → Get your key from: https://www.virustotal.com/gui/join-us');
}

logger.info(`  URLHAUS_AUTH_KEY: ${urlhausKey ? `✓ Set (${urlhausKey.length} characters)` : '✗ Not set (optional)'}`);
if (!urlhausKey) {
  logger.info('     → Optional: Get from https://auth.abuse.ch/ for higher rate limits');
}

logger.info(`  MONGO_URI: ${mongoUri ? '✓ Set' : '✗ Not set'}`);

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Atlas connection string
// Using the exact format from MongoDB Atlas connection string
// If this doesn't work, verify the cluster is running and the hostname is correct
const DEFAULT_MONGO_URI = 'mongodb+srv://bitoscorche_db_user:bitoscorche_db_user@cluster0.7laevnb.mongodb.net/phishhawk?retryWrites=true&w=majority&appName=Cluster0';



const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || DEFAULT_MONGO_URI;

// MongoDB Connection with retry logic
const connectDB = async () => {
  try {
    // Log connection attempt (hide password in logs)
    const safeUri = MONGO_URI.replace(/:[^:@]+@/, ':****@');
    logger.info(`🔌 Attempting to connect to MongoDB: ${safeUri}`);

    if (MONGO_URI.includes('localhost:27017')) {
      logger.warn('⚠️  Using default localhost MongoDB URI');
      logger.warn('💡 Set MONGO_URI in .env file for online MongoDB (MongoDB Atlas)');
    }

    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 10000,
      maxPoolSize: 10,
      minPoolSize: 1
    });

    logger.info('✅ Connected to MongoDB');
    logger.info(`📦 Database: ${mongoose.connection.name}`);
  } catch (err) {
    logger.error('❌ MongoDB connection error:', err.message);
    logger.error('❌ Error details:', {
      name: err.name,
      code: err.code,
      message: err.message
    });

    // More specific error messages
    if (err.message.includes('timeout') || err.name === 'MongooseServerSelectionError') {
      logger.warn('⚠️  Connection timeout - Possible causes:');
      logger.warn('   1. MongoDB Atlas cluster might be paused - Check cluster status in Atlas dashboard');
      logger.warn('   2. Network/firewall blocking connection');
      logger.warn('   3. DNS resolution issue - Try pinging cluster0.7laevnb.mongodb.net');
      logger.warn('   4. IP whitelist might need a few minutes to propagate');
    }

    if (err.code === 'ESERVFAIL' || err.message.includes('ESERVFAIL')) {
      logger.warn('⚠️  DNS Resolution Failed (ESERVFAIL) - Possible causes:');
      logger.warn('   1. MongoDB Atlas cluster might be paused or deleted - Check cluster status');
      logger.warn('   2. Cluster hostname might be incorrect - Verify in Atlas dashboard');
      logger.warn('   3. DNS server issue - Try using a different DNS (8.8.8.8)');
      logger.warn('   4. The cluster might need to be resumed if it was paused');
      logger.warn('   💡 Go to MongoDB Atlas -> Clusters -> Check if cluster shows "Paused"');
    }

    logger.warn('⚠️  Server will continue running, but database features will be unavailable');
    logger.warn('💡 To fix:');
    logger.warn('   1. Check your MONGO_URI in .env file');
    logger.warn('   2. For MongoDB Atlas: Ensure your IP is whitelisted (you have 0.0.0.0/0 which should work)');
    logger.warn('   3. Verify your connection string format: mongodb+srv://user:pass@cluster.mongodb.net/dbname');
    logger.warn('   4. Check if your MongoDB Atlas cluster is running (not paused)');
    // Don't exit - allow server to run without DB for testing
  }
};

// Handle MongoDB connection events
mongoose.connection.on('disconnected', () => {
  logger.warn('⚠️  MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  logger.info('✅ MongoDB reconnected');
});

mongoose.connection.on('error', (err) => {
  logger.error('❌ MongoDB connection error event:', err.message);
});

// Set buffer commands to false globally to prevent buffering when disconnected
mongoose.set('bufferCommands', false);
mongoose.set('strictQuery', false);

// Connect to database
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

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// API Routes
app.use('/api/phishing', phishingRoutes);
app.use('/api/scraping', scrapingRoutes);

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
  logger.info(`🚀 PhishHawk API Server running on port ${PORT}`);
  logger.info(`📊 Health check available at http://localhost:${PORT}/health`);
  const safeUri = MONGO_URI.replace(/:[^:@]+@/, ':****@');
  logger.info(`🗄️ Database: ${safeUri}`);
});

export default app;