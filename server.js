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
// Note: Adding database name 'phishhawk' - MongoDB will create it if it doesn't exist
const DEFAULT_MONGO_URI = "mongodb+srv://bitoscorche_db_user:Chawai2005@cluster0.7laevnb.mongodb.net/phishhawk?appName=Cluster0";



const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || DEFAULT_MONGO_URI;

// MongoDB Connection with retry logic
const connectDB = async (retryCount = 0) => {
  const maxRetries = 3;
  const retryDelay = 5000; // 5 seconds

  try {
    // Log connection attempt (hide password in logs)
    const safeUri = MONGO_URI.replace(/:[^:@]+@/, ':****@');
    if (retryCount === 0) {
      logger.info(`🔌 Attempting to connect to MongoDB: ${safeUri}`);
    } else {
      logger.info(`🔄 Retrying MongoDB connection (attempt ${retryCount + 1}/${maxRetries}): ${safeUri}`);
    }

    if (MONGO_URI.includes('localhost:27017')) {
      logger.warn('⚠️  Using default localhost MongoDB URI');
      logger.warn('💡 Set MONGO_URI in .env file for online MongoDB (MongoDB Atlas)');
    }

    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 10000, // 10 seconds timeout - fail faster
      socketTimeoutMS: 45000,
      connectTimeoutMS: 10000,
      retryWrites: true,
      w: 'majority',
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

    // IP Whitelist errors (most common issue)
    if (err.message.includes('IP') && err.message.includes('whitelist')) {
      logger.error('🚫 IP WHITELIST ERROR - Your IP address is not whitelisted in MongoDB Atlas');
      logger.warn('📋 To fix this:');
      logger.warn('   1. Go to MongoDB Atlas Dashboard: https://cloud.mongodb.com/');
      logger.warn('   2. Navigate to: Network Access (or IP Access List)');
      logger.warn('   3. Click "Add IP Address"');
      logger.warn('   4. Choose one of these options:');
      logger.warn('      - Click "Add Current IP Address" (recommended for development)');
      logger.warn('      - OR add "0.0.0.0/0" to allow all IPs (less secure, but works everywhere)');
      logger.warn('   5. Wait 1-2 minutes for changes to propagate');
      logger.warn('   6. Restart your server');
      logger.warn('');
      logger.warn('   ⚠️  Note: If you\'re on a dynamic IP, consider using 0.0.0.0/0 for development');
      logger.warn('');
      logger.warn('   🔍 If IP is already whitelisted, check:');
      logger.warn('      - Is the MongoDB Atlas cluster running (not paused)?');
      logger.warn('      - Are the username/password correct in Database Access?');
      logger.warn('      - Try copying the connection string directly from Atlas (Connect button)');
    }

    // More specific error messages
    if (err.message.includes('timeout') || err.name === 'MongooseServerSelectionError') {
      if (!err.message.includes('IP') || !err.message.includes('whitelist')) {
        logger.warn('⚠️  Connection timeout - Possible causes:');
        logger.warn('   1. MongoDB Atlas cluster might be paused - Check cluster status in Atlas dashboard');
        logger.warn('   2. Network/firewall blocking connection');
        logger.warn('   3. DNS resolution issue - Try pinging cluster0.7laevnb.mongodb.net');
        logger.warn('   4. IP whitelist might need a few minutes to propagate');
        logger.warn('   5. Incorrect username/password - Verify credentials in MongoDB Atlas');
        logger.warn('   💡 Quick check: Go to MongoDB Atlas -> Database Access -> Verify user exists and password is correct');
      } else {
        // IP whitelist error but user says it's configured - check other issues
        logger.warn('🔍 IP whitelist appears configured, but connection still failing. Check:');
        logger.warn('   1. Is MongoDB Atlas cluster running? (Go to Clusters -> Check status)');
        logger.warn('   2. Verify username/password in Database Access matches connection string');
        logger.warn('   3. Try getting a fresh connection string from Atlas (Connect -> Drivers -> Copy)');
        logger.warn('   4. Check if your network/firewall is blocking MongoDB ports');
        logger.warn('   5. Wait 2-3 minutes after IP whitelist changes (propagation delay)');
      }
    }

    // Authentication errors
    if (err.message.includes('authentication') || err.code === 8000 || err.codeName === 'AuthenticationFailed') {
      logger.warn('⚠️  Authentication failed - Possible causes:');
      logger.warn('   1. Incorrect username or password in connection string');
      logger.warn('   2. User might not exist in MongoDB Atlas');
      logger.warn('   3. User might not have proper permissions');
      logger.warn('   💡 Go to MongoDB Atlas -> Database Access -> Check user credentials');
    }

    if (err.code === 'ESERVFAIL' || err.message.includes('ESERVFAIL')) {
      logger.warn('⚠️  DNS Resolution Failed (ESERVFAIL) - Possible causes:');
      logger.warn('   1. MongoDB Atlas cluster might be paused or deleted - Check cluster status');
      logger.warn('   2. Cluster hostname might be incorrect - Verify in Atlas dashboard');
      logger.warn('   3. DNS server issue - Try using a different DNS (8.8.8.8)');
      logger.warn('   4. The cluster might need to be resumed if it was paused');
      logger.warn('   💡 Go to MongoDB Atlas -> Clusters -> Check if cluster shows "Paused"');
    }

    // Connection reset errors
    if (err.message.includes('ECONNRESET') || err.message.includes('connection reset')) {
      logger.warn('⚠️  Connection Reset (ECONNRESET) - Possible causes:');
      logger.warn('   1. MongoDB Atlas cluster might be paused - Check cluster status in Atlas dashboard');
      logger.warn('   2. Network instability or firewall blocking connection');
      logger.warn('   3. Connection string might be missing database name (should include /phishhawk)');
      logger.warn('   4. IP whitelist might need updating - Check Network Access in Atlas');
      logger.warn('   💡 Verify connection string format: mongodb+srv://user:pass@cluster.mongodb.net/dbname');
    }

    // Retry logic for connection errors
    if (retryCount < maxRetries && (
      err.message.includes('timeout') ||
      err.message.includes('ECONNRESET') ||
      err.name === 'MongooseServerSelectionError' ||
      err.code === 'ESERVFAIL'
    )) {
      logger.warn(`⏳ Retrying connection in ${retryDelay / 1000} seconds...`);
      setTimeout(() => {
        connectDB(retryCount + 1);
      }, retryDelay);
      return;
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
mongoose.connection.on('connecting', () => {
  logger.info('🔄 Connecting to MongoDB...');
});

mongoose.connection.on('connected', () => {
  logger.info('✅ MongoDB connected successfully');
  logger.info(`📦 Database: ${mongoose.connection.name || 'default'}`);
  logger.info(`🔗 Host: ${mongoose.connection.host}:${mongoose.connection.port || 'N/A'}`);
});

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

// Database diagnostic endpoint
app.get('/api/db-diagnostic', (req, res) => {
  const connectionState = mongoose.connection.readyState;
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };

  const safeUri = MONGO_URI.replace(/:[^:@]+@/, ':****@');
  const uriParts = MONGO_URI.match(/mongodb\+srv:\/\/([^:]+):([^@]+)@([^/]+)\/([^?]+)/);

  res.json({
    connectionState: states[connectionState] || 'unknown',
    connectionStateCode: connectionState,
    connectionString: safeUri,
    parsed: {
      username: uriParts ? uriParts[1] : 'unknown',
      host: uriParts ? uriParts[3] : 'unknown',
      database: uriParts ? uriParts[4] : 'unknown',
      hasPassword: uriParts ? (uriParts[2] ? 'yes' : 'no') : 'unknown'
    },
    troubleshooting: {
      ipWhitelist: 'Check MongoDB Atlas -> Network Access -> Verify your IP is listed',
      clusterStatus: 'Check MongoDB Atlas -> Clusters -> Ensure cluster is running (not paused)',
      credentials: 'Check MongoDB Atlas -> Database Access -> Verify username/password match',
      connectionString: 'Try getting a fresh connection string from Atlas (Connect -> Drivers)',
      network: 'Check if firewall/antivirus is blocking MongoDB connections'
    },
    nextSteps: connectionState !== 1 ? [
      '1. Verify MongoDB Atlas cluster is running (not paused)',
      '2. Check Database Access -> Verify user exists and password is correct',
      '3. Get a fresh connection string from Atlas (Connect -> Drivers -> Node.js)',
      '4. Wait 2-3 minutes after any changes for propagation',
      '5. Check Network Access -> Ensure IP whitelist includes your IP or 0.0.0.0/0'
    ] : ['Database is connected!']
  });
});

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
  logger.info(`🚀 PhishHawk API Server running on port ${PORT}`);
  logger.info(`📊 Health check available at http://localhost:${PORT}/health`);
  const safeUri = MONGO_URI.replace(/:[^:@]+@/, ':****@');
  logger.info(`🗄️ Database: ${safeUri}`);
});

export default app;