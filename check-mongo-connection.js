/**
 * MongoDB Connection Diagnostic Script
 * Run this to test your MongoDB connection independently
 * Usage: node check-mongo-connection.js
 */

import dotenv from 'dotenv';
import mongoose from 'mongoose';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env file
const envPath = path.join(__dirname, '.env');
const envResult = dotenv.config({ path: envPath });

console.log('🔍 MongoDB Connection Diagnostic\n');
console.log('='.repeat(50));

// Check if .env file exists
if (envResult.error) {
  console.error('❌ .env file not found!');
  console.error(`   Expected location: ${envPath}`);
  console.error('\n📝 Please create a .env file with:');
  console.error('   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname');
  process.exit(1);
}

console.log('✅ .env file loaded\n');

// Check if MONGO_URI is set
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

if (!MONGO_URI) {
  console.error('❌ MONGO_URI not set in .env file');
  console.error('\n📝 Please add to your .env file:');
  console.error('   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname');
  process.exit(1);
}

// Mask password in URI for display
const maskedUri = MONGO_URI.replace(/:([^:@]+)@/, ':***@');
console.log(`📋 Connection String: ${maskedUri}\n`);

// Test connection
console.log('🔌 Attempting to connect to MongoDB...\n');

mongoose.connect(MONGO_URI, {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 30000,
  connectTimeoutMS: 10000
})
  .then(() => {
    console.log('✅ SUCCESS! MongoDB connection established');
    console.log(`   Database: ${mongoose.connection.db.databaseName}`);
    console.log(`   Host: ${mongoose.connection.host}`);
    console.log(`   Port: ${mongoose.connection.port || 'N/A (Atlas)'}`);
    console.log('\n🎉 Your MongoDB connection is working correctly!');
    process.exit(0);
  })
  .catch((err) => {
    console.error('❌ FAILED! MongoDB connection error\n');
    console.error(`   Error: ${err.message}\n`);
    
    // Provide helpful error messages
    if (err.message.includes('authentication failed')) {
      console.error('💡 Suggestion: Check your username and password');
      console.error('   - Verify credentials in MongoDB Atlas');
      console.error('   - Ensure password doesn\'t contain special characters (or URL-encode them)');
    } else if (err.message.includes('ENOTFOUND') || err.message.includes('getaddrinfo')) {
      console.error('💡 Suggestion: Check your MongoDB cluster hostname');
      console.error('   - Verify cluster is running in MongoDB Atlas');
      console.error('   - Check cluster connection string in Atlas dashboard');
    } else if (err.message.includes('timeout') || err.message.includes('serverSelectionTimeoutMS')) {
      console.error('💡 Suggestion: Network/IP whitelist issue');
      console.error('   - Check MongoDB Atlas Network Access settings');
      console.error('   - Add your IP address or use 0.0.0.0/0 for all IPs');
      console.error('   - Verify firewall isn\'t blocking MongoDB port');
    } else if (err.message.includes('bad auth')) {
      console.error('💡 Suggestion: Authentication failed');
      console.error('   - Check username/password in connection string');
      console.error('   - Verify database user exists in MongoDB Atlas');
    }
    
    console.error('\n📚 For more help, check:');
    console.error('   https://www.mongodb.com/docs/atlas/troubleshoot-connection/');
    
    process.exit(1);
  });

