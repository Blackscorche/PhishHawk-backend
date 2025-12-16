// Quick test script to verify .env file is being loaded correctly
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const envPath = path.join(__dirname, '.env');
console.log('Looking for .env at:', envPath);

const result = dotenv.config({ path: envPath });

if (result.error) {
  console.error('❌ Error loading .env file:', result.error.message);
  console.error('   Make sure .env file exists in:', __dirname);
  process.exit(1);
}

console.log('✓ .env file loaded successfully\n');

// Check for VIRUSTOTAL_API_KEY
const vtKey = process.env.VIRUSTOTAL_API_KEY;
if (vtKey) {
  console.log('✓ VIRUSTOTAL_API_KEY is set');
  console.log('  Length:', vtKey.length, 'characters');
  console.log('  First 4 chars:', vtKey.substring(0, 4) + '...');
  console.log('  Last 4 chars:', '...' + vtKey.substring(vtKey.length - 4));
  
  // Check for common issues
  if (vtKey.includes(' ')) {
    console.warn('  ⚠️  WARNING: Key contains spaces! Remove any spaces around the = sign');
  }
  if (vtKey.startsWith('"') || vtKey.startsWith("'")) {
    console.warn('  ⚠️  WARNING: Key is wrapped in quotes! Remove quotes from .env file');
  }
} else {
  console.error('❌ VIRUSTOTAL_API_KEY is NOT set');
  console.error('   Add this line to your .env file:');
  console.error('   VIRUSTOTAL_API_KEY=your_key_here');
  console.error('   (No spaces around the = sign, no quotes)');
}

// Check for URLHAUS_AUTH_KEY (optional)
const urlhausKey = process.env.URLHAUS_AUTH_KEY;
if (urlhausKey) {
  console.log('\n✓ URLHAUS_AUTH_KEY is set (optional)');
} else {
  console.log('\nℹ️  URLHAUS_AUTH_KEY is not set (optional, not required)');
}

// Check for MONGO_URI
const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;
if (mongoUri) {
  console.log('\n✓ MONGO_URI is set');
} else {
  console.log('\nℹ️  MONGO_URI is not set (optional if not using database)');
}

console.log('\n--- All environment variables ---');
console.log('VIRUSTOTAL_API_KEY:', vtKey ? 'SET' : 'NOT SET');
console.log('URLHAUS_AUTH_KEY:', urlhausKey ? 'SET' : 'NOT SET');
console.log('MONGO_URI:', mongoUri ? 'SET' : 'NOT SET');










