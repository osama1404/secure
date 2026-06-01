/**
 * CyberShield - Local MongoDB Database Inspector Utility
 * Run this in your terminal using: node view-database.js
 */

const { UserModel, SecurityLogModel, mongoose } = require('./database');
require('dotenv').config();

async function inspectDatabase() {
  console.log('\n============================================================');
  console.log(' 🔍 CYBERSHIELD LOCAL MONGODB INSPECTION TOOL ');
  console.log('============================================================');

  try {
    // 1. Retrieve all user credentials and notes
    const users = await UserModel.find({});
    console.log(`\n👥 REGISTERED USERS IN MONGODB (${users.length} found):`);
    console.log('------------------------------------------------------------');
    
    users.forEach((user, index) => {
      console.log(`[User #${index + 1}]`);
      console.log(`  Username:      ${user.username}`);
      console.log(`  Session Role:  ${user.role}`);
      console.log(`  2FA Enabled?:  ${user.twoFactorEnabled ? '🛡️ YES' : '❌ NO'}`);
      console.log(`  2FA Secret:    ${user.twoFactorSecret || '(None set)'}`);
      console.log(`  Personal Note Ciphertext (Stored at Rest):`);
      console.log(`    ${user.personalNote || '(Empty - No note saved)'}`);
      console.log('------------------------------------------------------------');
    });

    // 2. Retrieve recent security logs
    const logs = await SecurityLogModel.find({}).sort({ timestamp: -1 }).limit(5);
    console.log(`\n🚨 RECENT SECURITY AUDIT LOGS (Last 5 events):`);
    console.log('------------------------------------------------------------');
    
    logs.forEach((log) => {
      console.log(`[${new Date(log.timestamp).toLocaleString()}] [${log.eventType}]`);
      console.log(`  User:    @${log.username}`);
      console.log(`  IP:      ${log.ipAddress}`);
      console.log(`  Details: ${log.details}`);
      console.log('------------------------------------------------------------');
    });

  } catch (err) {
    console.error('❌ Database inspection failed:', err.message);
  } finally {
    // Disconnect connection
    await mongoose.disconnect();
    console.log('\n🔌 MongoDB connection closed successfully.');
    console.log('============================================================\n');
  }
}

inspectDatabase();
