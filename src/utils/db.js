const mongoose = require('mongoose');

async function connectToDatabase() {
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/student_study_planner';
  mongoose.set('strictQuery', true);
  await mongoose.connect(mongoUri);
}

module.exports = { connectToDatabase };



