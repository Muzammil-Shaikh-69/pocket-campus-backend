const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, required: true, trim: true },
    subject: { type: String, trim: true },
    description: { type: String, trim: true },
    priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium', index: true },
    deadline: { type: Date, index: true },
    status: { type: String, enum: ['pending', 'completed'], default: 'pending', index: true },
    subtasks: {
      type: [
        new mongoose.Schema(
          {
            title: { type: String, required: true, trim: true },
            done: { type: Boolean, default: false },
          },
          { _id: false }
        ),
      ],
      default: [],
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Task', taskSchema);



