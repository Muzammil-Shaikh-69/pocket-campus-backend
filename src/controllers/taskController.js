const Task = require('../models/Task');

async function listTasks(req, res) {
  try {
    const { subject, priority, status, sortBy } = req.query;
    const filter = { user: req.user.id };
    if (subject) filter.subject = { $regex: subject, $options: 'i' }; // case-insensitive contains match
    if (priority) filter.priority = priority;
    if (status) filter.status = status;

    const sort = {};
    if (sortBy) {
      const [field, order] = sortBy.split(':');
      sort[field] = order === 'desc' ? -1 : 1;
    } else {
      sort.createdAt = -1;
    }

    const tasks = await Task.find(filter).sort(sort);
    res.json({ tasks });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch tasks' });
  }
}

async function createTask(req, res) {
  try {
    const { title, subject, description, priority, deadline, status, subtasks } = req.body;
    if (!title) return res.status(400).json({ message: 'Title is required' });
    const task = await Task.create({
      user: req.user.id,
      title,
      subject,
      description,
      priority,
      deadline,
      status,
      subtasks,
    });
    res.status(201).json({ task });
  } catch (err) {
    res.status(500).json({ message: 'Failed to create task' });
  }
}

async function updateTask(req, res) {
  try {
    const { id } = req.params;
    const updates = req.body;
    const task = await Task.findOneAndUpdate({ _id: id, user: req.user.id }, updates, {
      new: true,
      runValidators: true,
    });
    if (!task) return res.status(404).json({ message: 'Task not found' });
    res.json({ task });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update task' });
  }
}

async function deleteTask(req, res) {
  try {
    const { id } = req.params;
    const deleted = await Task.findOneAndDelete({ _id: id, user: req.user.id });
    if (!deleted) return res.status(404).json({ message: 'Task not found' });
    res.json({ message: 'Task deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete task' });
  }
}

async function dashboardStats(req, res) {
  try {
    const userId = req.user.id;
    const { subject, priority, status, q, from, to } = req.query;

    const baseFilter = { user: userId };
    if (subject) baseFilter.subject = { $regex: subject, $options: 'i' };
    if (priority) baseFilter.priority = priority;
    if (status) baseFilter.status = status;
    if (q) {
      baseFilter.$or = [
        { title: { $regex: q, $options: 'i' } },
        { description: { $regex: q, $options: 'i' } },
        { subject: { $regex: q, $options: 'i' } },
      ];
    }

    const dateFilter = {};
    if (from) dateFilter.$gte = new Date(from);
    if (to) dateFilter.$lte = new Date(to);
    if (from || to) baseFilter.createdAt = dateFilter;

    const [total, completed, pending, upcoming] = await Promise.all([
      Task.countDocuments(baseFilter),
      Task.countDocuments({ ...baseFilter, status: 'completed' }),
      Task.countDocuments({ ...baseFilter, status: 'pending' }),
      Task.find({ ...baseFilter, deadline: { $gte: new Date() } })
        .sort({ deadline: 1 })
        .limit(5),
    ]);
    res.json({ total, completed, pending, upcoming });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch stats' });
  }
}

module.exports = { listTasks, createTask, updateTask, deleteTask, dashboardStats };
// add subjects export later



