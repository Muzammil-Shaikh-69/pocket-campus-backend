const express = require('express');
const { authMiddleware } = require('../middleware/authMiddleware');
const { listTasks, createTask, updateTask, deleteTask, dashboardStats } = require('../controllers/taskController');
const Task = require('../models/Task');

const router = express.Router();

router.use(authMiddleware);

router.get('/', listTasks);
router.post('/', createTask);
router.put('/:id', updateTask);
router.delete('/:id', deleteTask);
router.get('/stats/dashboard', dashboardStats);

// subjects autocomplete
router.get('/meta/subjects', async (req, res) => {
  try {
    const subjects = await Task.distinct('subject', { user: req.user.id, subject: { $ne: null, $ne: '' } });
    res.json({ subjects });
  } catch (e) {
    res.status(500).json({ message: 'Failed to load subjects' });
  }
});

module.exports = router;



