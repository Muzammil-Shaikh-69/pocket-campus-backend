## Backend (Express + MongoDB)

### Prerequisites
- Node.js 18+
- MongoDB running locally or accessible via connection string

### Environment variables (`.env`)
Create `backend/.env` with:
```
MONGO_URI=mongodb://localhost:27017/student_study_planner
PORT=5001
JWT_SECRET=supersecretjwt
CLIENT_ORIGIN=http://localhost:5173
```

### Install & run
```bash
cd backend
npm install
npm run dev
```

### Project structure
```
src/
  controllers/
    authController.js   # register, login, me
    taskController.js   # list/create/update/delete, dashboardStats
  middleware/
    authMiddleware.js   # JWT verification
  models/
    User.js             # bcrypt pre-save, comparePassword
    Task.js             # task schema (title, subject, priority, deadline, status)
  routes/
    authRoutes.js       # /auth endpoints
    taskRoutes.js       # /tasks endpoints (protected)
  utils/
    db.js               # connectToDatabase()
  server.js             # express app bootstrap
```

### API endpoints
- `POST /auth/register` — body: `{ name, email, password }`
- `POST /auth/login` — body: `{ email, password }`
- `GET /auth/me` — header: `Authorization: Bearer <token>`
- `GET /tasks` — query: `subject, priority, status, sortBy=field:asc|desc`
- `POST /tasks` — body: `{ title, subject, description, priority, deadline, status }`
- `PUT /tasks/:id`
- `DELETE /tasks/:id`
- `GET /tasks/stats/dashboard`

All `/tasks` routes require `Authorization: Bearer <token>`.

### Notes
- `helmet`, `cors`, `morgan`, `cookie-parser` configured in `server.js`
- Default CORS origin: `CLIENT_ORIGIN`
- JWT expiry: 7 days


