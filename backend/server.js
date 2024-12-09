const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const app = express();
const cors = require("cors");

app.use(express.json());
app.use(cors());

const PORT = 3000;
const JWT_SECRET = "your_jwt_secret";

let db = null;

// Initialize DB
const initializeDB = async () => {
  db = await open({
    filename: "./tasks.db",
    driver: sqlite3.Database,
  });

  // Create tables if not exists
  await db.run(`
    CREATE TABLE IF NOT EXISTS user (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      name TEXT,
      password TEXT,
      gender TEXT,
      location TEXT
    )`);
  await db.run(`
    CREATE TABLE IF NOT EXISTS task (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT,
      description TEXT,
      status TEXT,
      FOREIGN KEY (user_id) REFERENCES user (id)
    )`);
};

// Authentication Middleware
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return response.status(401).send("Access Denied!");

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return response.status(403).send("Invalid Token!");
    request.user = user;
    next();
  });
};

// Register User
app.post("/users", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`;
  const dbUser = await db.get(selectUserQuery, [username]);

  if (dbUser === undefined) {
    const createUserQuery = `
      INSERT INTO 
        user (username, name, password, gender, location) 
      VALUES (?, ?, ?, ?, ?)`;
    await db.run(createUserQuery, [username, name, hashedPassword, gender, location]);
    response.send("User created successfully!");
  } else {
    response.status(400).send("User already exists!");
  }
});

// Login User
app.post("/login", async (request, response) => {
  const { username, password } = request.body;

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`;
  const dbUser = await db.get(selectUserQuery, [username]);

  if (dbUser === undefined) {
    response.status(400).send("Invalid User");
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched) {
      const token = jwt.sign({ userId: dbUser.id }, JWT_SECRET, { expiresIn: "1h" });
      response.send({ token });
    } else {
      response.status(400).send("Invalid Password");
    }
  }
});

// Fetch Tasks
app.get("/api/tasks", authenticateToken, async (request, response) => {
  const { userId } = request.user;
  const tasksQuery = `SELECT * FROM task WHERE user_id = ?`;
  const tasks = await db.all(tasksQuery, [userId]);
  response.send(tasks);
});

// Create Task
app.post("/api/tasks", authenticateToken, async (request, response) => {
  const { userId } = request.user;
  const { title, description, status } = request.body;

  const createTaskQuery = `
    INSERT INTO task (user_id, title, description, status) 
    VALUES (?, ?, ?, ?)`;
  await db.run(createTaskQuery, [userId, title, description, status]);
  response.send("Task added successfully!");
});

// Update Task
app.put("/api/tasks/:id", authenticateToken, async (request, response) => {
  const { userId } = request.user;
  const { id } = request.params;
  const { title, description, status } = request.body;

  const updateTaskQuery = `
    UPDATE task 
    SET title = ?, description = ?, status = ? 
    WHERE id = ? AND user_id = ?`;
  const result = await db.run(updateTaskQuery, [title, description, status, id, userId]);
  if (result.changes > 0) {
    response.send("Task updated successfully!");
  } else {
    response.status(404).send("Task not found!");
  }
});

// Delete Task
app.delete("/api/tasks/:id", authenticateToken, async (request, response) => {
  const { userId } = request.user;
  const { id } = request.params;

  const deleteTaskQuery = `DELETE FROM task WHERE id = ? AND user_id = ?`;
  const result = await db.run(deleteTaskQuery, [id, userId]);
  if (result.changes > 0) {
    response.send("Task deleted successfully!");
  } else {
    response.status(404).send("Task not found!");
  }
});

// Start Server
app.listen(PORT, async () => {
  await initializeDB();
  console.log(`Server is running on http://localhost:${PORT}`);
});
