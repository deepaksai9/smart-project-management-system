require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dns = require('dns');

// ======================================================
// DNS
// ======================================================

dns.setServers(['1.1.1.1', '8.8.8.8']);

// ======================================================
// APP
// ======================================================

const app = express();

app.use(express.json());

app.use(cors({
  origin: true,
  credentials: true
}));

// ======================================================
// ENVIRONMENT VARIABLES
// ======================================================

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5000;

if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI environment variable is missing.");
}

if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET environment variable is missing.");
}

// ======================================================
// DATABASE MODELS
// ======================================================

// ---------------- USER ----------------

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },

    password: {
      type: String,
      required: true
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model('User', UserSchema);

// ---------------- PROJECT ----------------

const ProjectSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },

    description: {
      type: String,
      default: ''
    },

    members: [
      {
        type: String
      }
    ]
  },
  {
    timestamps: true
  }
);

const Project = mongoose.model('Project', ProjectSchema);

// ---------------- TASK ----------------

const TaskSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true
    },

    description: {
      type: String,
      default: ''
    },

    priority: {
      type: String,
      enum: ['Low', 'Medium', 'High'],
      default: 'Medium'
    },

    dueDate: {
      type: Date
    },

    status: {
      type: String,
      default: 'Todo'
    },

    projectId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      required: true
    },

    assignee: {
      type: String,
      default: 'Unassigned'
    }
  },
  {
    timestamps: true
  }
);

const Task = mongoose.model('Task', TaskSchema);

// ======================================================
// AUTHENTICATION MIDDLEWARE
// ======================================================

const authenticateToken = (req, res, next) => {

  const authHeader = req.headers['authorization'];

  const token =
    authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: "Access denied. No token provided."
    });
  }

  jwt.verify(
    token,
    JWT_SECRET,
    (err, user) => {

      if (err) {
        return res.status(403).json({
          error: "Invalid or expired token."
        });
      }

      req.user = user;

      next();
    }
  );
};

// ======================================================
// HEALTH CHECK
// ======================================================

app.get('/api/health', (req, res) => {

  const databaseConnected =
    mongoose.connection.readyState === 1;

  res.json({
    server: "OK",
    database: databaseConnected ? "Connected" : "Disconnected",
    databaseState: mongoose.connection.readyState
  });
});

// ======================================================
// AUTHENTICATION ROUTES
// ======================================================

// ---------------- REGISTER ----------------

app.post('/api/register', async (req, res) => {

  try {

    console.log("======================================");
    console.log("Registration request received");
    console.log("Username:", req.body.username);
    console.log("MongoDB state:", mongoose.connection.readyState);
    console.log("======================================");

    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {

      return res.status(400).json({
        error: "Username and password are required."
      });
    }

    // Check database connection
    if (mongoose.connection.readyState !== 1) {

      console.error(
        "MongoDB is not connected. State:",
        mongoose.connection.readyState
      );

      return res.status(503).json({
        error: "Database is not connected."
      });
    }

    // Check existing username
    const existingUser =
      await User.findOne({ username });

    if (existingUser) {

      console.log(
        "Username already exists:",
        username
      );

      return res.status(409).json({
        error: "Username already exists."
      });
    }

    // Hash password
    const hashedPassword =
      await bcrypt.hash(password, 10);

    // Create user
    const newUser = new User({
      username: username,
      password: hashedPassword
    });

    // Save user
    await newUser.save();

    console.log(
      "User registered successfully:",
      username
    );

    return res.status(201).json({
      message: "User created successfully!"
    });

  } catch (error) {

    console.error("======================================");
    console.error("REGISTRATION ERROR");
    console.error("Name:", error.name);
    console.error("Message:", error.message);
    console.error("Code:", error.code);
    console.error("Stack:", error.stack);
    console.error("======================================");

    // Duplicate MongoDB key
    if (error.code === 11000) {

      return res.status(409).json({
        error: "Username already exists."
      });
    }

    return res.status(500).json({
      error: "Registration failed.",
      details: error.message
    });
  }
});

// ---------------- LOGIN ----------------

app.post('/api/login', async (req, res) => {

  try {

    const { username, password } = req.body;

    if (!username || !password) {

      return res.status(400).json({
        error: "Username and password are required."
      });
    }

    const user =
      await User.findOne({ username });

    if (
      !user ||
      !(await bcrypt.compare(
        password,
        user.password
      ))
    ) {

      return res.status(400).json({
        error: "Invalid credentials."
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username
      },
      JWT_SECRET,
      {
        expiresIn: '7d'
      }
    );

    return res.json({
      token,
      username: user.username
    });

  } catch (error) {

    console.error(
      "Login error:",
      error
    );

    return res.status(500).json({
      error: "Server error during login."
    });
  }
});

// ======================================================
// PROJECT ROUTES
// ======================================================

// ---------------- GET PROJECTS ----------------

app.get(
  '/api/projects',
  authenticateToken,
  async (req, res) => {

    try {

      const projects =
        await Project.find({
          members: req.user.username
        });

      return res.json(projects);

    } catch (error) {

      console.error(
        "Fetch projects error:",
        error
      );

      return res.status(500).json({
        error: "Failed to fetch projects."
      });
    }
  }
);

// ---------------- CREATE PROJECT ----------------

app.post(
  '/api/projects',
  authenticateToken,
  async (req, res) => {

    try {

      const newProject =
        new Project({

          name: req.body.name,

          description:
            req.body.description || '',

          members: [
            req.user.username
          ]
        });

      await newProject.save();

      return res.status(201).json(
        newProject
      );

    } catch (error) {

      console.error(
        "Create project error:",
        error
      );

      return res.status(500).json({
        error: "Failed to create project."
      });
    }
  }
);

// ---------------- INVITE USER ----------------

app.put(
  '/api/projects/:id/invite',
  authenticateToken,
  async (req, res) => {

    try {

      const {
        newMemberUsername
      } = req.body;

      const userExists =
        await User.findOne({
          username: newMemberUsername
        });

      if (!userExists) {

        return res.status(404).json({
          error: "User not found!"
        });
      }

      const updatedProject =
        await Project.findByIdAndUpdate(

          req.params.id,

          {
            $addToSet: {
              members: newMemberUsername
            }
          },

          {
            new: true
          }
        );

      if (!updatedProject) {

        return res.status(404).json({
          error: "Project not found."
        });
      }

      return res.json(
        updatedProject
      );

    } catch (error) {

      console.error(
        "Invite user error:",
        error
      );

      return res.status(500).json({
        error: "Failed to invite user."
      });
    }
  }
);

// ---------------- DELETE PROJECT ----------------

app.delete(
  '/api/projects/:id',
  authenticateToken,
  async (req, res) => {

    try {

      const deletedProject =
        await Project.findByIdAndDelete(
          req.params.id
        );

      if (!deletedProject) {

        return res.status(404).json({
          error: "Project not found."
        });
      }

      await Task.deleteMany({
        projectId: req.params.id
      });

      return res.json({
        message:
          "Project deleted successfully"
      });

    } catch (error) {

      console.error(
        "Delete project error:",
        error
      );

      return res.status(500).json({
        error: "Failed to delete project."
      });
    }
  }
);

// ======================================================
// TASK ROUTES
// ======================================================

// ---------------- GET TASKS ----------------

app.get(
  '/api/tasks/:projectId',
  authenticateToken,
  async (req, res) => {

    try {

      const tasks =
        await Task.find({
          projectId: req.params.projectId
        });

      return res.json(tasks);

    } catch (error) {

      console.error(
        "Fetch tasks error:",
        error
      );

      return res.status(500).json({
        error: "Failed to fetch tasks."
      });
    }
  }
);

// ---------------- CREATE TASK ----------------

app.post(
  '/api/tasks',
  authenticateToken,
  async (req, res) => {

    try {

      const newTask =
        new Task(req.body);

      await newTask.save();

      return res.status(201).json(
        newTask
      );

    } catch (error) {

      console.error(
        "Create task error:",
        error
      );

      return res.status(500).json({
        error: "Failed to create task."
      });
    }
  }
);

// ---------------- UPDATE TASK ----------------

app.put(
  '/api/tasks/:id',
  authenticateToken,
  async (req, res) => {

    try {

      const updatedTask =
        await Task.findByIdAndUpdate(

          req.params.id,

          req.body,

          {
            new: true,
            runValidators: true
          }
        );

      if (!updatedTask) {

        return res.status(404).json({
          error: "Task not found."
        });
      }

      return res.json(
        updatedTask
      );

    } catch (error) {

      console.error(
        "Update task error:",
        error
      );

      return res.status(500).json({
        error: "Failed to update task."
      });
    }
  }
);

// ---------------- DELETE TASK ----------------

app.delete(
  '/api/tasks/:id',
  authenticateToken,
  async (req, res) => {

    try {

      const deletedTask =
        await Task.findByIdAndDelete(
          req.params.id
        );

      if (!deletedTask) {

        return res.status(404).json({
          error: "Task not found."
        });
      }

      return res.json({
        message:
          "Task deleted successfully"
      });

    } catch (error) {

      console.error(
        "Delete task error:",
        error
      );

      return res.status(500).json({
        error: "Failed to delete task."
      });
    }
  }
);

// ======================================================
// START SERVER
// ======================================================

const startServer = async () => {

  try {

    if (!MONGODB_URI) {
      throw new Error(
        "MONGODB_URI environment variable is missing."
      );
    }

    if (!JWT_SECRET) {
      throw new Error(
        "JWT_SECRET environment variable is missing."
      );
    }

    console.log("Connecting to MongoDB...");

    await mongoose.connect(
      MONGODB_URI,
      {
        serverSelectionTimeoutMS: 10000
      }
    );

    console.log("Connected to MongoDB!");

    app.listen(
      PORT,
      () => {

        console.log(
          `Backend server running on port ${PORT}`
        );

        console.log(
          `Health check: /api/health`
        );
      }
    );

  } catch (error) {

    console.error(
      "======================================"
    );

    console.error(
      "FAILED TO START SERVER"
    );

    console.error(
      "Error:",
      error.message
    );

    console.error(
      "======================================"
    );

    process.exit(1);
  }
};

startServer();