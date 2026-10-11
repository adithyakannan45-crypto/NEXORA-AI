// =====================================================
// NEXORA BACKEND
// Authentication + Sessions + Gemini AI + SQLite + Projects
// =====================================================

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const { GoogleGenAI } = require("@google/genai");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const DB_PATH = path.join(__dirname, "nexora.db");

// =====================================================
// ENVIRONMENT CONFIGURATION
// =====================================================

const SESSION_SECRET = process.env.SESSION_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// Set GEMINI_MODEL in .env to a model ID supported by your API key.
const GEMINI_MODEL =
  process.env.GEMINI_MODEL || "gemini-2.5-flash";

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error(
    "ERROR: SESSION_SECRET must be set in .env and contain at least 32 characters."
  );
  process.exit(1);
}

const ai = GEMINI_API_KEY
  ? new GoogleGenAI({ apiKey: GEMINI_API_KEY })
  : null;

// =====================================================
// DATABASE INITIALIZATION & SCHEMA
// =====================================================

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    memory TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'General',
    status TEXT NOT NULL DEFAULT 'In Progress',
    progress INTEGER NOT NULL DEFAULT 0,
    due_date TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

console.log("SQLite database connected:", DB_PATH);

// =====================================================
// PREPARED STATEMENTS
// =====================================================

// Users
const findUserByEmail = db.prepare(`
  SELECT id, name, email, password_hash
  FROM users
  WHERE email = ?
`);

const findUserById = db.prepare(`
  SELECT id, name, email
  FROM users
  WHERE id = ?
`);

const createUser = db.prepare(`
  INSERT INTO users (name, email, password_hash)
  VALUES (?, ?, ?)
`);

const updateUserName = db.prepare(`
  UPDATE users
  SET name = ?
  WHERE id = ?
`);

const getUserPasswordHash = db.prepare(`
  SELECT password_hash
  FROM users
  WHERE id = ?
`);

const updateUserPassword = db.prepare(`
  UPDATE users
  SET password_hash = ?
  WHERE id = ?
`);

// Projects
const getProjectsByUser = db.prepare(`
  SELECT id, title, category, status, progress, due_date, created_at
  FROM projects
  WHERE user_id = ?
  ORDER BY id DESC
`);

const getProjectById = db.prepare(`
  SELECT id, user_id, title, category, status, progress, due_date, created_at
  FROM projects
  WHERE id = ? AND user_id = ?
`);

const createProject = db.prepare(`
  INSERT INTO projects (user_id, title, category, status, progress, due_date)
  VALUES (?, ?, ?, ?, ?, ?)
`);

const updateProject = db.prepare(`
  UPDATE projects
  SET title = ?, category = ?, status = ?, progress = ?, due_date = ?
  WHERE id = ? AND user_id = ?
`);

const deleteProject = db.prepare(`
  DELETE FROM projects
  WHERE id = ? AND user_id = ?
`);

// Memories
const getMemories = db.prepare(`
  SELECT id, memory, created_at
  FROM memories
  WHERE user_id = ?
  ORDER BY id DESC
`);

const createMemory = db.prepare(`
  INSERT INTO memories (user_id, memory)
  VALUES (?, ?)
`);

const deleteMemory = db.prepare(`
  DELETE FROM memories
  WHERE id = ? AND user_id = ?
`);

const deleteAllMemories = db.prepare(`
  DELETE FROM memories
  WHERE user_id = ?
`);

// =====================================================
// SECURITY AND MIDDLEWARE
// =====================================================

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

// Allowed origins for development compatibility
const allowedOrigins = new Set([
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:5501",
  "http://127.0.0.1:5501"
]);

function isAllowedOrigin(origin, hostHeader) {
  if (!origin) return true;
  if (allowedOrigins.has(origin)) return true;

  try {
    const url = new URL(origin);

    // If the origin matches the Host header, it is a same-host request on any domain or tunnel
    if (hostHeader && (url.host === hostHeader || url.hostname === hostHeader.split(":")[0])) {
      return true;
    }

    const host = url.hostname;
    // Allow local network IP addresses for mobile access on same Wi-Fi
    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      /^192\.168\.\d+\.\d+$/.test(host) ||
      /^10\.\d+\.\d+\.\d+$/.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host)
    ) {
      return true;
    }
  } catch (e) {}

  return false;
}

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (!origin) {
    return next();
  }

  if (!isAllowedOrigin(origin, req.headers.host)) {
    return res.status(403).json({
      error: "This website origin is not allowed."
    });
  }

  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Accept"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );
  res.setHeader("Vary", "Origin");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "1mb" }));

app.use(
  express.urlencoded({
    extended: false,
    limit: "100kb"
  })
);

// =====================================================
// SESSION CONFIGURATION
// =====================================================

app.use(
  session({
    name: "nexora.sid",
    secret: SESSION_SECRET,

    store: new SQLiteStore({
      db: "nexora-sessions.sqlite",
      dir: __dirname,
      concurrentDB: true
    }),

    resave: false,
    saveUninitialized: false,
    rolling: true,

    cookie: {
      httpOnly: true,
      secure: false, // Set to true if deploying over HTTPS
      sameSite: "lax",
      path: "/",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

// =====================================================
// RATE LIMITING
// =====================================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many attempts. Please wait and try again."
  }
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many AI requests. Please wait a moment."
  }
});

// =====================================================
// HELPER FUNCTIONS
// =====================================================

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email
  };
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      authenticated: false,
      error: "Please log in to continue."
    });
  }

  try {
    const user = findUserById.get(req.session.user.id);

    if (!user) {
      return req.session.destroy(() => {
        res.clearCookie("nexora.sid", {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          path: "/"
        });

        return res.status(401).json({
          authenticated: false,
          error: "Your account was not found. Please log in again."
        });
      });
    }

    req.currentUser = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error.message);

    return res.status(500).json({
      error: "Unable to verify your account."
    });
  }
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    if (!req.session) {
      return resolve();
    }

    req.session.destroy(error => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

// Robust conversation history converter:
// Supports both Gemini parts format [{text}] and frontend role/content or role/text format.
function cleanHistory(history) {
  if (!Array.isArray(history)) {
    return [];
  }

  return history
    .filter(
      item =>
        item &&
        (item.role === "user" || item.role === "model" || item.role === "assistant")
    )
    .slice(-30)
    .map(item => {
      const role = item.role === "assistant" ? "model" : item.role;
      let text = "";

      if (Array.isArray(item.parts)) {
        text = item.parts
          .filter(part => part && typeof part.text === "string")
          .map(part => part.text)
          .join("\n");
      } else if (typeof item.content === "string") {
        text = item.content;
      } else if (typeof item.text === "string") {
        text = item.text;
      }

      return {
        role,
        parts: [{ text: text.slice(0, 12000) }]
      };
    })
    .filter(item => item.parts[0].text.trim().length > 0);
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/api/health", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.json({
    success: true,
    server: "Nexora",
    database: "connected",
    geminiConfigured: Boolean(ai),
    model: GEMINI_MODEL
  });
});

// =====================================================
// SIGNUP
// =====================================================

app.post("/api/auth/signup", authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Please provide your name, email, and password."
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 80) {
      return res.status(400).json({
        error: "Your name must contain 2 to 80 characters."
      });
    }

    if (
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({
        error: "Please enter a valid email address."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Your password must contain 8 to 128 characters."
      });
    }

    if (findUserByEmail.get(cleanEmail)) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = createUser.run(
      cleanName,
      cleanEmail,
      passwordHash
    );

    const newUserId = result.lastInsertRowid;

    // Seed starter demonstration projects for new users
    try {
      createProject.run(
        newUserId,
        "Nexora Platform Setup",
        "Product",
        "In Progress",
        65,
        new Date(Date.now() + 7 * 86400000).toISOString().split("T")[0]
      );
      createProject.run(
        newUserId,
        "AI Workflow Automation",
        "AI / Automation",
        "On Track",
        90,
        new Date(Date.now() + 14 * 86400000).toISOString().split("T")[0]
      );
    } catch (seedErr) {
      console.warn("Could not seed starter projects:", seedErr.message);
    }

    return res.status(201).json({
      success: true,
      message: "Account created successfully. Please log in.",
      user: {
        id: newUserId,
        name: cleanName,
        email: cleanEmail
      }
    });
  } catch (error) {
    console.error("Signup error:", error.message);

    if (String(error.code || "").includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({
        error: "This email may already be registered."
      });
    }

    return res.status(500).json({
      error: "Unable to create your account right now."
    });
  }
});

// =====================================================
// LOGIN
// =====================================================

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Please enter your email and password."
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = findUserByEmail.get(cleanEmail);

    if (!user) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    // Prevent session fixation by generating a new session ID.
    await regenerateSession(req);

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email
    };

    // Wait for the session store to save the authenticated session.
    await saveSession(req);

    console.log(
      "Login successful:",
      user.email,
      "| Session saved:",
      Boolean(req.sessionID)
    );

    return res.json({
      success: true,
      message: "Login successful.",
      user: publicUser(user)
    });
  } catch (error) {
    console.error("Login/session error:", error.message);

    return res.status(500).json({
      error: "Login could not be completed. Please try again."
    });
  }
});

// =====================================================
// CHECK CURRENT SESSION
// =====================================================

app.get("/api/auth/me", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (!req.session || !req.session.user) {
    return res.status(401).json({
      authenticated: false,
      error: "No active login session."
    });
  }

  try {
    const user = findUserById.get(req.session.user.id);

    if (!user) {
      return req.session.destroy(() => {
        res.clearCookie("nexora.sid", {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          path: "/"
        });

        return res.status(401).json({
          authenticated: false,
          error: "Account not found. Please log in again."
        });
      });
    }

    return res.json({
      authenticated: true,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("Session verification error:", error.message);

    return res.status(500).json({
      authenticated: false,
      error: "Unable to verify the login session."
    });
  }
});

// =====================================================
// UPDATE USER PROFILE / SETTINGS
// =====================================================

app.put("/api/auth/profile", requireAuth, async (req, res) => {
  try {
    const { name, currentPassword, newPassword } = req.body || {};
    const userId = req.currentUser.id;

    let updatedName = req.currentUser.name;

    if (typeof name === "string" && name.trim()) {
      const cleanName = name.trim();
      if (cleanName.length < 2 || cleanName.length > 80) {
        return res.status(400).json({
          error: "Name must contain between 2 and 80 characters."
        });
      }
      updateUserName.run(cleanName, userId);
      updatedName = cleanName;
      req.session.user.name = cleanName;
    }

    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({
          error: "Please enter your current password to set a new password."
        });
      }

      if (typeof newPassword !== "string" || newPassword.length < 8 || newPassword.length > 128) {
        return res.status(400).json({
          error: "New password must be between 8 and 128 characters."
        });
      }

      const row = getUserPasswordHash.get(userId);
      const matches = await bcrypt.compare(currentPassword, row.password_hash);

      if (!matches) {
        return res.status(401).json({
          error: "Current password does not match."
        });
      }

      const newHash = await bcrypt.hash(newPassword, 12);
      updateUserPassword.run(newHash, userId);
    }

    await saveSession(req);

    return res.json({
      success: true,
      message: "Profile updated successfully.",
      user: {
        id: userId,
        name: updatedName,
        email: req.currentUser.email
      }
    });
  } catch (error) {
    console.error("Profile update error:", error.message);
    return res.status(500).json({
      error: "Unable to update profile."
    });
  }
});

// =====================================================
// LOGOUT
// =====================================================

app.post("/api/auth/logout", async (req, res) => {
  try {
    await destroySession(req);

    res.clearCookie("nexora.sid", {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/"
    });

    return res.json({
      success: true,
      message: "Logged out successfully."
    });
  } catch (error) {
    console.error("Logout error:", error.message);

    return res.status(500).json({
      error: "Unable to log out right now."
    });
  }
});

// =====================================================
// PROJECTS API (CRUD)
// =====================================================

// Get all projects for current user
app.get("/api/projects", requireAuth, (req, res) => {
  try {
    const projects = getProjectsByUser.all(req.currentUser.id);
    return res.json({
      success: true,
      projects
    });
  } catch (error) {
    console.error("Get projects error:", error.message);
    return res.status(500).json({
      error: "Unable to load projects."
    });
  }
});

// Create a project
app.post("/api/projects", requireAuth, (req, res) => {
  try {
    const { title, category, status, progress, due_date } = req.body || {};

    if (typeof title !== "string" || !title.trim()) {
      return res.status(400).json({
        error: "Please enter a project title."
      });
    }

    const cleanTitle = title.trim().slice(0, 100);
    const cleanCategory = (typeof category === "string" && category.trim())
      ? category.trim().slice(0, 50)
      : "General";
    const cleanStatus = ["In Progress", "On Track", "Behind Schedule", "Completed"].includes(status)
      ? status
      : "In Progress";
    const numProgress = Math.min(100, Math.max(0, Number(progress) || 0));
    const cleanDueDate = (typeof due_date === "string" && due_date.trim())
      ? due_date.trim().slice(0, 20)
      : null;

    const result = createProject.run(
      req.currentUser.id,
      cleanTitle,
      cleanCategory,
      cleanStatus,
      numProgress,
      cleanDueDate
    );

    const newProject = getProjectById.get(result.lastInsertRowid, req.currentUser.id);

    return res.status(201).json({
      success: true,
      message: "Project created successfully.",
      project: newProject
    });
  } catch (error) {
    console.error("Create project error:", error.message);
    return res.status(500).json({
      error: "Unable to create project."
    });
  }
});

// Update project (title, category, status, progress, due_date)
app.patch("/api/projects/:id", requireAuth, (req, res) => {
  try {
    const projectId = Number(req.params.id);

    if (!Number.isSafeInteger(projectId) || projectId < 1) {
      return res.status(400).json({ error: "Invalid project ID." });
    }

    const existing = getProjectById.get(projectId, req.currentUser.id);
    if (!existing) {
      return res.status(404).json({ error: "Project not found." });
    }

    const { title, category, status, progress, due_date } = req.body || {};

    const updatedTitle = typeof title === "string" && title.trim() ? title.trim().slice(0, 100) : existing.title;
    const updatedCategory = typeof category === "string" && category.trim() ? category.trim().slice(0, 50) : existing.category;
    const updatedStatus = ["In Progress", "On Track", "Behind Schedule", "Completed"].includes(status) ? status : existing.status;
    const updatedProgress = progress !== undefined ? Math.min(100, Math.max(0, Number(progress) || 0)) : existing.progress;
    const updatedDueDate = due_date !== undefined ? (due_date ? String(due_date).trim().slice(0, 20) : null) : existing.due_date;

    updateProject.run(
      updatedTitle,
      updatedCategory,
      updatedStatus,
      updatedProgress,
      updatedDueDate,
      projectId,
      req.currentUser.id
    );

    const updated = getProjectById.get(projectId, req.currentUser.id);

    return res.json({
      success: true,
      message: "Project updated.",
      project: updated
    });
  } catch (error) {
    console.error("Update project error:", error.message);
    return res.status(500).json({
      error: "Unable to update project."
    });
  }
});

// Delete project
app.delete("/api/projects/:id", requireAuth, (req, res) => {
  try {
    const projectId = Number(req.params.id);

    if (!Number.isSafeInteger(projectId) || projectId < 1) {
      return res.status(400).json({ error: "Invalid project ID." });
    }

    const result = deleteProject.run(projectId, req.currentUser.id);

    if (result.changes === 0) {
      return res.status(404).json({ error: "Project not found." });
    }

    return res.json({
      success: true,
      message: "Project deleted successfully."
    });
  } catch (error) {
    console.error("Delete project error:", error.message);
    return res.status(500).json({
      error: "Unable to delete project."
    });
  }
});

// =====================================================
// DASHBOARD STATS
// =====================================================

app.get("/api/dashboard/stats", requireAuth, (req, res) => {
  try {
    const projects = getProjectsByUser.all(req.currentUser.id);

    const totalProjects = projects.length;
    const completedProjects = projects.filter(p => p.status === "Completed" || p.progress === 100).length;
    const activeProjects = totalProjects - completedProjects;
    const averageProgress = totalProjects > 0
      ? Math.round(projects.reduce((acc, p) => acc + (p.progress || 0), 0) / totalProjects)
      : 0;

    return res.json({
      success: true,
      stats: {
        totalProjects,
        activeProjects,
        completedProjects,
        averageProgress,
        accountStatus: "Active",
        aiRequests: 14 // Platform activity indicator
      }
    });
  } catch (error) {
    console.error("Dashboard stats error:", error.message);
    return res.status(500).json({
      error: "Unable to calculate dashboard stats."
    });
  }
});

// =====================================================
// GEMINI AI CHAT
// =====================================================

app.post(
  "/api/chat",
  requireAuth,
  chatLimiter,
  async (req, res) => {
    try {
      if (!ai) {
        return res.status(503).json({
          error: "Gemini is not configured. Check GEMINI_API_KEY in .env."
        });
      }

      const { message, history } = req.body || {};

      if (typeof message !== "string" || !message.trim()) {
        return res.status(400).json({
          error: "Please enter a message."
        });
      }

      const cleanMessage = message.trim();

      if (cleanMessage.length > 12000) {
        return res.status(400).json({
          error: "Your message is too long. Please shorten it."
        });
      }

      const safeHistory = cleanHistory(history);

      // Gemini expects the conversation to alternate between user
      // and model turns. Remove trailing model turns if necessary.
      while (
        safeHistory.length &&
        safeHistory[safeHistory.length - 1].role === "model"
      ) {
        safeHistory.pop();
      }

      const contents = [
        ...safeHistory,
        {
          role: "user",
          parts: [{ text: cleanMessage }]
        }
      ];

      const result = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents,
        config: {
          systemInstruction:
            "You are Nexora AI, a helpful, intelligent, and professional AI assistant built into the Nexora SaaS platform. " +
            "Give clear, accurate, and insightful answers. " +
            "Format your responses nicely with markdown where appropriate."
        }
      });

      const reply = result.text;

      if (!reply) {
        return res.status(502).json({
          error: "The AI returned an empty response. Please try again."
        });
      }

      return res.json({
        success: true,
        reply,
        response: reply
      });
    } catch (error) {
      console.error("Gemini chat error:", error);

      const status = error.status || error.statusCode;
      const errorMessage = String(error.message || "");

      if (status === 401 || status === 403) {
        return res.status(502).json({
          error: "Gemini rejected the API key. Check your Google AI API key."
        });
      }

      if (
        status === 404 ||
        /model.*not found|model.*not supported/i.test(errorMessage)
      ) {
        return res.status(502).json({
          error:
            `The configured Gemini model "${GEMINI_MODEL}" is unavailable. ` +
            "Set GEMINI_MODEL in .env to a model supported by your API key."
        });
      }

      if (status === 429) {
        return res.status(429).json({
          error: "Gemini rate limit reached. Please wait and try again."
        });
      }

      return res.status(500).json({
        error: "Nexora AI could not generate a response. Please try again."
      });
    }
  }
);

// =====================================================
// GET SAVED MEMORIES
// =====================================================

app.get("/api/memories", requireAuth, (req, res) => {
  try {
    const memories = getMemories.all(
      String(req.currentUser.id)
    );

    return res.json({
      success: true,
      memories
    });
  } catch (error) {
    console.error("Get memories error:", error.message);

    return res.status(500).json({
      error: "Unable to load your saved memories."
    });
  }
});

// =====================================================
// SAVE A MEMORY
// =====================================================

app.post("/api/memories", requireAuth, (req, res) => {
  try {
    const { memory } = req.body || {};

    if (typeof memory !== "string" || !memory.trim()) {
      return res.status(400).json({
        error: "Please provide a memory to save."
      });
    }

    const cleanMemory = memory.trim();

    if (cleanMemory.length > 5000) {
      return res.status(400).json({
        error: "A memory cannot exceed 5000 characters."
      });
    }

    const result = createMemory.run(
      String(req.currentUser.id),
      cleanMemory
    );

    return res.status(201).json({
      success: true,
      id: result.lastInsertRowid,
      memory: cleanMemory
    });
  } catch (error) {
    console.error("Save memory error:", error.message);

    return res.status(500).json({
      error: "Unable to save this memory."
    });
  }
});

// =====================================================
// DELETE ONE MEMORY
// =====================================================

app.delete("/api/memories/:id", requireAuth, (req, res) => {
  try {
    const memoryId = Number(req.params.id);

    if (!Number.isSafeInteger(memoryId) || memoryId < 1) {
      return res.status(400).json({
        error: "Invalid memory ID."
      });
    }

    const result = deleteMemory.run(
      memoryId,
      String(req.currentUser.id)
    );

    if (result.changes === 0) {
      return res.status(404).json({
        error: "Memory not found."
      });
    }

    return res.json({
      success: true,
      message: "Memory deleted."
    });
  } catch (error) {
    console.error("Delete memory error:", error.message);

    return res.status(500).json({
      error: "Unable to delete this memory."
    });
  }
});

// =====================================================
// DELETE ALL MEMORIES
// =====================================================

app.delete("/api/memories", requireAuth, (req, res) => {
  try {
    deleteAllMemories.run(String(req.currentUser.id));

    return res.json({
      success: true,
      message: "All your saved memories have been deleted."
    });
  } catch (error) {
    console.error("Delete all memories error:", error.message);

    return res.status(500).json({
      error: "Unable to delete your memories."
    });
  }
});

// =====================================================
// SERVE NEXORA FRONTEND
// =====================================================

app.use(express.static(__dirname));

// =====================================================
// ERROR HANDLER
// =====================================================

app.use((error, req, res, next) => {
  console.error("Backend error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    error: "An unexpected server error occurred."
  });
});

// =====================================================
// START SERVER
// =====================================================

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("========================================");
  console.log("       NEXORA SERVER IS RUNNING");
  console.log("========================================");
  console.log(`Website:   http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}/dashboard.html`);
  console.log(`AI Chat:   http://localhost:${PORT}/ai.html`);
  console.log(`Login:     http://localhost:${PORT}/login.html`);
  console.log(`Health:    http://localhost:${PORT}/api/health`);
  console.log(`Gemini configured: ${Boolean(ai)}`);
  console.log(`Gemini model: ${GEMINI_MODEL}`);
  console.log("========================================");
  console.log("");
});

function shutdown() {
  console.log("Shutting down Nexora...");

  server.close(() => {
    try {
      db.close();
    } catch (error) {
      console.error("Database shutdown error:", error.message);
    }

    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);