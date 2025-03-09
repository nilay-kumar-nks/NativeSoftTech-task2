const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = 3000;
const SECRET_KEY = "supersecretkey";

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve Static Files (Frontend)
app.use(express.static(path.join(__dirname, "public")));

// MongoDB Connection
mongoose
  .connect("mongodb://localhost:27017/fullstack_app", { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

// Register Route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });

  await user.save();
  res.json({ message: "✅ User registered successfully!" });
});

// Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "❌ Invalid credentials" });
  }

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
  res.cookie("token", token, { httpOnly: true });
  res.json({ message: "✅ Login successful!" });
});

// Dashboard Route (Protected)
app.get("/dashboard", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "❌ Unauthorized" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ message: `✅ Welcome, ${decoded.username}!` });
  } catch {
    res.status(401).json({ message: "❌ Invalid Token" });
  }
});

// Logout
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "✅ Logged out successfully!" });
});

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));

