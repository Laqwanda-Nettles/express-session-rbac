const express = require("express");
const mongoose = require("mongoose");
const User = require("./models/user");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const auth = require("./middleware/auth");
const role = require("./middleware/role");
const app = express();
const port = 3000;

require("dotenv").config();
const mongoUrl = process.env.MONGO_URL;

// Middleware to parse JSON bodies
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

//Register a new user
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "Email already exists" });
  }

  try {
    const newUser = new User({ name, email, password, role });
    const savedUser = await newUser.save();

    res
      .status(201)
      .json({ message: "User registered successfully", savedUser });
  } catch (error) {
    console.error("Error registering user: ", error);
    res.status(500).json({ error: "Error registering user" });
  }
});

//Login a user
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    console.error("Error logging in user: ", error);
    res.status(500).json({ error: "Error logging in user" });
  }
});

//Dashboard route (authentication)
app.get("/dashboard", auth, (req, res) => {
  res.json({ message: "This is the dashboard." });
});

//Admin route (Role-Based Access)
app.get("/admin", auth, role("admin"), (req, res) => {
  res.json({ message: "This is the admin panel." });
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
