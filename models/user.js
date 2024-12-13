const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema({
  name: { type: String },
  email: { type: String, unique: true },
  password: { type: String },
  role: { type: String, enum: ["user", "admin"], default: "user" },
});

userSchema.pre("save", async function (next) {
  const salt = await bcrypt.genSalt(10);
  const plainTextPassword = this.password;
  const encryptedPassword = await bcrypt.hash(plainTextPassword, salt);
  this.password = encryptedPassword;
  next();
});

const User = mongoose.model("User", userSchema);

module.exports = User;
