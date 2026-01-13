const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
  
  name: {
    type: String,
    required: true
  },
  
  
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  role: {
    type: String,
    enum: ["user", "admin", "moderator"],
    default: "user"
  },

  isEmailVerified: {
    type: Boolean,
    default: false
  },

  emailOTP: String,
  emailOTPExpires: Date,

  resetPasswordOTP: String,
  resetPasswordExpires: Date

}, { timestamps: true });

userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.matchPassword = function (entered) {
  return bcrypt.compare(entered, this.password);
};

module.exports = mongoose.model("User", userSchema);