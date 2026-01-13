const User = require("../models/User");
const bcrypt = require("bcryptjs"); // Changed from bcryptjs
const jwt = require('jsonwebtoken');
const sendEmail = require("../utils/sendEmail");

const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

/* REGISTER */









exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const exists = await User.findOne({ email: normalizedEmail });
    if (exists) {
      return res.status(400).json({
        success: false,
        message: "Email already registered, try logging in"
      });
    }

    // DON'T hash here - let the model do it
    const otp = generateOTP();

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: password,  // ✅ Store plain password, model will hash it
      emailOTP: otp,
      emailOTPExpires: Date.now() + 10 * 60 * 1000
    });

    await sendEmail({
      to: normalizedEmail,
      subject: "Verify your email - ACCESS-TRAVEL NOREPLY",
      text: `Your verification OTP is ${otp}. This code will expire in 10 minutes.`
    });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(201).json({
      success: true,
      message: "Registration successful. Please check your email to verify your account.",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({
      success: false,
      message: "Registration failed. Please try again."
    });
  }
};
















/* VERIFY EMAIL */
exports.verifyEmail = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      email: normalizedEmail,
      emailOTP: otp,
      emailOTPExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP"
      });
    }

    user.isEmailVerified = true;
    user.emailOTP = undefined;
    user.emailOTPExpires = undefined;
    await user.save();

    return res.json({
      success: true,
      message: "Email verified successfully"
    });
  } catch (error) {
    console.error("Verification error:", error);
    return res.status(500).json({
      success: false,
      message: "Verification failed"
    });
  }
};

/* LOGIN */



















exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    
    console.log("Login attempt for:", normalizedEmail);
    console.log("Password from request:", password);
    
    // Find user with password field
    const user = await User.findOne({ email: normalizedEmail }).select("+password");
  
    if (!user) {
      console.log("User not found");
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    console.log("User found, checking verification...");

    // Check if email is verified
    if (!user.isEmailVerified) {
      console.log("Email not verified");
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in"
      });
    }

    console.log("Comparing passwords...");
    
    // Compare WITHOUT trimming since you hash WITHOUT trimming in register
    const isMatch = await bcrypt.compare(password, user.password);
    
    console.log("Password match:", isMatch);
    
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    // Create token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    console.log("Login successful!");

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again."
    });
  }
};














/* ME */
exports.me = async (req, res) => {
  try {
    return res.json({
      success: true,
      user: req.user
    });
  } catch (error) {
    console.error("Me error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch user data"
    });
  }
};

/* FORGOT PASSWORD */
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    
    const user = await User.findOne({ email: normalizedEmail });

    // Always return success for security (don't reveal if email exists)
    if (!user) {
      return res.json({
        success: true,
        message: "If that email exists, an OTP has been sent"
      });
    }

    const otp = generateOTP();

    user.resetPasswordOTP = otp;
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    await sendEmail({
      to: normalizedEmail,
      subject: "Password Reset OTP - ACCESS-TRAVEL",
      text: `Your password reset OTP is ${otp}. This code will expire in 10 minutes. If you didn't request this, please ignore this email.`
    });

    return res.json({
      success: true,
      message: "If that email exists, an OTP has been sent"
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to process request"
    });
  }
};

/* RESET PASSWORD */
exports.resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email, OTP, and new password are required"
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters long"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      email: normalizedEmail,
      resetPasswordOTP: otp,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP"
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword.trim(), 10);

    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return res.json({
      success: true,
      message: "Password reset successful. You can now login with your new password."
    });
  } catch (error) {
    console.error("Reset password error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to reset password"
    });
  }
};