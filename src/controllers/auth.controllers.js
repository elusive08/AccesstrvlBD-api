// const User = require("../models/User");
// const bcrypt = require("bcryptjs");
// const jwt = require('jsonwebtoken');
// const generateToken = require("../utils/generateToken");
// const sendEmail = require("../utils/sendEmail");
// const generateOTP = () =>
//   Math.floor(100000 + Math.random() * 900000).toString();

// /* REGISTER */
// exports.register = async (req, res) => {
//   const {name, email, password } = req.body;

// const normalizedEmail = email.trim().toLowerCase();







// if (!name || !email || !password) {
//       return res.status(400).json({
//         message: "Email and password are required",
//       });
//     }




//   const exists = await User.findOne({ email });
//   if (exists) return res.status(400).json({ message: "Email exists" });


// const hashedPassword = await bcrypt.hash(password, 10);

//     await User.create({
//       name,
//       email,
//       password: hashedPassword,
//     });







//   const otp = generateOTP();

//   const user = await User.create({
//     name,
//     email,
//     password,
//     emailOTP: otp,
//     emailOTPExpires: Date.now() + 10 * 60 * 1000
//   });

//   await sendEmail({
//     to: email,
//     subject: "Verify your email",
//     text: `Your verification OTP is ${otp}`
//   });

// //   // res.status(201).json({ message: "OTP sent to email" });
  
// //   res.status(201).json({
// //     success: true,
// //     token
// //   });
  
  
// // };

// try {
//     const user = await User.create(req.body);

//     const token = jwt.sign(
//       { id: user._id, role: user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: "2d" }
//     );

//     return res.status(201).json({
//       success: true,
//       token
//     });
//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({
//       success: false,
//       message: error.message
//     });
//   }
// };







// /* VERIFY EMAIL */
// exports.verifyEmail = async (req, res) => {
//   const { email, otp } = req.body;

//   const user = await User.findOne({
//     email,
//     emailOTP: otp,
//     emailOTPExpires: { $gt: Date.now() }
//   });

//   if (!user) {
//     return res.status(400).json({ message: "Invalid or expired OTP" });
//   }

//   user.isEmailVerified = true;
//   user.emailOTP = undefined;
//   user.emailOTPExpires = undefined;
//   await user.save();

//   res.json({ message: "Email verified successfully" });
// };

// /* LOGIN */
// // 



// exports.login = async (req, res) => {
//   try {
//     const { email, password } = req.body;

//     // 1. Check user
//     const user = await User.findOne({ email }).select("+password");
//     if (!user) {
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials"
//       });
//     }

//     // 2. Check password
//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials"
//       });
//     }

//     // 3. Create token
//     const token = jwt.sign(
//       { id: user._id, role: user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: "7d" }
//     );

//     // 4. RETURN TOKEN (this is what you are missing)
//     return res.status(200).json({
//       success: true,
//       token
//     });

//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({
//       success: false,
//       message: "Server error"
//     });
//   }
// };








// /* ME */
// exports.me = async (req, res) => {
//   res.json(req.user);
// };




// /* FORGOT PASSWORD */
// exports.forgotPassword = async (req, res) => {
//   const { email } = req.body;
//   const user = await User.findOne({ email });

//   if (!user) return res.json({ message: "OTP sent if email exists" });

//   const otp = generateOTP();

//   user.resetPasswordOTP = otp;
//   user.resetPasswordExpires = Date.now() + 10 * 60 * 1000;
//   await user.save();

//   await sendEmail({
//     to: email,
//     subject: "Password Reset OTP",
//     text: `Your password reset OTP is ${otp}`
//   });

//   res.json({ message: "OTP sent" });
// };

// /* RESET PASSWORD */
// exports.resetPassword = async (req, res) => {
//   const { email, otp, newPassword } = req.body;

//   const user = await User.findOne({
//     email,
//     resetPasswordOTP: otp,
//     resetPasswordExpires: { $gt: Date.now() }
//   });

//   if (!user) {
//     return res.status(400).json({ message: "Invalid or expired OTP" });
//   }

//   user.password = newPassword;
//   user.resetPasswordOTP = undefined;
//   user.resetPasswordExpires = undefined;
//   await user.save();

//   res.json({ message: "Password reset successful" });
// };











const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
const sendEmail = require("../utils/sendEmail");

const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

/* REGISTER */
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;




console.log("=== REGISTRATION DEBUG ===");
    console.log("Raw password received:", password);
    console.log("Password type:", typeof password);
    console.log("Password length:", password.length);
    console.log("Password as JSON:", JSON.stringify(password));



    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required",
      });
    }

    // Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // Check if user already exists
    const exists = await User.findOne({ email: normalizedEmail });
    if (exists) {
      return res.status(400).json({
        success: false,
        message: "Email already registered, try logging in"
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP
    const otp = generateOTP();

    // Create user (ONLY ONCE!)
    const user = await User.create({
      name,
      email: normalizedEmail,
      password: hashedPassword,
      emailOTP: otp,
      emailOTPExpires: Date.now() + 10 * 60 * 1000
    });

    // Send verification email
    await sendEmail({
      to: normalizedEmail,
      subject: "Verify your email·<ACCESS-TRAVEL NOREPLY>",
      text: `Your verification OTP is ${otp}`
    });

    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(201).json({
      success: true,
      message: "Registration successful. Please check your email to verify your email.",
      token
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
// exports.login = async (req, res) => {
//   try {
//     const { email, password } = req.body;





// exports.login = async (req, res) => {

//   try {
//     if (!req.body) {
//       return res.status(400).json({
//         success: false,
//         message: "Request body missing",
//       });
//     }

//     const { email, password } = req.body;

//     if (!email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "Email and password are required",
//       });
//     }
//     const normalizedEmail = email.trim().toLowerCase();

//     // Find user
//     const user = await User.findOne({ email: normalizedEmail }).select("+password");
  
//     if (!user) {
      
//       return res.status(401).json({
//         success: false,
//         message: "Invalid credentials"
//       });
//     }


//     // Check password
//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(401).json({
//         success: false,
//         message: "Incorrect password"
//       });
//     }

//     // Create token
//     const token = jwt.sign(
//       { id: user._id, role: user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: "7d" }
//     );

//     return res.status(200).json({
//       success: true,
//       token
//     });

//   } catch (error) {
//     console.error("Login error:", error);
//     return res.status(500).json({
//       success: false,
//       message: "failed to login"
//     });
//   }
// };







exports.login = async (req, res) => {
  try {
    if (!req.body) {
      return res.status(400).json({
        success: false,
        message: "Request body missing",
      });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Find user
    const user = await User.findOne({ email: normalizedEmail }).select("+password");
  
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    // DEBUG: Log to see what's happening
    console.log("Login attempt for:", normalizedEmail);
    console.log("Password from request:", password);
    console.log("Hashed password from DB:", user.password);
    console.log("Password length:", password.length);

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Password match result:", isMatch);
    
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Incorrect password"
      });
    }

    // Create token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      message: "failed to login"
    });
  }
};
















/* ME */
exports.me = async (req, res) => {
  res.json(req.user);
};

/* FORGOT PASSWORD */
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = email.trim().toLowerCase();
    
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        success: true,
        message: "An OTP has been sent to the provide email"
      });
    }

    const otp = generateOTP();

    user.resetPasswordOTP = otp;
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    await sendEmail({
      to: normalizedEmail,
      subject: "Password Reset OTP",
      text: `Your password reset OTP is ${otp}`
    });

    return res.json({
      success: true,
      message: "OTP sent to your email"
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
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return res.json({
      success: true,
      message: "Password reset successful"
    });
  } catch (error) {
    console.error("Reset password error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to reset password"
    });
  }
};