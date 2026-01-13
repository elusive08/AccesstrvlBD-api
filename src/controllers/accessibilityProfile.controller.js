const AccessibilityProfile = require("../models/accessibilityProfile.model");

/**
 * @desc Create accessibility profile
 * @route POST /profile/create
 * @access Private
 */
exports.createProfile = async (req, res) => {
  try {
    const existing = await AccessibilityProfile.findOne({
      user: req.user.id,
    });

    if (existing) {
      return res.status(400).json({
        success: false,
        message: "Accessibility profile already exists",
      });
    }

    const profile = await AccessibilityProfile.create({
      user: req.user.id,
      ...req.body,
    });

    res.status(201).json({
      success: true,
      data: profile,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc Update accessibility profile
 * @route PUT /profile/update
 * @access Private
 */
exports.updateProfile = async (req, res) => {
  try {
    const profile = await AccessibilityProfile.findOneAndUpdate(
      { user: req.user.id },
      req.body,
      { new: true, runValidators: true }
    );

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: "Profile not found",
      });
    }

    res.status(200).json({
      success: true,
      data: profile,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

/**
 * @desc Get logged in user's profile
 * @route GET /profile/get
 * @access Private
 */
exports.getProfile = async (req, res) => {
  try {
    const profile = await AccessibilityProfile.findOne({
      user: req.user.id,
    }).populate("user", "name email");

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: "Profile not found",
      });
    }

    res.status(200).json({
      success: true,
      data: profile,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};