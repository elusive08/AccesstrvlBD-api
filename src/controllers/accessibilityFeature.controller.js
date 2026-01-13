const AccessibilityFeature = require("../models/AccessibilityFeature.model");

// Create accessibility feature (Admin use)
exports.createFeature = async (req, res) => {
  try {
    const { name, category, description } = req.body;

    if (!name || !category) {
      return res.status(400).json({
        success: false,
        message: "Name and category are required"
      });
    }

    const exists = await AccessibilityFeature.findOne({ name });
    if (exists) {
      return res.status(409).json({
        success: false,
        message: "Accessibility feature already exists"
      });
    }

    const feature = await AccessibilityFeature.create({
      name,
      category,
      description
    });

    res.status(201).json({
      success: true,
      data: feature
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
};

// Get all accessibility features
exports.getAllFeatures = async (req, res) => {
  try {
    const features = await AccessibilityFeature.find().sort({
      category: 1,
      name: 1
    });

    res.status(200).json({
      success: true,
      count: features.length,
      data: features
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
};

// Get features by category
exports.getFeaturesByCategory = async (req, res) => {
  try {
    const { category } = req.params;

    const features = await AccessibilityFeature.find({ category });

    res.status(200).json({
      success: true,
      count: features.length,
      data: features
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
};