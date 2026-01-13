const express = require("express");
const router = express.Router();

const controller = require("../controllers/accessibilityFeature.controller");

// Create feature
router.post("/", controller.createFeature);

// Get all features
router.get("/", controller.getAllFeatures);

// Get features by category
router.get("/:category", controller.getFeaturesByCategory);

module.exports = router;