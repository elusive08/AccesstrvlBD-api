const express = require("express");
const router = express.Router();

const {
  createProfile,
  updateProfile,
  getProfile,
} = require("../controllers/accessibilityProfile.controller");

const { protect } = require("../middleware/auth.middleware");

router.post("/create", protect, createProfile);
router.put("/update", protect, updateProfile);
router.get("/get", protect, getProfile);

module.exports = router;