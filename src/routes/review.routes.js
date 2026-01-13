const express = require("express");
const router = express.Router();

const {
  addReview,
  getPlaceReviews,
} = require("../controllers/review.controller");

const { protect } = require("../middleware/auth.middleware");

// Add review
router.post("/add", protect, addReview);

// Get reviews for a place
router.get("/place/:id", getPlaceReviews);

module.exports = router;