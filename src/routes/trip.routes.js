const express = require("express");
const router = express.Router();

const {
  createTrip,
  getTrip,
  getTripSuggestions,
} = require("../controllers/trip.controller");

const auth = require("../middleware/auth.middleware");

router.post("/create", auth.protect, createTrip);
router.get("/suggestions", auth.protect, getTripSuggestions);
router.get("/:id", auth.protect, getTrip);

module.exports = router;