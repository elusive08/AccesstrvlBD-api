const express = require("express");
const router = express.Router();
const { voteReview } = require("../controllers/reviewVote.controller");
const { protect } = require("../middleware/auth.middleware");

router.post("/reviews/:id/vote", protect, voteReview);

module.exports = router;