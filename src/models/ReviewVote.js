const mongoose = require("mongoose");

const reviewVoteSchema = new mongoose.Schema({
  review: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Review",
    required: true,
  },

  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },

  voteType: {
    type: String,
    enum: ["helpful", "inaccurate"],
    required: true,
  },
}, { timestamps: true });

reviewVoteSchema.index({ review: 1, user: 1 }, { unique: true });

module.exports = mongoose.model("ReviewVote", reviewVoteSchema);