// const Review = require("../models/Review");
// const ReviewVote = require("../models/ReviewVote");




// /**
// * VOTE ON A REVIEW
// * POST /reviews/:id/vote
// */
// exports.voteReview = async (req, res) => {
//   try {
//     const { voteType } = req.body;
//     const reviewId = req.params.id;

//     if (!["helpful", "inaccurate"].includes(voteType)) {
//       return res.status(400).json({
//         success: false,
//         message: "Invalid vote type",
//       });
//     }

//     // Check if review exists
//     const review = await Review.findById(reviewId);
//     if (!review) {
//       return res.status(404).json({
//         success: false,
//         message: "Review not found",
//       });
//     }

//     // Prevent double voting
//     const existingVote = await ReviewVote.findOne({
//       review: reviewId,
//       user: req.user.id,
//     });

//     if (existingVote) {
//       return res.status(400).json({
//         success: false,
//         message: "You have already voted on this review",
//       });
//     }

//     // Save vote
//     await ReviewVote.create({
//       review: reviewId,
//       user: req.user.id,
//       voteType,
//     });

//     // Update trust metrics
//     if (voteType === "helpful") {
//       review.helpfulCount += 1;
//       review.trustScore += 1;
//     } else {
//       review.inaccurateCount += 1;
//       review.trustScore -= 1;
//     }

//     await review.save();

//     res.status(200).json({
//       success: true,
//       message: "Vote recorded",
//       trustScore: review.trustScore,
//     });

//   } catch (error) {
//     res.status(500).json({
//       success: false,
//       message: error.message,
//     });
//   }
// };









const ReviewVote = require("../models/ReviewVote");

exports.voteReview = async (req, res) => {
  try {
    const { reviewId, vote } = req.body;

    const existing = await ReviewVote.findOne({
      review: reviewId,
      user: req.user.id,
    });

    if (existing) {
      existing.vote = vote;
      await existing.save();
    } else {
      await ReviewVote.create({
        review: reviewId,
        user: req.user.id,
        vote,
      });
    }

    const helpful = await ReviewVote.countDocuments({
      review: reviewId,
      vote: "helpful",
    });

    const inaccurate = await ReviewVote.countDocuments({
      review: reviewId,
      vote: "inaccurate",
    });

    res.status(200).json({
      success: true,
      trustScore: helpful - inaccurate,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Voting failed",
      error: error.message,
    });
  }
};