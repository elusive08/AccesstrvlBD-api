const Review = require("../models/Review");
const Place = require("../models/Place");

/**
 * ADD REVIEW
 * POST /reviews/add
 */
exports.addReview = async (req, res) => {
  try {
    const { place, accessibilityRatings, structuredQuestions, dateOfVisit, comment, photos } =
      req.body;

    const placeExists = await Place.findById(place);
    if (!placeExists) {
      return res.status(404).json({
        success: false,
        message: "Place not found",
      });
    }

    const review = await Review.create({
      user: req.user.id,
      place,
      accessibilityRatings,
      structuredQuestions,
      dateOfVisit,
      comment,
      photos,
    });

    res.status(201).json({
      success: true,
      data: review,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
};

/**
 * GET REVIEWS FOR A PLACE
 * GET /reviews/place/:id
 */
exports.getPlaceReviews = async (req, res) => {
  try {
    const reviews = await Review.find({ place: req.params.id })
      .populate("user", "name")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: reviews.length,
      data: reviews,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
};