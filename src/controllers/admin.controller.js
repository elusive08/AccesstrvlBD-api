const Place = require("../models/Place");
const Review = require("../models/Review");
const Report = require("../models/Report");

/**
 * GET ALL PLACES
 * GET /admin/places
 */
exports.getAllPlaces = async (req, res) => {
  try {
    const places = await Place.find().sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: places.length,
      data: places,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch places",
    });
  }
};

/**
 * APPROVE PLACE
 * PATCH /admin/places/:id/approve
 */
exports.approvePlace = async (req, res) => {
  try {
    const place = await Place.findByIdAndUpdate(
      req.params.id,
      { verificationStatus: "approved" },
      { new: true }
    );

    if (!place) {
      return res.status(404).json({
        success: false,
        message: "Place not found",
      });
    }

    res.status(200).json({
      success: true,
      data: place,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to approve place",
    });
  }
};

/**
 * REJECT PLACE
 * PATCH /admin/places/:id/reject
 */
exports.rejectPlace = async (req, res) => {
  try {
    const place = await Place.findByIdAndUpdate(
      req.params.id,
      { verificationStatus: "rejected" },
      { new: true }
    );

    if (!place) {
      return res.status(404).json({
        success: false,
        message: "Place not found",
      });
    }

    res.status(200).json({
      success: true,
      data: place,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to reject place",
    });
  }
};

/**
 * GET ALL REVIEWS
 * GET /admin/reviews
 */
exports.getAllReviews = async (req, res) => {
  try {
    const reviews = await Review.find()
      .populate("user", "name email")
      .populate("place", "name");

    res.status(200).json({
      success: true,
      count: reviews.length,
      data: reviews,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch reviews",
    });
  }
};

/**
 * DELETE REVIEW
 * DELETE /admin/reviews/:id
 */
exports.deleteReview = async (req, res) => {
  try {
    const review = await Review.findByIdAndDelete(req.params.id);

    if (!review) {
      return res.status(404).json({
        success: false,
        message: "Review not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Review deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to delete review",
    });
  }
};

/**
 * GET ALL REPORTS
 * GET /admin/reports
 */
exports.getReports = async (req, res) => {
  try {
    const reports = await Report.find().sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: reports.length,
      data: reports,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch reports",
    });
  }
};

/**
 * RESOLVE REPORT
 * PATCH /admin/reports/:id/resolve
 */
exports.resolveReport = async (req, res) => {
  try {
    const report = await Report.findByIdAndUpdate(
      req.params.id,
      { status: "resolved" },
      { new: true }
    );

    if (!report) {
      return res.status(404).json({
        success: false,
        message: "Report not found",
      });
    }

    res.status(200).json({
      success: true,
      data: report,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to resolve report",
    });
  }
};