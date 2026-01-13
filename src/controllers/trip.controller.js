const Trip = require("../models/Trip");
const TripStop = require("../models/TripStop");
const accessibilityProfile = require("../models/accessibilityProfile.model.js");
const {
  findAccessiblePlaces,
} = require("../services/tripPlanner.service");

/**
 * CREATE TRIP
 * POST /trips/create
 */
exports.createTrip = async (req, res) => {
  try {
    const { destination, startDate, endDate } = req.body;

    const profile = await AccessibilityProfile.findOne({
      user: req.user.id,
    });

    if (!profile) {
      return res.status(400).json({
        success: false,
        message: "Accessibility profile not found",
      });
    }

    const trip = await Trip.create({
      user: req.user.id,
      destination,
      startDate,
      endDate,
      accessibilityProfile: profile._id,
    });

    res.status(201).json({
      success: true,
      data: trip,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
};

/**
 * GET TRIP DETAILS
 * GET /trips/:id
 */
exports.getTrip = async (req, res) => {
  try {
    const trip = await Trip.findById(req.params.id)
      .populate("stops")
      .populate("accessibilityProfile");

    if (!trip) {
      return res.status(404).json({
        success: false,
        message: "Trip not found",
      });
    }

    res.json({
      success: true,
      data: trip,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
};

/**
 * GET TRIP SUGGESTIONS
 * GET /trips/suggestions
 */
exports.getTripSuggestions = async (req, res) => {
  try {
    const { destination } = req.query;

    const profile = await AccessibilityProfile.findOne({
      user: req.user.id,
    });

    if (!profile) {
      return res.status(400).json({
        success: false,
        message: "Accessibility profile missing",
      });
    }

    const places = await findAccessiblePlaces(destination, profile);

    res.json({
      success: true,
      count: places.length,
      data: places,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
};