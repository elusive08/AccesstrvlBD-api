const Place = require("../models/Place");
const AccessibilityProfile = require("../models/accessibilityProfile.model");

exports.searchPlaces = async (req, res) => {
  try {
    const userId = req.user.id;
    const filters = req.query;

    let profile = await AccessibilityProfile.findOne({ user: userId });

    let query = {};

    if (profile) {
      if (profile.mobility?.wheelchair)
        query["accessibility.wheelchair"] = true;

      if (profile.visual?.braille)
        query["accessibility.braille"] = true;

      if (profile.hearing?.captions)
        query["accessibility.captions"] = true;

      if (profile.serviceAnimal)
        query["accessibility.serviceAnimal"] = true;
    }

    // Manual override filters
    Object.keys(filters).forEach((key) => {
      query[`accessibility.${key}`] = filters[key] === "true";
    });

    const places = await Place.find(query).lean();

    res.status(200).json({
      success: true,
      count: places.length,
      data: places,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Search failed",
      error: error.message,
    });
  }
};