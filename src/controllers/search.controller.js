

// src/controllers/place.search.controller.js
const Place = require("../models/places.model");

const searchPlaces = async (req, res) => {
  try {
    const {
      wheelchair,
      visual,
      hearing,
      serviceAnimal,
      category,
      city
    } = req.query;

    const query = {};

    if (wheelchair !== undefined) {
      query["accessibility.wheelchair"] = wheelchair === "true";
    }

    if (visual !== undefined) {
      query["accessibility.visual"] = visual === "true";
    }

    if (hearing !== undefined) {
      query["accessibility.hearing"] = hearing === "true";
    }

    if (serviceAnimal !== undefined) {
      query["accessibility.serviceAnimal"] = serviceAnimal === "true";
    }

    if (category) query.category = category;
    if (city) query["location.city"] = city;

    const places = await Place.find(query)
      .sort({ createdAt: -1 })
      .limit(20);

    return res.status(200).json({
      success: true,
      count: places.length,
      data: places
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Unable to search places",
      error: error.message
    });
  }
};

// ✅ CommonJS export — NO `export` keyword
module.exports = { searchPlaces };