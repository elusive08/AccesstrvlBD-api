const Place = require("../models/Place");

/**
 * CREATE PLACE
 * POST /places/create
 */
exports.createPlace = async (req, res) => {
  try {
    const place = await Place.create({
      ...req.body,
      createdBy: req.user.id,
    });

    res.status(201).json({
      success: true,
      data: place,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * UPDATE PLACE
 * PUT /places/update/:id
 */
exports.updatePlace = async (req, res) => {
  try {
    const place = await Place.findById(req.params.id);

    if (!place) {
      return res.status(404).json({ message: "Place not found" });
    }

    // Only creator or admin can update
    if (
      place.createdBy.toString() !== req.user.id &&
      req.user.role !== "admin"
    ) {
      return res.status(403).json({ message: "Not authorized" });
    }

    const updatedPlace = await Place.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json({
      success: true,
      data: updatedPlace,
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

/**
 * GET PLACE BY ID
 * GET /places/:id
 */
exports.getPlaceById = async (req, res) => {
  try {
    const place = await Place.findById(req.params.id).populate(
      "createdBy",
      "name email"
    );

    if (!place) {
      return res.status(404).json({ message: "Place not found" });
    }

    res.json({
      success: true,
      data: place,
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};




exports.searchPlaces = async (req, res) => {
  try {
    const {
      wheelchair,
      visual,
      hearing,
      serviceAnimal,
      category,
      city
    } = req.query;

    const filter = {};

    if (wheelchair !== undefined) {
      filter["accessibility.wheelchair"] = wheelchair === "true";
    }

    if (visual !== undefined) {
      filter["accessibility.visual"] = visual === "true";
    }

    if (hearing !== undefined) {
      filter["accessibility.hearing"] = hearing === "true";
    }

    if (serviceAnimal !== undefined) {
      filter["accessibility.serviceAnimal"] = serviceAnimal === "true";
    }

    if (category) {
      filter.category = category;
    }

    if (city) {
      filter["location.city"] = city;
    }

    const places = await Place.find(filter)
      .sort({ createdAt: -1 })
      .limit(20);

    res.status(200).json({
      success: true,
      count: places.length,
      data: places
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Search failed",
      error: error.message
    });
  }
};