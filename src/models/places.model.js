// src/models/place.model.js
const mongoose = require("mongoose");

const placeSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },

    category: {
      type: String,
      required: true,
      enum: ["hotel", "restaurant", "attraction", "transport"]
    },

    location: {
      address: { type: String },
      city: { type: String },
      country: { type: String }
    },

    accessibility: {
      wheelchair: { type: Boolean, default: false },
      visual: { type: Boolean, default: false },
      hearing: { type: Boolean, default: false },
      serviceAnimal: { type: Boolean, default: false }
    },

    photos: [{ type: String }],

    verified: {
      type: Boolean,
      default: false
    }
  },
  { timestamps: true }
);


const Place = mongoose.models.Place || mongoose.model("Place", placeSchema);
module.exports = Place;

// module.exports = mongoose.model("Place", placeSchema);