const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    place: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Place",
      required: true,
    },

    accessibilityRatings: {
      mobility: { type: Number, min: 1, max: 5, required: true },
      visual: { type: Number, min: 1, max: 5, required: true },
      hearing: { type: Number, min: 1, max: 5, required: true },
      cognitive: { type: Number, min: 1, max: 5, required: true },
      serviceAnimal: { type: Number, min: 1, max: 5, required: true },
    },

    structuredQuestions: {
      wheelchairAccessibleEntrance: { type: Boolean },
      accessibleToilets: { type: Boolean },
      brailleSignage: { type: Boolean },
      audioAssistance: { type: Boolean },
    },

    dateOfVisit: {
      type: Date,
      required: true,
    },

    comment: {
      type: String,
      trim: true,
      maxlength: 1000,
    },

    photos: [
      {
        type: String, // Cloudinary/S3 URL or media ID
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.model("Review", reviewSchema);