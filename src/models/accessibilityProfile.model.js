const mongoose = require("mongoose");

const accessibilityProfileSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
    },

    mobility: {
      wheelchair: { type: Boolean, default: false },
      rollInShower: { type: Boolean, default: false },
      stepFreeAccess: { type: Boolean, default: false },
    },

    visual: {
      braille: { type: Boolean, default: false },
      audioGuides: { type: Boolean, default: false },
    },

    hearing: {
      captions: { type: Boolean, default: false },
      signLanguage: { type: Boolean, default: false },
    },

    cognitive: {
      easyNavigation: { type: Boolean, default: false },
      lowSensory: { type: Boolean, default: false },
    },

    serviceAnimal: {
      allowed: { type: Boolean, default: false },
    },

    sensory: {
      lowNoise: { type: Boolean, default: false },
      lowLight: { type: Boolean, default: false },
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model(
  "AccessibilityProfile",
  accessibilityProfileSchema
);