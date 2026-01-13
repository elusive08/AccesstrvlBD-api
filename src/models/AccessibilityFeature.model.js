const mongoose = require("mongoose");

const accessibilityFeatureSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },
    category: {
      type: String,
      required: true,
      enum: [
        "mobility",
        "visual",
        "hearing",
        "cognitive",
        "service_animal",
        "sensory"
      ]
    },
    description: {
      type: String,
      default: ""
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model(
  "AccessibilityFeature",
  accessibilityFeatureSchema
);