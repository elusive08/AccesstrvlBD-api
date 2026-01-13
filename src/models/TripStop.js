const mongoose = require("mongoose");

const tripStopSchema = new mongoose.Schema(
  {
    trip: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Trip",
      required: true,
    },

    place: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Place",
      required: true,
    },

    type: {
      type: String,
      enum: ["hotel", "attraction", "transport"],
      required: true,
    },

    notes: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("TripStop", tripStopSchema);