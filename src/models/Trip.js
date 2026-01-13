// const mongoose = require("mongoose");

// const tripSchema = new mongoose.Schema(
//   {
//     user: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "User",
//       required: true,
//     },

//     destination: {
//       type: String,
//       required: true,
//     },

//     startDate: Date,
//     endDate: Date,

//     accessibilityProfile: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "AccessibilityProfile",
//       required: true,
//     },

//     stops: [
//       {
//         type: mongoose.Schema.Types.ObjectId,
//         ref: "TripStop",
//       },
//     ],
//   },
//   { timestamps: true }
// );

// module.exports = mongoose.model("Trip", tripSchema);





const mongoose = require("mongoose");

const tripSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    destination: {
      type: String,
      required: true,
      trim: true,
    },

    startDate: {
      type: Date,
      required: true,
    },

    endDate: {
      type: Date,
      required: true,
    },

    accessibilityProfile: {
      mobility: Boolean,
      visual: Boolean,
      hearing: Boolean,
      cognitive: Boolean,
      serviceAnimal: Boolean,
    },

    status: {
      type: String,
      enum: ["planned", "ongoing", "completed"],
      default: "planned",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Trip", tripSchema);