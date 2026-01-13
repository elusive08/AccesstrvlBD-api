// const mongoose = require("mongoose");

// const placeSchema = new mongoose.Schema(
//   {
//     name: {
//       type: String,
//       required: true,
//       trim: true,
//     },

//     category: {
//       type: String,
//       enum: ["hotel", "restaurant", "attraction", "transport"],
//       required: true,
//     },

//     description: {
//       type: String,
//       trim: true,
//     },

//     location: {
//       address: String,
//       city: String,
//       state: String,
//       country: String,
//       coordinates: {
//         lat: Number,
//         lng: Number,
//       },
//     },

//     accessibility: {
//       wheelchairAccessible: { type: Boolean, default: false },
//       brailleSignage: { type: Boolean, default: false },
//       hearingAssistance: { type: Boolean, default: false },
//       serviceAnimalAllowed: { type: Boolean, default: false },
//       accessibleRestroom: { type: Boolean, default: false },
//     },

//     photos: [
//       {
//         url: String,
//         uploadedAt: { type: Date, default: Date.now },
//       },
//     ],

//     verificationStatus: {
//       type: String,
//       enum: ["pending", "verified", "rejected"],
//       default: "pending",
//     },

//     createdBy: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "User",
//       required: true,
//     },
//   },
//   { timestamps: true }
// );

// module.exports = mongoose.model("Place", placeSchema);
// module.exports = mongoose.models.Place || mongoose.model("Place", placeSchema);






const mongoose = require("mongoose");

const placeSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    category: {
      type: String,
      enum: ["hotel", "restaurant", "attraction", "transport"],
      required: true,
    },

    description: {
      type: String,
      trim: true,
    },

    location: {
      address: String,
      city: String,
      state: String,
      country: String,
      coordinates: {
        lat: Number,
        lng: Number,
      },
    },

    accessibility: {
      wheelchairAccessible: { type: Boolean, default: false },
      brailleSignage: { type: Boolean, default: false },
      hearingAssistance: { type: Boolean, default: false },
      serviceAnimalAllowed: { type: Boolean, default: false },
      accessibleRestroom: { type: Boolean, default: false },
    },

    photos: [
      {
        url: String,
        uploadedAt: { type: Date, default: Date.now },
      },
    ],

    verificationStatus: {
      type: String,
      enum: ["pending", "verified", "rejected"],
      default: "pending",
    },

    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true }
);

// Only this export – removes overwrite risk
module.exports = mongoose.models.Place || mongoose.model("Place", placeSchema);