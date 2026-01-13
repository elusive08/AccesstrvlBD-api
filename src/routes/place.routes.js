// const express = require("express");
// const router = express.Router();
// // const { searchPlaces } = require("../controllers/place.controller.js");
// const { searchPlaces } = require("../controllers/place.search.controller");
// const {
//   createPlace,
//   updatePlace,
//   getPlaceById,
// } = require("../controllers/place.controller");

// const { protect } = require("../middleware/auth.middleware");






// // router.get("/search", searchPlaces);

// router.post("/create", protect, createPlace);
// router.put("/update/:id", protect, updatePlace);

// router.get("/search", searchPlaces);



// router.get("/:id", getPlaceById);



// //




// module.exports = router;









const express = require("express");
const router = express.Router();

const { searchPlaces } = require("../controllers/place.search.controller");
const {
  createPlace,
  updatePlace,
  getPlaceById,
} = require("../controllers/place.controller");

const { protect } = require("../middleware/auth.middleware");

// Routes
router.post("/create", protect, createPlace);
router.put("/update/:id", protect, updatePlace);
router.get("/search", searchPlaces);
router.get("/:id", getPlaceById);

module.exports = router;