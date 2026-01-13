const express = require("express");
const router = express.Router();
const { searchPlaces } = require("../controllers/place.search.controller");
const auth = require("../middleware/auth.middleware");

// console.log("searchPlaces:", searchPlaces);
// console.log("typeof searchPlaces:", typeof searchPlaces);
// console.log("auth:", auth);
// console.log("typeof auth:", typeof auth);


router.get("/places/search", auth.protect, searchPlaces); // ✅ Use auth.protect



// router.get("/places/search", auth, searchPlaces);

module.exports = router;