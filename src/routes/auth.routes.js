// // const router = require("express").Router();
// const express = require("express");
// const router = express.Router();



// const controller = require("../controllers/auth.controller");
// const { protect } = require("../middleware/auth.middleware");

// router.post("/register", controller.register);
// router.post("/verify-email", controller.verifyEmail);
// // router.post("/login", controller.login);

// router.post("/login", authController.login);




// router.get("/me", protect, controller.me);

// router.post("/forgot-password", controller.forgotPassword);
// router.post("/reset-password", controller.resetPassword);

// module.exports = router;





const express = require("express");
const router = express.Router();

const controller = require("../controllers/auth.controller");
const { protect } = require("../middleware/auth.middleware");

router.post("/register", controller.register);
router.post("/verify-email", controller.verifyEmail);
router.post("/login", controller.login);  // Changed this line

router.get("/me", protect, controller.me);

router.post("/forgot-password", controller.forgotPassword);
router.post("/reset-password", controller.resetPassword);

module.exports = router;