const express = require("express");
// const router = express.Router();


const router = express.Router();


const { protect, authorize } = require("../middleware/auth.middleware");


const role = require("../middleware/role.middleware");
const {
  getReports,
  resolveReport,
} = require("../controllers/admin.controller");







// GET flagged reviews (basic moderation)
router.get(
  "/reviews",
  protect,
  authorize("admin", "moderator"),
  async (req, res) => {
    res.status(200).json({
      success: true,
      message: "Admin reviews endpoint working",
    });
  }
);

// GET places pending verification
router.get(
  "/places",
  protect,
  authorize("admin", "moderator"),
  async (req, res) => {
    res.status(200).json({
      success: true,
      message: "Admin places endpoint working",
    });
  }
);



const Report = require("../models/Report");
const Review = require("../models/Review");
const Place = require("../models/Place");

exports.getReports = async (req, res) => {
  const reports = await Report.find({ status: "pending" });
  res.status(200).json({ success: true, data: reports });
};

exports.resolveReport = async (req, res) => {
  const { id } = req.params;

  await Report.findByIdAndUpdate(id, { status: "resolved" });

  res.status(200).json({
    success: true,
    message: "Report resolved",
  });
};







// router.get("/admin/reports", auth, getReports);
// router.put("/admin/reports/:id", auth, role("admin"), resolveReport);







// const { protect, authorize } = require("../middleware/auth.middleware");
// const role = require("../middleware/role.middleware");

// const {
//   getReports,
//   resolveReport,
// } = require("../controllers/admin.controller");

// ADMIN REPORT ROUTES
router.get(
  "/admin/reports",
  protect,
  authorize("admin"),
  getReports
);

router.put(
  "/admin/reports/:id",
  protect,
  authorize("admin"),
  resolveReport
);





module.exports = router;