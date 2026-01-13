const express = require("express");
const router = express.Router();
const { createReport } = require("../controllers/report.controller");
const { protect } = require("../middleware/auth.middleware");

router.post("/reports", protect, createReport);

module.exports = router;