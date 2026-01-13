const Report = require("../models/Report");

exports.createReport = async (req, res) => {
  try {
    const report = await Report.create({
      ...req.body,
      reportedBy: req.user.id,
    });

    res.status(201).json({
      success: true,
      data: report,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Report failed",
      error: error.message,
    });
  }
};