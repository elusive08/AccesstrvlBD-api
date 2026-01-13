const express = require("express");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const connectDB = require("./config/db");





const cors = require("cors");
app.use(cors());




const placeRoutes = require("./routes/place.routes.js");

connectDB();


app.use("/profile", require("./routes/accessibilityProfile.routes"));

app.use("/places", placeRoutes);

app.use("/auth", require("./routes/auth.routes"));

app.use("/places", require("./routes/place.routes"));


app.use("/reviews", require("./routes/review.routes"));


const accessibilityFeatureRoutes = require(
  "./routes/accessibilityFeature.routes"
);

app.use("/accessibility-features", accessibilityFeatureRoutes);

app.use("/places", placeRoutes);

const adminRoutes = require("./routes/admin.routes");

app.use("/api/admin", adminRoutes);



const reviewVoteRoutes = require("./routes/reviewVote.routes");

app.use("/api", reviewVoteRoutes);

// const adminRoutes = require("./routes/admin.routes");

// app.use("/admin", adminRoutes);




app.use("/api", require("./routes/search.routes"));
app.use("/api", require("./routes/reviewVote.routes"));
app.use("/api", require("./routes/report.routes"));
app.use("/api", require("./routes/admin.routes"));




app.use("/trips", require("./routes/trip.routes"));


// module.exports = router;
module.exports = app;