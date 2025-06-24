const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const phishingRoutes = require("./routes/phishingRoutes");

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
app.use("/api/phishing", phishingRoutes);

mongoose.connect(process.env.MONGO_URI).then(() => {
  console.log("MongoDB connected");
  app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
  });
}).catch((err) => {
  console.error("Connection error", err);
});
