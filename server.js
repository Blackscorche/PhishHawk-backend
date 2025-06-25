import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import phishingRoutes from "./routes/phishingRoutes.js";

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());
app.use("/api/phishing", phishingRoutes);

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    app.listen(process.env.PORT || 5000, () =>
      console.log("Server running on port", process.env.PORT || 5000)
    );
  })
  .catch(err => console.error("MongoDB error:", err));
