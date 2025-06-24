const express = require("express");
const router = express.Router();
const { reportPhishingUrl, getAllReports } = require("../controllers/phishingController");

router.post("/", reportPhishingUrl);
router.get("/", getAllReports);

module.exports = router;
