// airSearchRoutes.js

const express = require('express');
const router = express.Router();
const airPreBook = require('../controllers/airPreBook');

router.route('/airPreBook').post(async (req, res) => {
  try {
    // Assuming you want to use the request body as the search query
    const searchQuery = req.body;
    const result = await airPreBook.airPreBook(searchQuery);
    res.status(200).json(result);
  } catch (error) {
    console.error('Error in air search:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
