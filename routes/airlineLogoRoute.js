// airlineLogoRoute.js

const express = require('express');
const router = express.Router();

const getAirlineLogo = require('../controllers/getAirlineLogo');

router.post('/airlineLogo', async (req, res) => {
  try {
    const { airline } = req.body;

    if (!airline) {
      return res.status(400).json({ error: 'Missing airline parameter' });
    }

    const logo = await getAirlineLogo(airline);
    res.json({ logo });
  } catch (error) {
    let errorMessage;

    if (error.message.includes('Logo not found for airline:')) {
      errorMessage = 'Logo not found';
    } else {
      console.error('Error fetching airline logo:', error);
      errorMessage = 'Internal Server Error';
    }

    res.status(404).json({ error: errorMessage });
  }
});

module.exports = router;
