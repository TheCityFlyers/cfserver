// getAirlineLogo.js

const axios = require('axios');
const cheerio = require('cheerio');

const getAirlineLogo = async (airline) => {
  try {
    const formattedAirline = encodeURIComponent(airline);
    const url = `https://www.seeklogo.com/search?q=${formattedAirline}`;

    const response = await axios.get(url);
    const $ = cheerio.load(response.data);

    // Extract logo URLs
    const logoElements = $('.logo img');
    const logoUrls = logoElements.map((index, element) => $(element).attr('src')).get();

    console.log('Logo URLs:', logoUrls);

    if (logoUrls.length > 0) {
      // Return the first logo URL
      return logoUrls[0];
    } else {
      throw new Error(`Logo not found for airline: ${airline}`);
    }
  } catch (error) {
    throw error;
  }
};

module.exports = getAirlineLogo;
