const axios = require('axios');

const AirPreBookURL = 'https://api.flyhub.com/api/v1/AirPreBook';
const AirBookURL = 'https://api.flyhub.com/api/v1/AirBook';
const { generateToken } = require('./generateToken');

const airPreBook = async (searchQuery) => {
  try {
            const token = await generateToken();

    // Call AirPreBook API
    const preBookResponse = await axios.post(AirPreBookURL, searchQuery, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    // Extract relevant data from the AirPreBook response, assuming there is some specific data you need
    const airPreBookData = preBookResponse.data;

    // Call AirBook API with the same searchQuery and token
    const bookResponse = await axios.post(AirBookURL, searchQuery, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    // Extract relevant data from the AirBook response, assuming there is some specific data you need
    const airBookData = bookResponse.data;


    
    // Combine the data from both responses or do any further processing as needed
    const combinedData = {
      airPreBookData,
      airBookData,
    };

    return airBookData;
  } catch (error) {
    throw new Error(`Error fetching air information: ${error.message}`);
  }
};

module.exports = {
  airPreBook,
};
