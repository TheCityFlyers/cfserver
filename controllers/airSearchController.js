const axios = require('axios');
const { generateToken } = require('./generateToken');
const AIR_SEARCH_API_URL = 'https://api.flyhub.com/api/v1/AirSearch';

const airSearch = async (searchQuery) => {
  try {
// const token = await generateToken();


const token = await generateToken();
   

    const response = await axios.post(AIR_SEARCH_API_URL, searchQuery, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    return response.data;
  } catch (error) {
    throw new Error(`Error fetching air information: ${error.message}`);
  }
};

module.exports = {
  airSearch,
};
