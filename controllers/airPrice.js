// const axios = require('axios');

// const AIR_PRICE_API_URL = 'https://api.flyhub.com/api/v1/AirPrice';
// const AirRulesURL = 'https://api.flyhub.com/api/v1/AirRules';
// const AirPromotionURL = 'https://api.flyhub.com/api/v1/AirPromotion';

// const airPrice = async (searchQuery) => {
//   try {
//     const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InRoZWNpdHlmbHllcnNAZ21haWwuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy91c2VyZGF0YSI6IjIwOTc4fDIxNTMxfDEwMy4xMjQuMjUxLjE0NywxODIuMjUyLjgwLjIiLCJuYmYiOjE3MDU4MTk0NTQsImV4cCI6MTcwNjQyNDI1NCwiaWF0IjoxNzA1ODE5NDU0LCJpc3MiOiJodHRwczovL2FwaS5mbHlodWIuY29tIiwiYXVkIjoiYXBpLmZseWh1Yi5jb20ifQ.I25QsqWeGzo8TisiOAwYF4iR7BimlTq0jc8t6b2dDNg'; // Replace with your actual bearer token

//     const response = await axios.post(AIR_PRICE_API_URL, searchQuery, {
//       headers: {
//         Authorization: `Bearer ${token}`,
//       },
//     });

//     return response.data;
//   } catch (error) {
//     throw new Error(`Error fetching air information: ${error.message}`);
//   }
// };

// module.exports = {
//   airPrice,
// };


const axios = require('axios');
const { generateToken } = require('./generateToken');
const AIR_PRICE_API_URL = 'https://api.flyhub.com/api/v1/AirPrice';
const AIR_RULES_URL = 'https://api.flyhub.com/api/v1/AirRules';
const AIR_PROMOTION_URL = 'https://api.flyhub.com/api/v1/AirPromotion';

const airPrice = async (searchQuery) => {
  try {
      const token = await generateToken();
    // First API call to AirPrice
    const airPriceResponse = await axios.post(AIR_PRICE_API_URL, searchQuery, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    // Check if AirPrice response is successful
    if (airPriceResponse && airPriceResponse.data) {
      // Second API call to AirRules
      const airRulesResponse = await axios.post(AIR_RULES_URL, searchQuery, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      // Third API call to AirPromotion
      const airPromotionResponse = await axios.post(AIR_PROMOTION_URL, searchQuery, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      // Attach AirRules and AirPromotion responses to the AirPrice response
      airPriceResponse.data.airRules = airRulesResponse.data;
      airPriceResponse.data.airPromotion = airPromotionResponse.data;

      return airPriceResponse.data;
    } else {
      throw new Error('AirPrice API response is not successful.');
    }
  } catch (error) {
    throw new Error(`Error fetching air information: ${error.message}`);
  }
};

module.exports = {
  airPrice,
};
