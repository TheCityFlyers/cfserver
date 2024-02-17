const axios = require('axios');
const jwt = require('jsonwebtoken');

let cachedToken = null;

const AUTH_API_URL = 'https://api.flyhub.com/api/v1/Authenticate';

const credentials = {
  username: 'thecityflyers@Gmail.com',
  apikey: 'g5TiX28v20Dg6BXkLpuTNUk7vEFCFo9igmOwXNvZulqKCoBHcO',
};

const generateToken = async () => {
  try {
    if (cachedToken) {
      // Check if the cached token is expired
      const decodedToken = jwt.decode(cachedToken);

      const currentTimestamp = Math.floor(Date.now() / 1000);
      if (decodedToken.exp > currentTimestamp) {
        // Token is not expired, use the cached token
        console.log('Using cached token:', cachedToken);
        return cachedToken;
      }
    }

    // If the cached token is expired or doesn't exist, generate a new token
    const response = await axios.post(AUTH_API_URL, credentials);

    if (response.status === 200 && response.data && response.data.TokenId) {
      const { TokenId, ExpireTime } = response.data;
      console.log('Generated new token:', TokenId);

      // Store the new token in the variable
      cachedToken = TokenId;

      return TokenId;
    } else {
      throw new Error('Failed to generate token. Check credentials.');
    }
  } catch (error) {
    throw new Error(`Error generating token: ${error.message}`);
  }
};

module.exports = {
  generateToken,
};
