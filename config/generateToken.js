const jwt = require('jsonwebtoken');

const generateToken = (payload) => {
  // Replace 'YOUR_SECRET_KEY' with your actual secret key
  const secretKey = 'paroshmahmud';

  // Generate JWT token with the payload and secret key
  const token = jwt.sign(payload, secretKey, { expiresIn: '1h' }); // Token expires in 1 hour

  return token;
};

module.exports = generateToken;
