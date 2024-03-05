const asyncHandler = require("express-async-handler");
const jwt = require('jsonwebtoken');

const { createUser, findUserByEmail } = require('../models/userModels');

const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const { promisify } = require('util');
const pbkdf2Async = promisify(crypto.pbkdf2);

// Signup Route
const registration = async (req, res) => {
  try {
    const { email, password, phoneNumber, firstName, lastName } = req.body;

    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = await pbkdf2Async(password, salt, 1000, 64, 'sha512');
      const hashedPassword = hash.toString('hex');

      const updatedUserData = {
        email,
        password: hashedPassword,
        salt, // Store salt for later verification
        phoneNumber,
        firstName,
        lastName,
      };

      await updateUser(existingUser.uid, updatedUserData);
      const token = generateToken({ ...updatedUserData, uid: existingUser.uid });

      return res.status(200).json({ message: 'User updated successfully', token, userId: existingUser.uid });
    } else {
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = await pbkdf2Async(password, salt, 1000, 64, 'sha512');
      const hashedPassword = hash.toString('hex');

      const userId = uuidv4();
      const userData = {
        email,
        password: hashedPassword,
        salt, // Remember to store the salt along with the hashed password
        phoneNumber,
        firstName,
        lastName,
      };

      await createUser(userId, userData);
      const token = generateToken({ ...userData, uid: userId });

      return res.status(200).json({ token, userId });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Error processing request' });
  }
};

// Login Route
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const user = await findUserByEmail(email);

  if (user) {
    // Check if the provided password matches the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      // If passwords match, generate JWT token and send it in the response
      const token = generateToken(user);
      res.status(200).json({ token });
    } else {
      // If passwords do not match, return authentication error
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } else {
    // If user with the provided email is not found, return authentication error
    res.status(401).json({ message: 'User not found' });
  }
});

// Example route in your Express.js backend
const userCreate= asyncHandler ( async (req, res) => {
  try {
    const { uid, email, firstName, lastName } = req.body;
    // Check if user already exists
    const existingUser = await findUserByUid(uid);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    // Create new user
    const user = await createUser({ uid, email, firstName, lastName });
    res.status(200).json({ message: 'User created successfully', user });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Error creating user' });
  }
});


module.exports = {
  registration,
  login,
  userCreate
};
