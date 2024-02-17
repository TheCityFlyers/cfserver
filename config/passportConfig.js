const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { createUser } = require('../models/userModels'); // Import the function to create a new user

passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the number of salt rounds

    // Create user data object
    const userData = {
      email: email,
      password: hashedPassword,
    };

    // Save user data in your database (e.g., Firebase Firestore)
    await createUser(userData);

    // If user creation is successful, return the user object
    return done(null, userData);
  } catch (error) {
    return done(error);
  }
}));

// Serialize user to store in the session
passport.serializeUser((user, done) => {
  done(null, user.email); // Using email as the user identifier
});

// Deserialize user from the session
passport.deserializeUser(async (email, done) => {
  try {
    // Implement logic to find user by email and return the user object
    // For example, if you are using Firebase Admin SDK:
    // const user = await admin.auth().getUserByEmail(email);
    // return done(null, user);
    return done(null, { email: email }); // Dummy example without actual database query
  } catch (error) {
    done(error);
  }
});

module.exports = passport;
