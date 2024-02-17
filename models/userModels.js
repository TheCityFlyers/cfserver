const { firestore } = require('../config/firebaseConfig'); // Adjust the path to your Firebase configuration file

const createUser = async (uid, userData) => {
  try {
    // Create user in Firestore with the provided uid
    const userRef = firestore.collection('users').doc(uid);
    await userRef.set(userData);

    // Create user in Realtime Database (if needed)
    // ...

    console.log(`User with UID ${uid} created successfully.`);
  } catch (error) {
    console.error('Error creating user:', error);
    throw error; // Rethrow the error to handle it in the calling function
  }
};

const findUserByEmail = async (email) => {
  try {
    // Query Firestore to find user by email
    const querySnapshot = await firestore.collection('users').where('email', '==', email).get();
    
    if (querySnapshot.empty) {
      // If no matching user is found, return null
      return null;
    }

    // Extract user data from the query result (assuming only one user with a given email)
    const user = querySnapshot.docs[0].data();

    return user;
  } catch (error) {
    console.error('Error finding user by email:', error);
    throw error; // Rethrow the error to handle it in the calling function
  }
};

module.exports = {
  createUser,
  findUserByEmail,
};