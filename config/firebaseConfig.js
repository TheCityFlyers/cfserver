// const admin = require('firebase-admin');
// const serviceAccount = require('./firebaseServiceKey/serviceAccountKey.json'); // Replace with your service account key

// let db;
// try {
//   admin.initializeApp({
//     credential: admin.credential.cert(serviceAccount),
//     databaseURL: 'https://city-flyers-7977d-default-rtdb.firebaseio.com', // Replace with your Firebase project URL
//   });

//    db = admin.database(); // Initialize Firebase Realtime Database

//   console.log('Firebase Admin SDK and Realtime Database initialized successfully.');
// } catch (error) {
//   console.error('Error initializing Firebase Admin SDK and Realtime Database:', error);
// }

// module.exports = {
//   admin,
//   db, // Export the Realtime Database instance as well
// };


const admin = require('firebase-admin');
const serviceAccount = require('./firebaseServiceKey/serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://console.firebase.google.com/project/thecityflyerss/database/thecityflyerss-default-rtdb/data/~2F'
});

const firestore = admin.firestore(); // Initialize Firestore

module.exports = {
  firestore: firestore,
  // ... other exports if needed
};
