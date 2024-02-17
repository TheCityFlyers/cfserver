const asyncHandler = require("express-async-handler");
const airports = require('airport-codes-updated').toJSON();
const { default: axios } = require("axios");
const bearerToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6InRoZWNpdHlmbHllcnNAZ21haWwuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy91c2VyZGF0YSI6IjIwOTc4fDIxNTMxfDEwMy4xMjQuMjUxLjE0NywxMDMuMTI0LjI1MS4xNDciLCJuYmYiOjE2OTczMDk4NzgsImV4cCI6MTY5NzkxNDY3OCwiaWF0IjoxNjk3MzA5ODc4LCJpc3MiOiJodHRwczovL2FwaS5mbHlodWIuY29tIiwiYXVkIjoiYXBpLmZseWh1Yi5jb20ifQ.3An4oOBAWvkVz5V8-4dFxlSd8-J_NwYcixGe2bNT0pc';
const {admin,db} = require('../config/firebaseConfig')





const accessAirportList = asyncHandler(async (req, res) => {
  try {
    const query = req.query.query.toLowerCase(); // Convert the query to lowercase for case-insensitive search

    // Create a RegEx pattern for matching the query at the beginning of name or code
    const regexPattern = new RegExp(`^${query}`, 'i'); // 'i' flag for case-insensitive search, '^' matches the start of the string

    // Filter airports that match the query using RegEx
    const filteredAirports = airports.filter((airport) =>
      regexPattern.test(airport.name) || regexPattern.test(airport.iata)||regexPattern.test(airport.city)||regexPattern.test(airport.country)
    );

    // Sort the filteredAirports to prioritize airports with matching IATA codes
    filteredAirports.sort((a, b) => {
      const aIsMatch = regexPattern.test(a.iata);
      const bIsMatch = regexPattern.test(b.iata);

      if (aIsMatch && !bIsMatch) {
        return -1;
      } else if (!aIsMatch && bIsMatch) {
        return 1;
      } else {
        return 0;
      }
    });

    // Get the first 10 matching airport IATA codes and names
    const airportList = filteredAirports
      .slice(0, 6) // Get the first 6 results
      .map((airport) => ({
        code: airport.iata, // Include IATA code
        name: airport.name, // Include airport name
        city: airport.city, // Include
        country: airport.country, // Include
      }));

    // Send the airportList array as a JSON response to the frontend
    res.json(airportList);
  } catch (error) {
    console.error('Error sending airport data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Example usage:
// app.get('/api/airports/airportList', accessAirportList);









// New route to send data into Firebase Realtime Database
const sendAirportDataToRealtimeDB = asyncHandler(async (req, res) => {
  try {
    // Create an array to store the airport data (similar to what you did for Firestore)
    const airportList = airports.toJSON().map((airport) => ({
      name: airport.name,
      iata: airport.iata,
      city: airport.city,
      country: airport.country,
    }));

    // Send the airportList data to Firebase Realtime Database
    const airportsRef = db.ref('airports'); // Replace 'airports' with your Realtime Database path

    airportList.forEach((airportData) => {
      airportsRef.push(airportData);
    });

    res.json({ message: 'Airport data inserted into Realtime Database.' });
  } catch (error) {
    console.error('Error inserting airport data into Realtime Database:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const accessAir = asyncHandler(async (req, res) => {
  try {
    // Extract the Bearer token from the request headers
    const authorizationHeader = req.headers.authorization;
    
    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Invalid or missing Bearer token' });
    }

    const bearerToken = authorizationHeader.replace('Bearer ', '');

    // Extract the request data from the request body
    const requestData = req.body;

    // Define the API URL you want to access
    const apiUrl = 'https://api.flyhub.com/api/v1/AirSearch'; // Replace with your actual API endpoint

    // Set the headers with the Bearer token
    const headers = {
      Authorization: `Bearer ${bearerToken}`,
    };

    // Make the API request using Axios
    const response = await axios.post(apiUrl, requestData, { headers });

    // Handle the response data as needed
    const responseData = response.data;
    
    // Send the response back to the client
    res.status(200).json(responseData);
  } catch (error) {
    // Handle any errors here
    console.error('Error accessing AirSearch API:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


module.exports = {accessAirportList,accessAir,sendAirportDataToRealtimeDB};
