
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const userRoutes = require('./routes/userRoutes');

const airportSearchRoutes = require('./routes/airportSearchRoutes');
const airSearchRoutes = require('./routes/airSearchRoutes')
const airPriceRoute = require('./routes/airPriceRoute');
const airPreBook = require('./routes/airPreBook');
const logoRoutes = require('./routes/airlineLogoRoute')
const app = express();
const port = process.env.PORT || 5000;



const allData = require('airline-iata-code')

const data = allData();
// console.log(data);

app.use(bodyParser.json());
app.use(cors());



// Set up your routes
app.use('/api/user', userRoutes);
app.use('/api/airports', airportSearchRoutes);
app.use('/api',airSearchRoutes);
app.use('/api',airPriceRoute);
app.use('/api',airPreBook);
app.use('/api',logoRoutes)

// app.use('/api/logos', logosRoutes);
app.get('/', (req, res) => {
  res.send('Hello, World!');
});

// API endpoint to get airline information
app.get('/api/airline/:code', async (req, res) => {
  const airlineCode = req.params.code.toUpperCase(); // Ensure it's uppercase


  try {
    // Convert the object to an array
    const dataArray = Object.values(data);


    // Find the airline with the provided code
    const airline = dataArray.find((item) => item.IATACode === airlineCode);

    if (airline) {
      res.json({ logoUrl: airline.logo });
    } else {
      res.status(404).json({ error: 'Airline not found' });
    }
  } catch (error) {
    console.error('Error fetching airline logo:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});


