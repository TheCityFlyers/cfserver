const express = require('express');
const {accessAirportList,accessAir,sendAirportDataToRealtimeDB} = require('../controllers/airportSearchController')

const router = express.Router();

router.route('/airportList').get( accessAirportList);
router.route('/airportListto').get( sendAirportDataToRealtimeDB);

router.route('/airSearch').post(accessAir)


module.exports = router;