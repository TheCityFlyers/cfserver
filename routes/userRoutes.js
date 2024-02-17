const express = require('express');
const router = express.Router();


const { registration,login,userCreate } = require('../controllers/userControllers'); // Assuming registration function is exported from userControllers.js

router.post('/registration', registration);
router.post('/login',login);
router.post ('/userCreate',userCreate);
module.exports = router;

