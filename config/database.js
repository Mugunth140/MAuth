const mongoose = require('mongoose');

mongoose.set('strictQuery', false);
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI);

module.exports = mongoose;