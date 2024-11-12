require('dotenv').config();

module.exports = {
  SECRET_KEY: process.env.SECRET_KEY,
  MONGODB_URI: process.env.MONGODB_URI,
};