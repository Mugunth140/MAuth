const express = require('express');
const app = express();
const authRoutes = require('./routes/auth.routes');
const mongoose = require('./config/database');
const MAuth = require("./MAuth")
const mauth = new MAuth();

console.log(mauth)

app.use(express.json());
app.use('/mauth', authRoutes);
app.use(mauth.protectRoute);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
}).on('error', (err) => {
  console.error('Error starting server:', err);
});