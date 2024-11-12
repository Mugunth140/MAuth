const express = require('express');
const app = express();
const authRoutes = require('./routes/auth.routes');
const mongoose = require('./config/database');
const MAuth = require("./index")
const mauth = new MAuth();

app.use(express.json());
app.use('/api/auth', authRoutes);
app.use(mauth.protectRoute);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
}).on('error', (err) => {
  console.error('Error starting server:', err);
});