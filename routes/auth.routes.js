const express = require('express');
const router = express.Router();
const AuthService = require('../auth/auth.service');
const AuthGuard = require('../auth/auth.guard');

const authService = new AuthService();
const authGuard = new AuthGuard();

router.post('/register', async (req, res) => {
  const user = req.body;
  const newUser = await authService.register(user);
  res.send(newUser);
});

router.post('/login', async (req, res) => {
  const user = req.body;
  const token = await authService.login(user);
  res.send({ token });
});

router.post("/forgotpassword", async (req, res) => {
  const user = req.body
});

router.get('/protected', authGuard.protectRoute, (req, res) => {
  res.send(`Hello, ${req.userId}!`);
});

module.exports = router;