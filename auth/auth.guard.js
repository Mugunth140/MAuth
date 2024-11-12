const AuthProvider = require('./auth.provider');

class AuthGuard {
  async protectRoute(req, res, next) {
    const token = req.headers.authorization;
    const userId = await AuthProvider.authenticate(token);
    if (!userId) {
      return res.status(401).send('Unauthorized');
    }
    req.userId = userId;
    next();
  }
}

module.exports = AuthGuard;