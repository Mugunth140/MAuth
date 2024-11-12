const AuthProvider = require('./auth.provider');
const AUTHORIZATION_PREFIX = 'Bearer ';

class AuthGuard {
  async protectRoute(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith(AUTHORIZATION_PREFIX)) {
        return res.status(401).send('Unauthorized');
      }
      const token = authHeader.split(' ')[1];
      if (!token) {
        return res.status(401).send('Unauthorized');
      }
      const userId = await AuthProvider.authenticate(token);
      if (!userId) {
        return res.status(401).send('Unauthorized');
      }
      req.userId = userId;
      next();
    } catch (error) {
      console.error('Authentication error:', error);
      return res.status(500).send('Internal Server Error');
    }
  }
}

module.exports = AuthGuard;