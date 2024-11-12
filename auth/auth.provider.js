const jwt = require('jsonwebtoken');

class AuthProvider {
  static async authenticate(token) {
    try {
      const decoded = jwt.verify(token, process.env.SECRET_KEY, {
        algorithms: ['HS256'],
        ignoreExpiration: false,
      });
      return decoded.userId;
    } catch (error) {
      console.error('Authentication error:', error);
      throw new Error('Invalid token');
    }
  }
}

module.exports = AuthProvider;