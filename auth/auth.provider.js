const jwt = require('jsonwebtoken');

class AuthProvider {
  async authenticate(token) {
    try {
      const decoded = jwt.verify(token, process.env.SECRET_KEY);
      return decoded.userId;
    } catch (error) {
      return null;
    }
  }
}

module.exports = AuthProvider;