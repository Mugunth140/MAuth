const AuthService = require('./auth/auth.service');
const AuthProvider = require('./auth/auth.provider');
const AuthGuard = require('./auth/auth.guard');

class MAuth {
  constructor() {
    this.authService = new AuthService();
    this.authProvider = new AuthProvider();
    this.authGuard = new AuthGuard();
    this.userModel = require('./auth/user.model');
  }

  async register(user) {
    try {
      if (!user || !user.email || !user.password) {
        throw new Error('Invalid user data');
      }
      return this.authService.register(user);
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  }

  async login(user) {
    try {
      if (!user || !user.email || !user.password) {
        throw new Error('Invalid user data');
      }
      return this.authService.login(user);
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  }

  async authenticate(token) {
    try {
      if (!token) {
        throw new Error('Missing token');
      }
      return this.authProvider.authenticate(token);
    } catch (error) {
      console.error('Authentication error:', error);
      throw error;
    }
  }

  protectRoute(req, res, next) {
    return this.authGuard.protectRoute(req, res, next);
  }
}

module.exports = MAuth;