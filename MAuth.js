class MAuth {
    constructor() {
      this.authService = new AuthService();
      this.authProvider = new AuthProvider();
      this.authGuard = new AuthGuard();
      this.userModel = require('./auth/user.model');
    }
  
    async register(user) {
      return this.authService.register(user);
    }
  
    async login(user) {
      return this.authService.login(user);
    }
  
    async authenticate(token) {
      return this.authProvider.authenticate(token);
    }
  
    protectRoute(req, res, next) {
      return this.authGuard.protectRoute(req, res, next);
    }
  }
  
  module.exports = MAuth;