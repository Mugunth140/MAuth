const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./user.model');

class AuthService {
  async register(user) {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    const newUser = await User.create({ ...user, password: hashedPassword });
    return newUser;
  }

  async login(user) {
    const existingUser = await User.findOne({ email: user.email });
    if (!existingUser) {
      throw new Error('Invalid credentials');
    }
    const isValidPassword = await bcrypt.compare(user.password, existingUser.password);
    if (!isValidPassword) {
      throw new Error('Invalid credentials');
    }
    const token = jwt.sign({ userId: existingUser.id }, process.env.SECRET_KEY, {
      expiresIn: '1h',
    });
    return token;
  }
}

module.exports = AuthService;