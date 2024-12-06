Here's an expanded `README.md` file for your authentication system, including installation with `m-auth`:

```markdown
# Authentication System

## Overview
This authentication system provides a secure way to manage user registration, login, and protected routes using JSON Web Tokens (JWT).

## Features
- User registration with email and password
- User login with email and password
- Token-based authentication using JWT
- Protected routes with authentication guard
- Error handling and logging

## Dependencies
- **express**: Node.js web framework
- **jsonwebtoken**: JWT implementation
- **bcrypt**: Password hashing
- **mongoose**: MongoDB ORM

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Mugunth140/MAuth.git
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Install the `m-auth` package:**
   ```bash
   npm i m-auth
   ```

4. **Set environment variables:**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   Update the `.env` file with your configuration (e.g., JWT secret, database URL).

5. **Start the server:**
   ```bash
   npm run dev
   ```

## API Endpoints

### User Registration
- **URL**: `/mauth/register`
- **Method**: `POST`
- **Request Body**: 
  ```json
  {
    "name": "mugunth",
    "email": "mugunth@mugunth.me",
    "password": "strong_password"
  }
  ```
- **Response**:
  ```json
  {
    "user": {
      "_id": "user_id",
      "email": "user@example.com"
    }
  }
  ```

### User Login
- **URL**: `/mauth/login`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "your_password"
  }
  ```
- **Response**:
  ```json
  {
    "token": "jwt_token"
  }
  ```

### Protected Route
- **URL**: `/mauth/protected`
- **Method**: `GET`
- **Request Header**:
  - `Authorization: Bearer <token>`
- **Response**:
  ```json
  {
    "message": "Protected content"
  }
  ```

## Error Handling

- **Validation Errors**: `400 Bad Request`
- **Authentication Errors**: `401 Unauthorized`
- **Internal Server Errors**: `500 Internal Server Error`

## Security Considerations
- Use **bcrypt** for secure password hashing.
- Keep the JWT secret key secure.
- Validate all user inputs to prevent attacks.
- Use HTTPS in production for secure data transmission.

## Database Schema

### User Model
- **name**: `String`
- **email**: `String`
- **password**: `String` (hashed)

## Code Structure

- **server.js**: Main server file.
- **routes/**: Route files.
- **auth/**: Authentication files.
- **models/**: Database model files.

## License
This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).

## Author
Mugunth140

## Acknowledgments
- Thanks to [OWASP](https://owasp.org/) for security guidelines.
- The open-source community for best practices.
