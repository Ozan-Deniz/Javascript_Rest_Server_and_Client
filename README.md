# Authentication Server with JWT and PostgreSQL

This is an Express-based authentication server that utilizes JWT (JSON Web Tokens) for secure user authentication and PostgreSQL as a database to store user credentials. The server supports user registration, login, logout, and token refresh functionalities. It is also equipped with rate-limiting to prevent abuse of the registration endpoint.

## Features:
- User registration with email and password.
- Login functionality with JWT-based authentication.
- Token-based authentication (access and refresh tokens).
- Refresh tokens to keep the user logged in for a long period.
- Logout functionality that invalidates the refresh token.
- Rate limiting to prevent abuse of the registration endpoint.
- Secure password hashing using bcrypt.

## Technologies:
- **Express.js**: A fast, unopinionated web framework for Node.js.
- **PostgreSQL**: A relational database for storing user credentials.
- **JWT (JSON Web Tokens)**: Used for secure user authentication and token-based sessions.
- **bcrypt**: For securely hashing passwords.
- **rate-limit**: To limit the rate of requests to certain endpoints.

## Installation

To get started with this project, follow the steps below.

### 1. Clone the repository

```bash
git clone https://github.com/your-username/authentication-server.git
cd authentication-server
```

### 2. Install dependencies
```bash
npm install
```

### 3. Setup environment variables
Edit the .env file in the root directory of the project and set the following values:
```bash
DB_USER=your_db_user
DB_HOST=your_db_host
DB_NAME=your_db_name
DB_PASS=your_db_password
DB_PORT=5432

JWT_ACCESS_SECRET=your_jwt_access_secret
JWT_REFRESH_SECRET=your_jwt_refresh_secret
JWT_ACCESS_EXPIRES=15m
JWT_REFRESH_EXPIRES=99y
```

### 4. Run the application
Locate the folder in CMD panel then run:
```bash
node rest_server.js
```


## License
This project is licensed under the MIT License - see the LICENSE file for details.
