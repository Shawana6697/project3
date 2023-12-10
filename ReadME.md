# README

## CSCE 3500.001
## Flask Authentication and Encryption Application

This application is a Flask-based web service that performs authentication and encryption using RSA and AES algorithms. It includes functions for key generation, encryption, decryption, serialization, and database operations. The application also implements rate limiting and logging of authentication attempts.

### Author
Shawana Tahseen

### Date
10th Dec 2023


## Features

- RSA and AES encryption
- Key generation
- Encryption and decryption
- Serialization
- Database operations
- Rate limiting
- Logging of authentication attempts

## Endpoints

- `/auth`: Authenticates the user and generates a JWT token.
- `/register`: Registers a new user.
- `/.well-known/jwks.json`: Returns a JSON response containing a list of valid keys in JWKS format.

## Setup

1. Clone the repository.
2. Install the required packages using pip:
    ```
    pip install flask flask_limiter cryptography argon2 jwt
    ```
3. Run the application:
    ```
    python main.py
    ```

The application will start running at `localhost:8080`.

## Note

This application uses an SQLite database named `totally_not_my_privateKeys.db` to store keys, user details, and authentication logs. The database is created and initialized when the application starts. Make sure all the required packages are installed correctly.