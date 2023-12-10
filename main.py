"""
This code snippet demonstrates a Flask application that performs authentication and encryption using RSA and AES algorithms.
It includes functions for key generation, encryption, decryption, serialization, and database operations.
The application also implements rate limiting and logging of authentication attempts.
Author: Shawana Tahseen
Date: 12th Dec 2023
Course: CSCE 3550.001
"""

# Import necessary modules from cryptography package for RSA and AES encryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Import argon2 for password hashing
from argon2 import PasswordHasher

# Import necessary modules for encoding, JSON handling, JWT, date and time, SQLite database, UUID, and OS operations
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
import os

# Import Flask for web application and Limiter for rate limiting
from flask import Flask, Response, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Set environment variable
os.environ["NOT_MY_KEY"] = "ylcg3o6pv84aehqj"

# Initialize Flask application and Limiter for rate limiting
app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address
)


def int_to_base64(value):
    """
    Convert an integer value to a base64 encoded string.

    Args:
        value (int): The integer value to be converted.

    Returns:
        str: The base64 encoded string.

    """
    value_hex = format(value, "x")
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
    return encoded.decode("utf-8")


def encrypt_with_aes(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts the given plaintext using AES encryption algorithm.

    Args:
        key (bytes): The encryption key.
        plaintext (bytes): The plaintext to be encrypted.

    Returns:
        bytes: The encrypted ciphertext.
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add PKCS7 padding to the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def decrypt_with_aes(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts the given ciphertext using AES algorithm.

    Args:
        key (bytes): The encryption key.
        ciphertext (bytes): The ciphertext to be decrypted.

    Returns:
        bytes: The decrypted plaintext.
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext


def serialize_key_to_pem(key):
    """
    Serialize the private key to PKCS1 PEM format.

    Args:
        key (object): The private key object.

    Returns:
        str: The serialized private key in PEM format.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def deserialize_pem_to_key(pem_bytes):
    """
    Deserialize the private key from PKCS1 PEM format.

    Args:
        pem_bytes (bytes): The PEM-encoded private key.

    Returns:
        object: The deserialized private key object.
    """
    return serialization.load_pem_private_key(pem_bytes, password=None)


def get_all_valid_private_keys_with_kid() -> list[tuple[int, RSAPrivateKey]]:
    """
    Retrieves all valid private keys from the database along with their respective kid.

    Returns:
        A list of tuples, where each tuple contains the kid (int) and the RSAPrivateKey object.
    """
    current_time = int(datetime.datetime.utcnow().timestamp())
    query = "SELECT kid, key FROM keys WHERE exp > ?"

    with sqlite3.connect("totally_not_my_privateKeys.db") as conn1:
        cursor = conn1.execute(query, (current_time,))
        key_data = cursor.fetchall()

    keys = [
        (
            data[0],
            deserialize_pem_to_key(
                decrypt_with_aes(os.environ["NOT_MY_KEY"].encode(), data[1])
            ),
        )
        for data in key_data
    ]
    return keys


def get_private_key_with_kid_from_db(expired=False):  # Get un/expired key from DB
    current_time = int(datetime.datetime.utcnow().timestamp())

    # Query to fetch based on expiration status
    if expired:
        query = "SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
    else:
        query = "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"

    with sqlite3.connect("totally_not_my_privateKeys.db") as conn2:
        cursor = conn2.execute(query, (current_time,))
        key_data = cursor.fetchone()

    # Deserialize the key and pair with its kid if found
    if key_data:
        return key_data[0], deserialize_pem_to_key(
            decrypt_with_aes(os.environ["NOT_MY_KEY"].encode(), key_data[1])
        )
    return None, None


def get_user_id_from_username(
    username,
):  # Get user_id given a username from the database
    with sqlite3.connect("totally_not_my_privateKeys.db") as connGetID:
        cursor = connGetID.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        )
        user_data = cursor.fetchone()

    if user_data:
        return user_data[0]
    return None


# Create and initialize DB
conn = sqlite3.connect("totally_not_my_privateKeys.db")  # Create DB

conn.execute(
    "CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, "
    "key BLOB NOT NULL, exp INTEGER NOT NULL)"
)  # Create keys table in DB

conn.execute(
    "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, "
    "password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
    "last_login TIMESTAMP)"
)  # Create users table in DB

conn.execute(
    "CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, "
    "request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, "
    "FOREIGN KEY(user_id) REFERENCES users(id));"
)  # Create auth_logs table in DB

conn.commit()  # Commit the above changed to the DB

# Create and serialize keys
init_unexpired_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)  # Create RSA key
init_expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
init_unexpired_key_PEM = serialize_key_to_pem(
    init_unexpired_key
)  # Serialize key to PEM format
init_expired_key_PEM = serialize_key_to_pem(init_expired_key)

now = int(datetime.datetime.utcnow().timestamp())  # Get current time
hour_from_now = now + 3600  # Get one hour from now time

# Insert the serialized and encrypted keys into the DB
encrypted_unexpired_key = encrypt_with_aes(
    os.environ["NOT_MY_KEY"].encode(), init_unexpired_key_PEM.encode("utf-8")
)
encrypted_expired_key = encrypt_with_aes(
    os.environ["NOT_MY_KEY"].encode(), init_expired_key_PEM.encode("utf-8")
)

conn.execute(
    "INSERT INTO keys (key, exp) VALUES (?, ?)",
    (encrypted_unexpired_key, hour_from_now),
)
conn.execute(
    "INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_expired_key, (now - 36000))
)
conn.commit()


@app.route("/auth", methods=["POST"])
@limiter.limit("10 per second")
def auth():
    """
    Authenticates the user and generates a JWT token.

    Returns:
        Response: The encoded JWT token as a response.
    """
    auth_data = json.loads(request.get_data().decode("utf-8"))
    # Authentication logic
    kid, key = get_private_key_with_kid_from_db(request.args.get("expired"))

    if not key:  # If no key returned/found
        return Response("Unable to fetch private key", status=500)

    headers = {"kid": str(kid)}
    token_payload = {
        "user": auth_data.get("username"),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    key_pem = serialize_key_to_pem(key)  # Serialize key
    encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)

    # Log the details into the auth_logs table
    user_id = get_user_id_from_username(auth_data.get("username"))
    request_ip = request.remote_addr  # Get the client's IP address
    request_timestamp = datetime.datetime.utcnow()

    with sqlite3.connect("totally_not_my_privateKeys.db") as connLog:
        connLog.execute(
            "INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
            (request_ip, request_timestamp, user_id),
        )
        connLog.commit()

    return Response(encoded_jwt, mimetype="application/octet-stream", status=200)


@app.route("/register", methods=["POST"])
def register():
    try:
        user_data = json.loads(request.get_data().decode("utf-8"))

        # Generate a secure password using UUIDv4
        generated_password = str(uuid.uuid4())

        # Hash the password using Argon2
        ph = PasswordHasher(
            time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16
        )
        hashed_password = ph.hash(generated_password)

        # Store the user details and hashed password in the users table
        with sqlite3.connect("totally_not_my_privateKeys.db") as connRegister:
            connRegister.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (user_data["username"], user_data["email"], hashed_password),
            )
            connRegister.commit()

        # Return the generated password to the user
        response_data = {"password": generated_password}
        return Response(
            json.dumps(response_data), mimetype="application/json", status=200
        )

    except Exception as e:
        print("Inside exception: %s" % e)
        print(e)
        return Response("Error", status=500)


@app.route("/.well-known/jwks.json")
def well_known_json():
    """
    Returns a JSON response containing a list of valid keys in JWKS format.

    Returns:
        Response: JSON response containing the list of valid keys.
    """
    valid_keys_with_kid = get_all_valid_private_keys_with_kid()
    jwks = {"keys": []}
    # Create list of keys
    for kid, key in valid_keys_with_kid:
        private_numbers = key.private_numbers()
        jwks["keys"].append(
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": str(kid),
                "n": int_to_base64(private_numbers.public_numbers.n),
                "e": int_to_base64(private_numbers.public_numbers.e),
            }
        )
    # Return list of keys
    return Response(jwks, mimetype="application/json", status=200)


if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)
