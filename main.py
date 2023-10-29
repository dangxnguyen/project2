from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080

# Path to the database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'totally_not_my_privateKeys.db')

def int_to_base64(value):
    # Convert an integer to a Base64URL-encoded string
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def initialize_database():
    # Initialize SQLite database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')

    # Check if keys already exist
    cursor.execute('SELECT COUNT(*) FROM keys')
    if cursor.fetchone()[0] == 0:
        # Generate and save private keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        expired_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Save private keys to the database
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, 0))  # 0 for not expired
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (expired_pem, 1))  # 1 for expired
        conn.commit()
    conn.close()

# This class defines the HTTP server that will be used for testing
class MyServer(BaseHTTPRequestHandler):
    # Post request handler
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        # Check if the path is auth
        if parsed_path.path == "/auth":
            headers = {}

            # Check if expired query parameter is present
            if 'expired' in params:
                exp_value = 1
            else:
                exp_value = 0

            # Retrieve the private key from the database
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT key, kid FROM keys WHERE exp = ?', (exp_value,))
            row = cursor.fetchone()
            if row:
                key_pem, kid = row
            else:
                self.send_response(500)
                self.end_headers()
                return
            conn.close()

            # Set the kid header
            headers["kid"] = f"key{kid}"

            # Deserialize the key
            private_key = load_pem_private_key(key_pem, password=None)

            # Generate a JWT token
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    # Get request handler
    def do_GET(self):
        # Check if the path is jwks.json
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            # Retrieve valid private keys from the database
            conn = sqlite3.connect('totally_not_my_privateKeys.db')
            cursor = conn.cursor()
            cursor.execute('SELECT key, kid FROM keys WHERE exp = ?', (0,))
            valid_keys = cursor.fetchall()
            conn.close()
            
            # Generate the jwks.json response
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": f"key{kid}",
                        "n": int_to_base64(load_pem_private_key(key_pem, password=None).public_key().public_numbers().n),
                        "e": int_to_base64(load_pem_private_key(key_pem, password=None).public_key().public_numbers().e),
                    } for key_pem, kid in valid_keys
                ]
            }
            
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

# Run the server
if __name__ == "__main__":
    initialize_database()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
