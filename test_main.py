import pytest
import http.client
import os
import json
from main import DATABASE_PATH, initialize_database
from threading import Thread
from http.server import HTTPServer
from main import MyServer

SERVER_ADDRESS = ("localhost", 8080)

@pytest.fixture(scope="session")
def start_server():
    server = HTTPServer(SERVER_ADDRESS, MyServer)
    thread = Thread(target=server.serve_forever)
    thread.start()
    yield
    server.shutdown()
    thread.join()

@pytest.fixture(autouse=True)
def init_db():
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
    initialize_database()
    yield
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)

def test_post_auth(start_server):
    conn = http.client.HTTPConnection(*SERVER_ADDRESS)
    conn.request("POST", "/auth")
    response = conn.getresponse()
    assert response.status == 200
    jwt_token = response.read().decode()
    assert jwt_token  # Validate that a JWT token was returned
    conn.close()

def test_get_jwks(start_server):
    conn = http.client.HTTPConnection(*SERVER_ADDRESS)
    conn.request("GET", "/.well-known/jwks.json")
    response = conn.getresponse()
    assert response.status == 200
    jwks = json.loads(response.read().decode())
    assert "keys" in jwks
    assert jwks["keys"]  # Validate that keys are returned
    conn.close()

def test_post_auth_expired(start_server):
    conn = http.client.HTTPConnection(*SERVER_ADDRESS)
    conn.request("POST", "/auth?expired=true")
    response = conn.getresponse()
    assert response.status == 200
    jwt_token = response.read().decode()
    assert jwt_token  # Validate that a JWT token was returned
    conn.close()

def test_invalid_path(start_server):
    conn = http.client.HTTPConnection(*SERVER_ADDRESS)
    conn.request("GET", "/invalid_path")
    response = conn.getresponse()
    assert response.status == 405
    conn.close()
