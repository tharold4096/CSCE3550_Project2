import json
import os
import time
import jwt
import pytest
import db
import keys
import threading
import urllib.request
import urllib.error
from http.server import HTTPServer
import project1

def test_encoder_known_value():
    assert keys.int_to_str(65537) == "AQAB"


@pytest.fixture(scope="module")
def key_dir(tmp_path_factory):
    old = os.getcwd()
    os.chdir(tmp_path_factory.mktemp("keys"))
    keys.ensure_keys()
    yield
    os.chdir(old)

def test_jwk_omits_private_material(key_dir):
    jwk = keys.to_jwk(keys.get_unexpired()[0])
    for field in ("d", "p", "q", "dp", "dq", "qi"):
        assert field not in jwk

@pytest.fixture(scope="module")
def server(key_dir):
    httpd = HTTPServer(("localhost", 0), project1.JWKSHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield port
    httpd.shutdown()

def test_jwks_endpoint_returns_valid_key(server):
    url = f"http://localhost:{server}/.well-known/jwks.json"
    with urllib.request.urlopen(url) as resp:
        assert resp.status == 200
        data = json.loads(resp.read())
    assert len(data["keys"]) == 1

def test_auth_returns_signed_jwt(server):
    url = f"http://localhost:{server}/auth"
    req = urllib.request.Request(url, method="POST", data=b"")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read())
        token = data["token"]
        assert token.count(".") == 2  # JWT has three parts separated by dots

def test_auth_expired_key(server):
    url = f"http://localhost:{server}/auth?expired=true"
    req = urllib.request.Request(url, method="POST", data=b"")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read())
        token = data["token"]
        assert token.count(".") == 2  # JWT has three parts separated by dots

def test_wrong_method_returns_405(server):
    url = f"http://localhost:{server}/auth"
    req = urllib.request.Request(url, method="GET")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req)
    assert excinfo.value.code == 405

def test_unknown_path_returns_404(server):
    url = f"http://localhost:{server}/unknown"
    req = urllib.request.Request(url, method="POST", data=b"")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req)
    assert excinfo.value.code == 404

def test_get_on_auth_returns_405(server):
    url = f"http://localhost:{server}/auth"
    req = urllib.request.Request(url, method="GET")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req)
    assert excinfo.value.code == 405

def test_put_on_auth_returns_405(server):
    url = f"http://localhost:{server}/auth"
    req = urllib.request.Request(url, method="PUT", data=b"")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req)
    assert excinfo.value.code == 405

def test_post_on_jwks_returns_405(server):
    url = f"http://localhost:{server}/.well-known/jwks.json"
    req = urllib.request.Request(url, method="POST", data=b"")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req)
    assert excinfo.value.code == 405
def test_int_to_str_zero_case():
    assert keys.int_to_str(0) == "AA"


def test_serialize_round_trip():
    k = keys.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = keys.serialize_key(k)
    assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    assert keys.deserialize_key(pem).private_numbers() == k.private_numbers()

def test_ensure_keys_does_not_duplicate(tmp_path):
    path = str(tmp_path / "test.db")
    keys.ensure_keys(path)
    keys.ensure_keys(path)
    assert len(keys.get_unexpired(path)) == 1
    assert keys.signing_selector(expired=True, path=path) is not None

def test_ensure_keys_replaces_expired_valid_key(tmp_path):
    path = str(tmp_path / "test.db")
    db.init_db(path)
    keys.create_key(int(time.time()) - 60, path)
    keys.ensure_keys(path)
    assert len(keys.get_unexpired(path)) == 1

def test_signing_selector_empty_db(tmp_path):
    path = str(tmp_path / "test.db")
    db.init_db(path)
    assert keys.signing_selector(expired=False, path=path) is None
    assert keys.signing_selector(expired=True, path=path) is None

def test_kid_in_jwt_matches_jwks(server):
    req = urllib.request.Request(f"http://localhost:{server}/auth", method="POST", data=b"")
    with urllib.request.urlopen(req) as resp:
        token = json.loads(resp.read())["token"]
    with urllib.request.urlopen(f"http://localhost:{server}/.well-known/jwks.json") as resp:
        published = [k["kid"] for k in json.loads(resp.read())["keys"]]
    assert jwt.get_unverified_header(token)["kid"] in published

