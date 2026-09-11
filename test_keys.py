import json
import pytest
import keys
import threading
import urllib.request
import urllib.error
from http.server import HTTPServer
import project1

def test_encoder_known_value():
    assert keys.int_to_str(65537) == "AQAB"


def test_jwk_omits_private_material():
    jwk = keys.to_jwk(keys._keys[0])
    for field in ("d", "p", "q", "dp", "dq", "qi"):
        assert field not in jwk

@pytest.fixture(scope="module")
def server():
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

