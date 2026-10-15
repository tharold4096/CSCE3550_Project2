import base64
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import db

#Method to calculate how many bytes are needed to represent a number
def calc_bytes(v):
    if v == 0:
        return 1
    return (v.bit_length() + 7) // 8 #Formula for converting to bits, then dividing by 8 to bytes (rounding up)


#Converts the integer to a base64 string
def int_to_str(v):
    length = calc_bytes(v)
    b = v.to_bytes(length, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8") #encodes b, after stripping =, then decodes it to a string

@dataclass
class Key:
    kid: str
    private_key: rsa.RSAPrivateKey
    expiry: datetime


def serialize_key(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_key(pem: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def row_to_key(row) -> Key:
    kid, pem, exp = row
    return Key(str(kid), deserialize_key(pem), datetime.fromtimestamp(exp, timezone.utc))


def create_key(exp: int, path=db.DB_FILE) -> int:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return db.insert_key(serialize_key(private_key), exp, path)


def ensure_keys(path=db.DB_FILE):
    db.init_db(path)
    now = int(time.time())
    if not db.get_valid_keys(now, path):
        create_key(now + 3600, path)
    if db.get_expired_key(now, path) is None:
        create_key(now - 3600, path)


def get_unexpired(path=db.DB_FILE) -> list:
    return [row_to_key(row) for row in db.get_valid_keys(int(time.time()), path)]


def to_jwk(key: Key) -> dict:
    public_key = key.private_key.public_key()
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": key.kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_str(numbers.n),
        "e": int_to_str(numbers.e)
    }


def jwks_wrapper(path=db.DB_FILE) -> dict:
    return {"keys": [to_jwk(key) for key in get_unexpired(path)]}


def signing_selector(expired=False, path=db.DB_FILE):
    now = int(time.time())
    if expired:
        row = db.get_expired_key(now, path)
    else:
        rows = db.get_valid_keys(now, path)
        row = rows[0] if rows else None
    return row_to_key(row) if row else None
