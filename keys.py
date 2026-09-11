import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import rsa

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
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expiry

    
def generate_key(expiry):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = str(uuid4())
    return Key(kid, private_key, expiry)

_keys = [
     generate_key(datetime.now(timezone.utc) + timedelta(hours=1)),
     generate_key(datetime.now(timezone.utc) - timedelta(hours=1))
]

    
def get_unexpired():               
    return [key for key in _keys if not key.is_expired()]
#def get_key(kid):
#    for key in _keys:
#        if key.kid == kid:
#            return key
#    return None

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
def jwks_wrapper() -> dict:
    return {"keys": [to_jwk(key) for key in get_unexpired()]}

def signing_selector(expired=False):
    for key in _keys:
        if expired and key.is_expired():
            return key
        elif not expired and not key.is_expired():
            return key

    return None



#if __name__ == "__main__":
    #number = input("Enter a number to convert to base64: ")
    #print(f"Base64 representation: {int_to_str(int(number))}")
 #   assert int_to_str(65537) == "AQAB"
  #  print(len(get_unexpired()))


