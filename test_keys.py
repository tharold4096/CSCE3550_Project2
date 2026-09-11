import json
import pytest
import keys


def test_encoder_known_value():
    assert keys.int_to_str(65537) == "AQAB"


def test_jwk_omits_private_material():
    jwk = keys.to_jwk(keys._keys[0])
    for field in ("d", "p", "q", "dp", "dq", "qi"):
        assert field not in jwk