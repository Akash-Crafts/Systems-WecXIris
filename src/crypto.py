from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# A curve G y^2 = x^3 + ax + b
CURVE = ec.SECP256R1()


# Generate private key (a)
def generate_private_key():
    private_key = ec.generate_private_key(CURVE)

    return private_key


# Generate Public key (aG)
def generate_public_key(private_key):
    my_public_key = private_key.public_key()

    return my_public_key


# Get Secret Shared Key (abG)
def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    return shared_secret


# Convert ECDh Object to Binary(Serialize)
def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


# Convert Binary(Serialize) to ECDh Object
def deserialize_key(data):
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)
