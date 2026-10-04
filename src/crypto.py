from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
import hmac as std_hmac

# A curve G y^2 = x^3 + ax + b
CURVE = ec.SECP256R1()


# Salt for HMAC(salt, IKM)
def generate_salt():
    return os.urandom(32)


# Generate private key (a)
def generate_private_key():
    private_key = ec.generate_private_key(CURVE)

    return private_key


# Generate Public key (aG)
def generate_public_key(private_key):
    my_public_key = private_key.public_key()

    return my_public_key


# Get Shared Secret Key (abG) in bytes
def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(
        ec.ECDH(), peer_public_key
    )  # shared_secret is in bytes

    return shared_secret


def derive_session_key(salt, shared_secret, info):

    # HKDF Extraction phase for uniform interface
    # Get PRK(Pseudo Random Key) = HMAC(Salt, IMK)
    prk = HKDF.extract(algorithm=hashes.SHA256(), salt=salt, key_material=shared_secret)

    # HKDF-Expansion Phase
    # Get Session key from prk, info, OKM = T(1)T(2).... where T(i) =  HMAC(PRK, T(i-1)||info|| i)
    hdkf_expand = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info)

    okm = hdkf_expand.derive(prk)  # okm : Output Keying Material

    return okm


# Function to Compute the HMAC of transcript to send to other side for HANDSHAKE Confirmation
# Returns HMAC(MAC_KEY, transcript)
def compute_hmac(MAC_KEY, transcript):
    h = hmac.HMAC(MAC_KEY, hashes.SHA256())
    h.update(transcript)
    mac_bytes = h.finalize()

    return mac_bytes


# Compare HMAC keys
def compare_hmac(received_hmac, expected_hmac):
    return std_hmac.compare_digest(received_hmac, expected_hmac)


# Convert ECDh Object to Binary(Serialize)
def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


# Convert Binary(Serialize) to ECDh Object
def deserialize_key(data):
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)
