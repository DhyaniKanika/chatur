
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import os

# Load RSA keys from files
def load_keys_from_files():
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key


# Encrypt a message using an RSA public key
def encrypt_message_rsa(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt a message using an RSA private key
def decrypt_message_rsa(encrypted_message, private_key):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# Generate DH key pair
def generate_dh_keys():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize a public key to send it over the network
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Load public key from serialized PEM format
def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

# Perform the DH key exchange and derive a shared key
def derive_shared_secret(private_key, public_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    public_keys = sorted([public_key, peer_public_key], key=lambda x: x)
    concatenated_public_keys = public_keys[0] + public_keys[1]
    salt = hashlib.sha256(concatenated_public_keys).digest()
    # Derive a key from the shared secret
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

# Encrypt message using AES-GCM (symmetric key)
def encrypt_message_symmetric(key, plaintext, associated_data=None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext  # Return nonce with the ciphertext for decryption

# Decrypt message using AES-GCM (symmetric key)
def decrypt_message_symmetric(key, ciphertext, associated_data=None):
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    actual_ciphertext = ciphertext[12:]
    return aesgcm.decrypt(nonce, actual_ciphertext, associated_data)

# Sign a message using private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify a signature using public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False
