from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import traceback
import os
import base64

# Load RSA keys from files
def load_private_key_from_file(password: bytes):
    # Load and decrypt the private key
    with open('keystore/client.key', 'rb') as f:
        private_key = load_pem_private_key(
            f.read(),
            password=password,
        )
    return private_key



# Encrypt a message using an RSA public key
def encrypt_message_rsa(message, public_key):
    try:
        print(f"Message: {message}")
        print(f"public_key: {public_key}")
        loaded_public_key = load_public_key(public_key)
        encrypted = loaded_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encoded = base64.b64encode(encrypted)
        print(f"RSA Encryption - Original message length: {len(message)}")
        print(f"RSA Encryption - Encrypted message length: {len(encrypted)}")
        print(f"RSA Encryption - Base64 encoded message length: {len(encoded)}")
        return encoded
    except Exception as e:
        print(f"RSA Encryption error: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None
# def encrypt_message_rsa(message, public_key):
#     return public_key.encrypt(
#         message,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )

# Decrypt a message using an RSA private key
def decrypt_message_rsa(encrypted_message, private_key):
    try:
        decoded = base64.b64decode(encrypted_message)
        print(f"RSA Decryption - Received message length: {len(encrypted_message)}")
        print(f"RSA Decryption - Decoded message length: {len(decoded)}")
        print(f"RSA Decryption - Private key size: {private_key.key_size}")
        decrypted = private_key.decrypt(
            decoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"RSA Decryption - Decrypted message length: {len(decrypted)}")
        return decrypted
    except ValueError as e:
        print(f"RSA Decryption error (ValueError): {e}")
    except Exception as e:
        print(f"RSA Decryption error: {type(e).__name__}: {e}")
    return None
# def decrypt_message_rsa(encrypted_message, private_key):
#     return private_key.decrypt(
#         encrypted_message,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )#.decode()

# # Generate DH key pair
# def generate_dh_keys():
#     parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
#     private_key = parameters.generate_private_key()
#     public_key = private_key.public_key()
#     return private_key, public_key

# Serialize a public key to send it over the network
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Load public key from serialized PEM format
def load_public_key(pem_data):
    if isinstance(pem_data, str) and pem_data.startswith('PUBLIC_KEY:'):
        pem_data = pem_data.split(':', 1)[1].encode()
    elif isinstance(pem_data, str):
        pem_data = pem_data.encode()
    return serialization.load_pem_public_key(pem_data, backend=default_backend())
# def load_public_key(pem_data):
#     return serialization.load_pem_public_key(pem_data, backend=default_backend())

# # Perform the DH key exchange and derive a shared key
# def derive_shared_secret(private_key, public_key, peer_public_key):
#     shared_secret = private_key.exchange(peer_public_key)
#     public_keys = sorted([public_key, peer_public_key], key=lambda x: x)
#     concatenated_public_keys = public_keys[0] + public_keys[1]
#     salt = hashlib.sha256(concatenated_public_keys).digest()
#     # Derive a key from the shared secret
#     return HKDF(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         info=b'handshake data',
#         backend=default_backend()
#     ).derive(shared_secret)

# Encrypt message using AES-GCM (symmetric key)
def encrypt_message_symmetric(key, plaintext, associated_data):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
    encoded_message = base64.urlsafe_b64encode(nonce + ciphertext).decode()
    return encoded_message
# def encrypt_message_symmetric(key, plaintext, associated_data):
#     aesgcm = AESGCM(key)
#     nonce = os.urandom(12)
#     message = base64.b64encode(plaintext.encode())
#     ciphertext = aesgcm.encrypt(nonce, message, associated_data)
#     return nonce + ciphertext  # Return nonce with the ciphertext for decryption

# Decrypt message using AES-GCM (symmetric key)
def decrypt_message_symmetric(key, encrypted_message, associated_data):
    aesgcm = AESGCM(key)
    try:
        print(f"Attempting to decode: {encrypted_message}")
        decoded_message = base64.urlsafe_b64decode(encrypted_message)
        print(f"Decoded message length: {len(decoded_message)}")
        nonce = decoded_message[:12]
        ciphertext = decoded_message[12:]
        print(f"Nonce length: {len(nonce)}, Ciphertext length: {len(ciphertext)}")
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode()
    except InvalidTag:
        print("Error: Message authentication failed. The message may have been tampered with.")
    except ValueError as e:
        print(f"ValueError in decryption: {e}")
    except Exception as e:
        print(f"Unexpected error in decryption: {type(e).__name__}: {e}")
    return None
# def decrypt_message_symmetric(key, ciphertext, associated_data):
#     aesgcm = AESGCM(key)
#     nonce = ciphertext[:12]
#     actual_ciphertext = ciphertext[12:]
#     message = base64.b64decode(actual_ciphertext)
#     return aesgcm.decrypt(nonce, message, associated_data).decode()

# # Sign a message using private key
# def sign_message(private_key, message):
#     signature = private_key.sign(
#         message.encode(),
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),
#             salt_length=padding.PSS.MAX_LENGTH
#         ),
#         hashes.SHA256()
#     )
#     return signature

# # Verify a signature using public key
# def verify_signature(public_key, message, signature):
#     try:
#         public_key.verify(
#             signature,
#             message.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         return True
#     except Exception as e:
#         return False
