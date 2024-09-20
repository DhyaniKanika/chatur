from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidTag

import traceback
import os
import base64

# Load RSA keys from file
def load_private_key_from_file(password: bytes):
    try:
        with open('keystore/client.key', 'rb') as f:
            private_key_data = f.read()
        private_key = load_pem_private_key(
            private_key_data,
            password=password,
        )
        print(f"Successfully loaded private key.")
        return private_key
    except Exception as e:
        print(f"Error loading private key: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None

# Encrypt a message using an RSA public key
def encrypt_message_rsa(message, public_key):
    try:
        loaded_public_key = load_public_key(public_key)
        encrypted_message = loaded_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encoded_message = base64.b64encode(encrypted_message)
        return encoded_message
    except Exception as e:
        print(f"RSA Encryption error: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None

# Decrypt a message using an RSA private key
def decrypt_message_rsa(encrypted_message, private_key):
    try:
        decoded_message = base64.b64decode(encrypted_message)
        decrypted_message = private_key.decrypt(
            decoded_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message
    except ValueError as e:
        print(f"RSA Decryption error (ValueError): {e}")
    except Exception as e:
        print(f"RSA Decryption error: {type(e).__name__}: {e}")
        traceback.print_exc()
    return None

# Serialize a public key to send it over the network
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Load public key from serialized PEM format
def load_public_key(pem_data):
    try:
        if isinstance(pem_data, str):
            pem_data = pem_data.encode()
        public_key = serialization.load_pem_public_key(pem_data)
        return public_key
    except Exception as e:
        print(f"Error loading public key: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None


# Encrypt message using AES-GCM (symmetric key)
def encrypt_message_symmetric(key, plaintext, associated_data = None):
    message = base64.b64encode(plaintext.encode())
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, associated_data)
    encoded_message = base64.urlsafe_b64encode(nonce + ciphertext).decode()
    return encoded_message


# Decrypt message using AES-GCM (symmetric key)
def decrypt_message_symmetric(key, encrypted_message, associated_data = None):
    aesgcm = AESGCM(key)
    try:
        decoded_message = base64.urlsafe_b64decode(encrypted_message)
        nonce = decoded_message[:12]
        ciphertext = decoded_message[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode()
    except InvalidTag:
        print("Error: Message authentication failed. The message may have been tampered with.")
    except ValueError as e:
        print(f"ValueError in decryption: {e}")
    except Exception as e:
        print(f"Unexpected error in decryption: {type(e).__name__}: {e}")
    return None

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
