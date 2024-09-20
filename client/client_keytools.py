"""
Client Key Tools Module for Secure Chat Application

This module provides essential cryptographic functions for the client-side of a secure chat application.
It includes functions for RSA key management, RSA encryption/decryption, AES-GCM symmetric encryption/decryption,
and utilities for key serialization and loading.

Key features:
1. RSA private key loading and management
2. RSA encryption and decryption
3. AES-GCM symmetric encryption and decryption
4. Public key serialization and loading
5. Error handling and logging for cryptographic operations

Dependencies:
- cryptography: For various cryptographic primitives and operations
- traceback: For detailed error reporting
- os: For secure random number generation
- base64: For encoding and decoding binary data to text

Note: This module requires proper key management and secure storage of sensitive information.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidTag
import traceback
import os
import base64

def load_private_key_from_file(password: bytes):
    """
    Loads a private RSA key from a file, decrypting it with a provided password.

    Args:
        password (bytes): Password to decrypt the private key.

    Returns:
        private_key: The loaded private RSA key object, or None if loading fails.

    Raises:
        Various exceptions related to file I/O and key decryption, which are caught and logged.
    """
    try:
        # Open the file containing the private key in binary read mode
        with open('keystore/client.key', 'rb') as f:
            # Read the entire content of the file
            private_key_data = f.read()
        
        # Load and decrypt the private key using the provided password
        private_key = load_pem_private_key(
            private_key_data,  # The encrypted key data
            password=password,  # The password to decrypt the key
        )
        # Log successful key loading
        print("Successfully loaded private key.")
        # Return the loaded private key object
        return private_key
    except Exception as e:
        # Log any errors that occur during key loading
        print(f"Error loading private key: {type(e).__name__}: {e}")
        # Print the full traceback for debugging purposes
        traceback.print_exc()
        # Return None to indicate failure
        return None

def encrypt_message_rsa(message, public_key):
    """
    Encrypts a message using RSA and the recipient's public key.

    Args:
        message (bytes): The message to be encrypted.
        public_key (bytes/str): The recipient's public key in PEM format.

    Returns:
        str: The base64-encoded encrypted message, or None if encryption fails.

    Raises:
        Various exceptions related to key loading and encryption, which are caught and logged.
    """
    try:
        # Load the recipient's public key
        loaded_public_key = load_public_key(public_key)
        
        # Encrypt the message using RSA OAEP padding and SHA-256 hash
        encrypted_message = loaded_public_key.encrypt(
            message,  # The message to encrypt
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
                algorithm=hashes.SHA256(),  # Hash function for OAEP
                label=None  # No additional label used
            )
        )
        # Base64 encode the encrypted message for easy transport
        encoded_message = base64.b64encode(encrypted_message)
        # Return the base64 encoded encrypted message
        return encoded_message
    except Exception as e:
        # Log any errors that occur during encryption
        print(f"RSA Encryption error: {type(e).__name__}: {e}")
        # Print the full traceback for debugging purposes
        traceback.print_exc()
        # Return None to indicate failure
        return None

def decrypt_message_rsa(encrypted_message, private_key):
    """
    Decrypts an RSA-encrypted message using the recipient's private key.

    Args:
        encrypted_message (str): The base64-encoded encrypted message.
        private_key: The recipient's private RSA key object.

    Returns:
        bytes: The decrypted message in bytes, or None if decryption fails.

    Raises:
        ValueError: If decryption fails due to invalid padding.
        Other exceptions related to decryption, which are caught and logged.
    """
    try:
        # Decode the base64-encoded encrypted message
        decoded_message = base64.b64decode(encrypted_message)
        
        # Decrypt the message using the RSA private key
        decrypted_message = private_key.decrypt(
            decoded_message,  # The encrypted message to decrypt
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
                algorithm=hashes.SHA256(),  # Hash function for OAEP
                label=None  # No additional label used
            )
        )
        # Return the decrypted message
        return decrypted_message
    except ValueError as e:
        # Log specific ValueError exceptions (often due to padding issues)
        print(f"RSA Decryption error (ValueError): {e}")
    except Exception as e:
        # Log any other exceptions that occur during decryption
        print(f"RSA Decryption error: {type(e).__name__}: {e}")
        # Print the full traceback for debugging purposes
        traceback.print_exc()
    # Return None if decryption fails
    return None

def serialize_public_key(public_key):
    """
    Serializes a public RSA key into PEM format.

    Args:
        public_key: The public RSA key object.

    Returns:
        bytes: The serialized public key in PEM format.
    """
    # Serialize the public key to PEM format
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # Use PEM encoding
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Use SubjectPublicKeyInfo format for public keys
    )

def load_public_key(pem_data):
    """
    Loads a public RSA key from PEM-encoded data.

    Args:
        pem_data (str/bytes): The PEM-encoded public key.

    Returns:
        public_key: The public RSA key object, or None if loading fails.

    Raises:
        Various exceptions related to key loading, which are caught and logged.
    """
    try:
        # If the input is a string, encode it to bytes
        if isinstance(pem_data, str):
            pem_data = pem_data.encode()
        
        # Load the public key from PEM data
        public_key = serialization.load_pem_public_key(pem_data)
        # Return the loaded public key object
        return public_key
    except Exception as e:
        # Log any errors that occur during public key loading
        print(f"Error loading public key: {type(e).__name__}: {e}")
        # Print the full traceback for debugging purposes
        traceback.print_exc()
        # Return None to indicate failure
        return None

def encrypt_message_symmetric(key, plaintext, associated_data=None):
    """
    Encrypts a message using AES-GCM symmetric encryption.

    Args:
        key (bytes): The symmetric key for AES-GCM encryption.
        plaintext (str): The message to be encrypted.
        associated_data (bytes, optional): Additional data to authenticate.

    Returns:
        str: The base64-encoded encrypted message (nonce + ciphertext).
    """
    # Convert plaintext to bytes and then to base64-encoded format
    message = base64.b64encode(plaintext.encode())
    
    # Initialize AES-GCM with the provided symmetric key
    aesgcm = AESGCM(key)
    
    # Generate a random 12-byte (96-bit) nonce
    nonce = os.urandom(12)
    
    # Encrypt the message using AES-GCM, with optional associated data
    ciphertext = aesgcm.encrypt(nonce, message, associated_data)
    
    # Combine the nonce and ciphertext, encode in base64, and return as a string
    encoded_message = base64.urlsafe_b64encode(nonce + ciphertext).decode()
    return encoded_message

def decrypt_message_symmetric(key, encrypted_message, associated_data=None):
    """
    Decrypts an AES-GCM encrypted message.

    Args:
        key (bytes): The symmetric key used for encryption.
        encrypted_message (str): The base64-encoded encrypted message.
        associated_data (bytes, optional): Additional authenticated data.

    Returns:
        str: The decrypted message in plaintext, or None if decryption fails.

    Raises:
        InvalidTag: If message authentication fails.
        ValueError: If there's an issue with message format or decoding.
        Other exceptions related to decryption, which are caught and logged.
    """
    # Initialize AES-GCM with the provided symmetric key
    aesgcm = AESGCM(key)
    
    try:
        # Decode the base64-encoded encrypted message
        decoded_message = base64.urlsafe_b64decode(encrypted_message)
        
        # Extract the nonce (first 12 bytes) from the decoded message
        nonce = decoded_message[:12]
        
        # Extract the ciphertext (remaining bytes) from the decoded message
        ciphertext = decoded_message[12:]
        
        # Decrypt the ciphertext using AES-GCM
        encoded_plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        
        # Decode the base64-encoded plaintext and return it as a string
        decoded_plaintext = base64.urlsafe_b64decode(encoded_plaintext)
        return decoded_plaintext.decode()
    
    except InvalidTag:
        # Handle authentication failure (message tampering)
        print("Error: Message authentication failed. The message may have been tampered with.")
    except ValueError as e:
        # Handle value errors (often due to incorrect base64 encoding)
        print(f"ValueError in decryption: {e}")
    except Exception as e:
        # Handle any other unexpected errors
        print(f"Unexpected error in decryption: {type(e).__name__}: {e}")
    # Return None if decryption fails for any reason
    return None

# The following functions are commented out but kept for potential future use:

# def sign_message(private_key, message):
#     """
#     Signs a message using a private RSA key.
#
#     Args:
#         private_key: The private RSA key object.
#         message (str): The message to sign.
#
#     Returns:
#         bytes: The signature.
#     """
#     signature = private_key.sign(
#         message.encode(),
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function
#             salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length
#         ),
#         hashes.SHA256()  # Hashing algorithm
#     )
#     return signature

# def verify_signature(public_key, message, signature):
#     """
#     Verifies a signature using a public RSA key.
#
#     Args:
#         public_key: The public RSA key object.
#         message (str): The original message.
#         signature (bytes): The signature to verify.
#
#     Returns:
#         bool: True if the signature is valid, False otherwise.
#     """
#     try:
#         public_key.verify(
#             signature,
#             message.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function
#                 salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length
#             ),
#             hashes.SHA256()  # Hashing algorithm
#         )
#         return True
#     except Exception as e:
#         return False