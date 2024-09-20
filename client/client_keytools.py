from cryptography.hazmat.primitives.asymmetric import padding  # Import RSA encryption primitives
from cryptography.hazmat.primitives import serialization, hashes  # Import serialization and hash utilities
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM for symmetric encryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key  # Load private keys
from cryptography.exceptions import InvalidTag  # Exception for invalid message tags in encryption
import traceback  # For handling exceptions with tracebacks
import os  # OS module for random number generation
import base64  # Base64 encoding for converting binary data to text

# Function to load RSA private key from a file, decrypt it using a password
def load_private_key_from_file(password: bytes):
    """
    Loads a private RSA key from a file, decrypting it with a provided password.

    Args:
        password (bytes): Password to decrypt the private key.

    Returns:
        private_key: The loaded private RSA key object.
    """
    try:
        # Open the file containing the private key
        with open('keystore/client.key', 'rb') as f:
            private_key_data = f.read()
        
        # Load the private key using the password for decryption
        private_key = load_pem_private_key(
            private_key_data,
            password=password,
        )
        print(f"Successfully loaded private key.")
        return private_key
    except Exception as e:
        print(f"Error loading private key: {type(e).__name__}: {e}")
        traceback.print_exc()  # Print the traceback for debugging
        return None

# Function to encrypt a message using RSA and a public key
def encrypt_message_rsa(message, public_key):
    """
    Encrypts a message using RSA and the recipient's public key.

    Args:
        message (bytes): The message to be encrypted.
        public_key (bytes/str): The recipient's public key in PEM format.

    Returns:
        str: The base64-encoded encrypted message.
    """
    try:
        # Load the recipient's public key
        loaded_public_key = load_public_key(public_key)
        
        # Encrypt the message using RSA OAEP padding and SHA-256 hash
        encrypted_message = loaded_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
                algorithm=hashes.SHA256(),  # Hash function
                label=None  # No additional label
            )
        )
        # Base64 encode the encrypted message for easy transport
        encoded_message = base64.b64encode(encrypted_message)
        return encoded_message
    except Exception as e:
        print(f"RSA Encryption error: {type(e).__name__}: {e}")
        traceback.print_exc()  # Print the traceback for debugging
        return None

# Function to decrypt an RSA-encrypted message using a private key
def decrypt_message_rsa(encrypted_message, private_key):
    """
    Decrypts an RSA-encrypted message using the recipient's private key.

    Args:
        encrypted_message (str): The base64-encoded encrypted message.
        private_key: The recipient's private RSA key.

    Returns:
        bytes: The decrypted message in bytes.
    """
    try:
        # Decode the base64-encoded message
        decoded_message = base64.b64decode(encrypted_message)
        
        # Decrypt the message using the RSA private key
        decrypted_message = private_key.decrypt(
            decoded_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
                algorithm=hashes.SHA256(),  # Hash function
                label=None  # No additional label
            )
        )
        return decrypted_message
    except ValueError as e:
        print(f"RSA Decryption error (ValueError): {e}")
    except Exception as e:
        print(f"RSA Decryption error: {type(e).__name__}: {e}")
        traceback.print_exc()  # Print the traceback for debugging
    return None

# Function to serialize (convert) a public key to PEM format
def serialize_public_key(public_key):
    """
    Serializes a public RSA key into PEM format.

    Args:
        public_key: The public RSA key object.

    Returns:
        bytes: The serialized public key in PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # Encode using PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # SubjectPublicKeyInfo format for public keys
    )

# Function to load a public RSA key from PEM format
def load_public_key(pem_data):
    """
    Loads a public RSA key from PEM-encoded data.

    Args:
        pem_data (str/bytes): The PEM-encoded public key.

    Returns:
        public_key: The public RSA key object.
    """
    try:
        # If the input is a string, encode it to bytes
        if isinstance(pem_data, str):
            pem_data = pem_data.encode()
        
        # Load the public key from PEM data
        public_key = serialization.load_pem_public_key(pem_data)
        return public_key
    except Exception as e:
        print(f"Error loading public key: {type(e).__name__}: {e}")
        traceback.print_exc()  # Print the traceback for debugging
        return None

# Function to encrypt a message using AES-GCM (symmetric encryption)
def encrypt_message_symmetric(key, plaintext, associated_data=None):
    """
    Encrypts a message using AES-GCM symmetric encryption.

    Args:
        key (bytes): The symmetric key for AES-GCM encryption.
        plaintext (str): The message to be encrypted.
        associated_data (bytes): Optional associated data for authentication.

    Returns:
        str: The base64-encoded encrypted message.
    """
    # Convert plaintext to base64-encoded format for encryption
    message = base64.b64encode(plaintext.encode())
    
    # Initialize AES-GCM with the provided symmetric key
    aesgcm = AESGCM(key)
    
    # Generate a random nonce (12 bytes) for AES-GCM
    nonce = os.urandom(12)
    
    # Encrypt the message using AES-GCM, with optional associated data
    ciphertext = aesgcm.encrypt(nonce, message, associated_data)
    
    # Combine the nonce and ciphertext and return them as a base64-encoded string
    encoded_message = base64.urlsafe_b64encode(nonce + ciphertext).decode()
    return encoded_message

# Function to decrypt a message using AES-GCM (symmetric encryption)
def decrypt_message_symmetric(key, encrypted_message, associated_data=None):
    """
    Decrypts an AES-GCM encrypted message.

    Args:
        key (bytes): The symmetric key used for encryption.
        encrypted_message (str): The base64-encoded encrypted message.
        associated_data (bytes): Optional associated data for authentication.

    Returns:
        str: The decrypted message in plaintext.
    """
    # Initialize AES-GCM with the provided symmetric key
    aesgcm = AESGCM(key)
    
    try:
        # Decode the base64-encoded message to retrieve the nonce and ciphertext
        decoded_message = base64.urlsafe_b64decode(encrypted_message)
        
        # Extract the nonce (first 12 bytes) from the decoded message
        nonce = decoded_message[:12]
        
        # Extract the ciphertext from the remaining part of the decoded message
        ciphertext = decoded_message[12:]
        
        # Decrypt the ciphertext using AES-GCM
        encoded_plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        
        # Decode the base64-encoded plaintext and return it as a string
        decoded_plaintext = base64.urlsafe_b64decode(encoded_plaintext)
        return decoded_plaintext.decode()
    
    # Handle decryption failures due to invalid tags (message integrity/authentication errors)
    except InvalidTag:
        print("Error: Message authentication failed. The message may have been tampered with.")
    except ValueError as e:
        print(f"ValueError in decryption: {e}")
    except Exception as e:
        print(f"Unexpected error in decryption: {type(e).__name__}: {e}")
    return None

# # Function to sign a message using a private RSA key (commented out)
# def sign_message(private_key, message):
#     signature = private_key.sign(
#         message.encode(),
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function
#             salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length
#         ),
#         hashes.SHA256()  # Hashing algorithm
#     )
#     return signature

# # Function to verify a signature using a public RSA key (commented out)
# def verify_signature(public_key, message, signature):
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
