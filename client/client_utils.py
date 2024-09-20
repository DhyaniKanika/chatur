"""
Client Utilities Module for Secure Chat Application

This module provides essential utility functions for the client-side of a secure chat application.
It includes functions for SSL context creation, user authentication, message handling,
chat initiation, and cryptographic operations.

Key features:
1. SSL context creation for secure server communication
2. Password hashing for secure storage and transmission
3. User registration and login
4. Message sending and receiving
5. Chat request handling and initiation
6. Symmetric key exchange for secure messaging

Dependencies:
- hashlib: For password hashing
- ssl: For creating secure SSL contexts
- subprocess: (Imported but not used in the current implementation)
- client_keytools: For various cryptographic operations
- secrets: For generating secure random numbers
- traceback: For detailed error reporting

Note: This module requires proper configuration of SSL certificates and careful 
handling of sensitive information like passwords and encryption keys.
"""

import hashlib
import ssl
import subprocess
from client_keytools import *
import secrets
import traceback

# Path to the server's PEM certificate
SERVER_CRT_PATH = 'truststore/server.pem'

def create_ssl_context():
    """
    Create an SSL context for server authentication.

    This function sets up an SSL context that will verify the server's certificate
    against a trusted CA certificate (in this case, a self-signed certificate).

    Returns:
        ssl.SSLContext: Configured SSL context for secure communication.
    """
    # Create a default SSL context for client-side operations
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Enable hostname checking for additional security
    context.check_hostname = True
    # Require certificate verification
    context.verify_mode = ssl.CERT_REQUIRED  
    # Load the CA certificate (server's certificate in this case)
    context.load_verify_locations(SERVER_CRT_PATH)
    # Return the configured SSL context
    return context

# Commented out alternate context for testing purposes
# def create_ssl_context():
#     """
#     Create a default SSL context that trusts any server certificate.
#     
#     This context should only be used in testing environments as it disables
#     certificate verification.
#     
#     Returns:
#         ssl.SSLContext: Default SSL context with relaxed security.
#     """
#     context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
#     context.check_hostname = False  # Disable hostname checking
#     context.verify_mode = ssl.CERT_NONE  # Trust any certificate
#     return context

def hash_password(password):
    """
    Hash a password using SHA-256.

    Args:
        password (str): The password to hash.

    Returns:
        str: The SHA-256 hash of the password as a hexadecimal string.
    """
    # Encode the password to bytes, hash it using SHA-256, and return the hexadecimal representation
    return hashlib.sha256(password.encode()).hexdigest()

def read_public_key(file_path):
    """
    Read the public key from a specified file.

    Args:
        file_path (str): Path to the public key file.

    Returns:
        str: The public key as a string, stripped of extra newlines.
    """
    # Open the file in read mode
    with open(file_path, 'r') as file:
        # Read the content and strip any extra whitespace
        return file.read().strip()

def register_user(sock, username, password, public_key):
    """
    Register a new user with the server.

    Args:
        sock (socket): The socket connected to the server.
        username (str): The username for registration.
        password (str): The password for registration.
        public_key (str): The public key of the user.

    Returns:
        str: Server's response to the registration attempt.
    """
    # Construct the registration message
    message = f'REGISTER:{username}:{password}:{public_key}'
    # Send the registration message to the server
    sock.send(message.encode())
    # Receive and return the server's response
    response = sock.recv(1024).decode()
    return response

def login_user(sock, username, password):
    """
    Log in a user to the server.

    Args:
        sock (socket): The socket connected to the server.
        username (str): The username for login.
        password (str): The password for login.

    Returns:
        str: Server's response to the login attempt.
    """
    # Construct the login message
    message = f'LOGIN:{username}:{password}'
    # Send the login message to the server
    sock.sendall(message.encode())
    # Receive and return the server's response
    response = sock.recv(1024).decode()
    return response

def send_message(client_socket, message, recipient_name):
    """
    Send a message to a specified recipient.

    Args:
        client_socket (socket): The socket connected to the server.
        message (str): The message content to send.
        recipient_name (str): The name of the recipient.

    Returns:
        None
    """
    try:
        # Construct and send the message to the server
        client_socket.send(f'MESSAGE:{recipient_name}:{message}'.encode())
    except Exception as e:
        # Log any errors that occur during sending
        print(f"Error sending message to {recipient_name}: {e}")

def receive_message(client_socket, username):
    """
    Receive a message addressed to the specified user.

    Args:
        client_socket (socket): The socket connected to the server.
        username (str): The username of the recipient.

    Returns:
        str: The decoded message if received, otherwise None.
    """
    try:
        while True:
            # Receive a message from the server
            server_message = client_socket.recv(1024).decode()
            # Check if it's a message intended for this user
            if server_message.startswith('MESSAGE'):
                # Split the message into its components
                _, receiver_name, encoded_message = server_message.split(':', 2)
                # Verify the receiver is the current user
                if receiver_name.strip() == username.strip():
                    return encoded_message
            else:
                # Log unexpected message formats
                print(f"Unexpected message format: {server_message}")
                return None
    except Exception as e:
        # Log any errors that occur during receiving
        print(f"Error receiving message: {type(e).__name__}: {e}")
        return None

def listen_for_incoming_requests(client_socket, username):
    """
    Listen for incoming chat requests from the server.

    Args:
        client_socket (socket): The socket connected to the server.
        username (str): The username of the client.

    Returns:
        tuple: (sender_name, public_key_pem) if chat accepted, else None.
    """
    try:
        while True:
            # Receive a message from the server
            server_message = client_socket.recv(1024).decode()
            # Check if it's a chat request
            if server_message.startswith('CHAT_REQUEST'):
                # Extract the sender's name
                _, sender_name = server_message.split(':')
                print(f"{sender_name} wants to chat with you.")
                # Ask the user if they want to accept the chat
                response = input(f"Accept chat from {sender_name}? (yes/no): ").strip().lower()
                if response == 'yes':
                    # Send acceptance to the server
                    client_socket.send(f'ACCEPT_CHAT:{sender_name}:{username}'.encode())
                    # Wait for server confirmation
                    response = client_socket.recv(1024).decode()
                    if response.startswith('CHAT_ACCEPT'):
                        # Request the sender's public key
                        request = f'GET_PUBLIC_KEY:{sender_name}'
                        client_socket.send(request.encode())
                        while True:
                            # Receive the public key from the server
                            public_key_pem = client_socket.recv(1024).decode()
                            if public_key_pem.startswith('PUBLIC_KEY_NOT_FOUND'):
                                print(f"Public key for {sender_name} not found on the server.")
                                return None
                            elif public_key_pem.startswith('PUBLIC_KEY'):
                                print(f"Chat initiated with {sender_name}. You can start messaging.")
                                return sender_name, public_key_pem
                else:
                    # Reject the chat request
                    print(f"Rejected chat from {sender_name}.")
                    client_socket.send(f'REJECT_CHAT:{sender_name}'.encode())
    except Exception as e:
        # Log any errors that occur during the process
        print(f"Error while listening for incoming requests: {e}")

def initiate_chat(client_socket, username, recipient_name):
    """
    Initiate a chat with a specified recipient.

    Args:
        client_socket (socket): The socket connected to the server.
        username (str): The username of the client.
        recipient_name (str): The username of the chat recipient.

    Returns:
        tuple: (recipient_name, public_key_pem) if chat initiated successfully, otherwise None.
    """
    try:
        # Construct and send the chat request
        request = f'REQUEST_CHAT:{username}:{recipient_name}'
        client_socket.send(request.encode())
        # Receive the server's response
        server_response = client_socket.recv(1024).decode()
        # Handle different server responses
        if server_response.startswith('USER_NOT_FOUND'):
            print(f"User {recipient_name} not found.")
            return None
        elif server_response.startswith('USER_BUSY'):
            print(f"User {recipient_name} is currently busy.")
            return None
        elif server_response.startswith('CHAT_ACCEPT'):
            # If chat is accepted, request the recipient's public key
            request = f'GET_PUBLIC_KEY:{recipient_name}'
            client_socket.send(request.encode())
            while True:
                # Receive the public key from the server
                public_key_pem = client_socket.recv(1024).decode()
                if public_key_pem.startswith('PUBLIC_KEY_NOT_FOUND'):
                    print(f"Public key for {recipient_name} not found on the server.")
                    return None
                elif public_key_pem.startswith('PUBLIC_KEY:'):
                    print(f"Chat initiated with {recipient_name}. You can start messaging.")
                    return recipient_name, public_key_pem
    except Exception as e:
        # Log any errors that occur during chat initiation
        print(f"Error initiating chat with {recipient_name}: {e}")
        return None

def symmetric_key_exchange(sock, username, chat_partner, private_rsa_key, recipient_rsa_public_key, is_initiator):
    """
    Handle symmetric key exchange between two chat partners.

    Args:
        sock (socket.socket): The socket connected to the server.
        username (str): The username of the client.
        chat_partner (str): The username of the chat partner.
        private_rsa_key: The client's private RSA key.
        recipient_rsa_public_key: The recipient's public RSA key.
        is_initiator (bool): True if the client is initiating the chat, else False.

    Returns:
        bytes or None: The symmetric key if successful, else None.
    """
    if is_initiator:
        # Generate a random 256-bit (32-byte) symmetric key
        symmetric_key = secrets.token_bytes(32)
        
        # Encrypt the symmetric key using the recipient's public RSA key
        encrypted_key = encrypt_message_rsa(symmetric_key, recipient_rsa_public_key)
        
        if encrypted_key is None:
            print("Failed to encrypt symmetric key")
            return None
        
        # Prepare the chat ready message with the encrypted key
        request = f'CHAT_READY:{chat_partner}:{encrypted_key.decode()}'
        
        # Send the chat ready message to the server
        sock.send(request.encode())
        
        # Return the generated symmetric key
        return symmetric_key
    else:
        # If not the initiator, wait to receive the symmetric key
        symmetric_key = receive_encrypted_symetric_key(sock, username, private_rsa_key)
        
        if symmetric_key is None:
            print("Failed to receive symmetric key")
            return None
        
        # Return the received and decrypted symmetric key
        return symmetric_key

def receive_encrypted_symetric_key(sock, username, private_rsa_key):
    """
    Receive an encrypted symmetric key and decrypt it.

    Args:
        sock (socket.socket): The socket connected to the server.
        username (str): The username of the client.
        private_rsa_key: The client's private RSA key.

    Returns:
        bytes or None: The decrypted symmetric key, or None if failed.
    """
    while True:
        # Receive data from the server
        response = sock.recv(1024).decode()
        
        # Check if the response indicates that the chat is ready
        if response.startswith('CHAT_READY'):
            # Split the response into components
            _, receiver_name, encrypted_key = response.split(':', 2)
            
            # Verify that the receiver name matches the username
            if receiver_name.strip() == username.strip():
                try:
                    # Decrypt the symmetric key using the client's private RSA key
                    decrypted_symmetric_key = decrypt_message_rsa(encrypted_key, private_rsa_key)
                    
                    if decrypted_symmetric_key:
                        return decrypted_symmetric_key
                    else:
                        print("Failed to decrypt the symmetric key. Requesting a new one.")
                        # Notify sender about the decryption failure
                        sock.send(b'KEY_DECRYPTION_FAILED')
                except Exception as e:
                    # Log any exceptions during decryption
                    print(f"Error during symmetric key decryption: {e}")
                    sock.send(b'KEY_DECRYPTION_FAILED')
        else:
            # Handle unexpected responses
            print(f"Unexpected response: {response[:50]}...")  # Print first 50 chars
            break
    
    # Return None if the process fails
    return None