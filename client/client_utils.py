import hashlib
import ssl
import subprocess
from client_keytools import *
import secrets
import traceback

SERVER_CRT_PATH = 'truststore/server.pem'

def create_ssl_context():
    # Create SSL context for server authentication
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Load CA certificates for verifying the server
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED  
    context.load_verify_locations(SERVER_CRT_PATH)
    return context


#Since we use a self signed certificate for the demo, we will make our contesxt to trust any certificate that the server sends.
# THIS IS ONLY FOR TESTING
#def create_ssl_context():
#    # Create s default SSL context for server authentication
#    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
#    
#    # Trust whatever the server sends
#    context.check_hostname = False
#    context.verify_mode = ssl.CERT_NONE
#    return context

# Function to hash the password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to read the public key from the file system
def read_public_key(file_path):
    with open(file_path, 'r') as file:
        return file.read().strip()  # Strip any extra newlines

# Function to register the user by sending the username, hashed password, and public key
def register_user(sock, username, password, public_key):
    message = f'REGISTER:{username}:{password}:{public_key}'
    sock.send(message.encode())
    response = sock.recv(1024).decode()
    return response

def login_user(sock, username, password):
    message = f'LOGIN:{username}:{password}'
    sock.sendall(message.encode())
    response = sock.recv(1024).decode()
    return response

def send_message(client_socket, message, recipient_name):
    try:
        client_socket.send(f'MESSAGE:{recipient_name}:{message}'.encode())
    except Exception as e:
        print(f"Error sending message to {recipient_name}: {e}")

def receive_message(client_socket, username):
    try:
        while True:
            server_message = client_socket.recv(1024).decode()
            if server_message.startswith('MESSAGE'):
                _, receiver_name, encoded_message = server_message.split(':', 2)
                if receiver_name.strip() == username.strip():
                    return encoded_message
            else:
                print(f"Unexpected message format: {server_message}")
                return None
    except Exception as e:
        print(f"Error receiving message: {type(e).__name__}: {e}")
        return None


def listen_for_incoming_requests(client_socket, username):
    try:
        while True:
            server_message = client_socket.recv(1024).decode()
            if server_message.startswith('CHAT_REQUEST'):
                _, sender_name = server_message.split(':')
                print(f"{sender_name} wants to chat with you.")
                response = input(f"Accept chat from {sender_name}? (yes/no): ").strip().lower()
                if response == 'yes':
                    client_socket.send(f'ACCEPT_CHAT:{sender_name}:{username}'.encode())
                    response = client_socket.recv(1024).decode()
                    if response.startswith('CHAT_ACCEPT'):
                        request = f'GET_PUBLIC_KEY:{sender_name}'
                        client_socket.send(request.encode())
                        while True:
                            public_key_pem = client_socket.recv(1024).decode()
                            if public_key_pem.startswith('PUBLIC_KEY_NOT_FOUND'):
                                print(f"Public key for {sender_name} not found on the server.")
                                return None
                            elif public_key_pem.startswith('PUBLIC_KEY'):
                                print(f"Chat initiated with {sender_name}. You can start messaging.")
                                return sender_name, public_key_pem
                else:
                    print(f"Rejected chat from {sender_name}.")
                    client_socket.send(f'REJECT_CHAT:{sender_name}'.encode())
    except Exception as e:
        print(f"Error while listening for incoming requests: {e}")

def initiate_chat(client_socket, username, recipient_name):
    try:
        request = f'REQUEST_CHAT:{username}:{recipient_name}'
        client_socket.send(request.encode())
        server_response = client_socket.recv(1024).decode()
        if server_response.startswith('USER_NOT_FOUND'):
            print(f"User {recipient_name} not found.")
            return None
        elif server_response.startswith('USER_BUSY'):
            print(f"User {recipient_name} is currently busy.")
            return None
        elif server_response.startswith('CHAT_ACCEPT'):
            request = f'GET_PUBLIC_KEY:{recipient_name}'
            client_socket.send(request.encode())
            while True:
                public_key_pem = client_socket.recv(1024).decode()
                if public_key_pem.startswith('PUBLIC_KEY_NOT_FOUND'):
                    print(f"Public key for {recipient_name} not found on the server.")
                    return None
                elif public_key_pem.startswith('PUBLIC_KEY:'):
                    print(f"Chat initiated with {recipient_name}. You can start messaging.")
                    return recipient_name, public_key_pem  # Return the full public key PEM
    except Exception as e:
        print(f"Error initiating chat with {recipient_name}: {e}")
        return None

# Symmetric key exchange logic (shared between Alice and Bob)
def symmetric_key_exchange(sock, username, chat_partner, private_rsa_key, recipient_rsa_public_key, is_initiator):
    if is_initiator:
        symmetric_key = secrets.token_bytes(32)
        encrypted_key = encrypt_message_rsa(symmetric_key, recipient_rsa_public_key)
        if encrypted_key is None:
            print("Failed to encrypt symmetric key")
            return None
        request = f'CHAT_READY:{chat_partner}:{encrypted_key.decode()}'
        sock.send(request.encode())
        return symmetric_key
    else:
        symmetric_key = receive_encrypted_symetric_key(sock, username, private_rsa_key)
        if symmetric_key is None:
            print("Failed to receive symmetric key")
            return None
        return symmetric_key

def receive_encrypted_symetric_key(sock, username, private_rsa_key):
    while True:
        response = sock.recv(1024).decode()
        if response.startswith('CHAT_READY'):
            _, receiver_name, encrypted_key = response.split(':', 2)
            if receiver_name.strip() == username.strip():
                try:
                    decrypted_symmetric_key = decrypt_message_rsa(encrypted_key, private_rsa_key)
                    if decrypted_symmetric_key:
                        return decrypted_symmetric_key
                    else:
                        print("Failed to decrypt the symmetric key. Requesting a new one.")
                        sock.send(b'KEY_DECRYPTION_FAILED')
                except Exception as e:
                    print(f"Error during symmetric key decryption: {e}")
                    sock.send(b'KEY_DECRYPTION_FAILED')
        else:
            print(f"Unexpected response: {response[:50]}...")  # Print first 50 chars
            break
    return None
