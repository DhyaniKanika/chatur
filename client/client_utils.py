import hashlib
import ssl
import subprocess
import base64
from client_keytools import *
import secrets

TRUSTSTORE_PATH = 'truststore'

# def create_ssl_context():
#     # Create SSL context for server authentication
#     context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
#     # Load CA certificates for verifying the server
#     context.load_verify_locations(cafile=TRUSTSTORE_PATH)
#     return context

#Since we use a self signed certificate for the demo, we will make our contesxt to trust any certificate that the server sends.
# THIS IS ONLY FOR TESTING
def create_ssl_context():
    # Create s default SSL context for server authentication
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Trust whatever the server sends
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

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
                _, reciever_name, message = server_message.split(':', 2)
                if reciever_name.strip() == username.strip():
                    return message 
            else:
                print(f"Unexpected message")
                return None
    except Exception as e:
        print(f"Error receiving message: {e}")

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
        print(server_response)
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
                elif public_key_pem.startswith('PUBLIC_KEY'):
                    print(f"Chat initiated with {recipient_name}. You can start messaging.")
                    return recipient_name, public_key_pem
    except Exception as e:
        print(f"Error initiating chat with {recipient_name}: {e}")
        return None

# Symmetric key exchange logic (shared between Alice and Bob)
def symmetric_key_exchange(sock,username, chat_partner, private_rsa_key, recipient_rsa_public_key, is_initiator):  
    # If initiator, send key first
    if is_initiator:
        symetric_key = (secrets.token_bytes(32))
        recipient_rsa_public_key = bytearray(
                    recipient_rsa_public_key.split(':')[1].encode()
                )
        request = f'CHAT_READY:{chat_partner}:{encrypt_message_rsa(symetric_key, load_public_key(recipient_rsa_public_key))}'
        request =  base64.b64encode(request.encode())
        sock.send(request)
    else:
        symetric_key = receive_encrypted_symetric_key(sock,username, private_rsa_key)
    
    return symetric_key


def receive_encrypted_symetric_key(sock, username, private_rsa_key):
    # Receive the encrypted symetric key from the server
    while True:
        response = sock.recv(1024).decode()
        response = base64.b64decode(response)
        print(response)
        # Decrypt the key using the client's own RSA private key
        if response.startswith('CHAT_READY'):
            _, reciever_name, message = response.split(':', 2)
            print(message)
            if reciever_name == username:
                # decrypted_symetric_key = decrypt_message_rsa(decrypt_message_rsa(message, private_rsa_key))
                decrypted_symetric_key = decrypt_message_rsa(message, private_rsa_key)
                print(decrypted_symetric_key)
                print(decrypted_symetric_key.decode())
                return decrypted_symetric_key.decode()
            return None


def decrypt_truststore(encrypted_file: str, decrypted_file: str, password: str):
    """Decrypt the encrypted truststore file."""
    try:
        subprocess.run([
            'openssl', 'enc', '-d', '-aes-256-cbc',
            '-in', encrypted_file,
            '-out', decrypted_file,
            '-pass', f'pass:{password}'
        ], check=True)
        print(f"Decrypted truststore saved to: {decrypted_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error during decryption: {e}")
        raise

def encrypt_truststore(decrypted_file: str, encrypted_file: str, password: str):
    """Encrypt the truststore file."""
    try:
        subprocess.run([
            'openssl', 'enc', '-aes-256-cbc',
            '-salt', '-in', decrypted_file,
            '-out', encrypted_file,
            '-pass', f'pass:{password}'
        ], check=True)
        print(f"Encrypted truststore saved to: {encrypted_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error during encryption: {e}")
        raise