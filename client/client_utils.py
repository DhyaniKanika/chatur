
import hashlib
import ssl
from client_keytools import *

TRUSTSTORE_PATH = 'truststore.pem'

def create_ssl_context():
    # Create SSL context for server authentication
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Load CA certificates for verifying the server
    context.load_verify_locations(cafile=TRUSTSTORE_PATH)
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
        server_message = client_socket.recv(1024).decode()
        if server_message.startswith('MESSAGE'):
            _, reciever_name, message = server_message.split(':', 2)
            if reciever_name == username:
                return message 
        else:
            print(f"Unexpected message")
            return None
    except Exception as e:
        print(f"Error receiving message: {e}")

def listen_for_incoming_requests(client_socket):
    try:
        while True:
            server_message = client_socket.recv(1024).decode()
            if server_message.startswith('CHAT_REQUEST'):
                _, sender_name = server_message.split(':')
                print(f"{sender_name} wants to chat with you.")
                response = input(f"Accept chat from {sender_name}? (yes/no): ").strip().lower()
                if response == 'yes':
                    client_socket.send(f'ACCEPT_CHAT:{sender_name}'.encode())
                    response = client_socket.recv(1024).decode()
                    if response == 'CHAT_READY':
                        request = f'GET_PUBLIC_KEY:{sender_name}'
                        client_socket.send(request.encode())
                        public_key_pem = client_socket.recv(1024).decode()
                        if public_key_pem == 'PUBLIC_KEY_NOT_FOUND':
                            print(f"Public key for {sender_name} not found on the server.")
                            return None
                        print(f"Chat initiated with {sender_name}. You can start messaging.")
                        return sender_name, public_key_pem
                else:
                    print(f"Rejected chat from {sender_name}.")
                    client_socket.send(f'REJECT_CHAT:{sender_name}'.encode())
            else:
                print(f"Unexpected server message: {server_message}")
    except Exception as e:
        print(f"Error while listening for incoming requests: {e}")

def initiate_chat(client_socket, recipient_name):
    try:
        request = f'REQUEST_CHAT:{recipient_name}'
        client_socket.send(request.encode())
        server_response = client_socket.recv(1024).decode()
        if server_response == 'USER_NOT_FOUND':
            print(f"User {recipient_name} not found.")
            return None
        elif server_response == 'USER_BUSY':
            print(f"User {recipient_name} is currently busy.")
            return None
        elif server_response == 'CHAT_READY':
            request = f'GET_PUBLIC_KEY:{recipient_name}'
            client_socket.send(request.encode())
            public_key_pem = client_socket.recv(1024).decode()
            if public_key_pem == 'PUBLIC_KEY_NOT_FOUND':
                print(f"Public key for {recipient_name} not found on the server.")
                return None
            print(f"Chat initiated with {recipient_name}. You can start messaging.")
            return recipient_name, public_key_pem
    except Exception as e:
        print(f"Error initiating chat with {recipient_name}: {e}")
        return None

# Diffie-Hellman key exchange logic (shared between Alice and Bob)
def diffie_hellman_key_exchange(sock, private_rsa_key, recipient_rsa_public_key, is_initiator):
    private_dh_key, public_dh_key = generate_dh_keys()
    
    # Step 2: If initiator, send DH public key first
    if is_initiator:
        sock.sendall(encrypt_message_rsa(serialize_public_key(public_dh_key), recipient_rsa_public_key))
        other_dh_public_key = receive_encrypted_dh_key(sock, private_rsa_key)
    else:
        other_dh_public_key = receive_encrypted_dh_key(sock, private_rsa_key)
        sock.sendall(encrypt_message_rsa(serialize_public_key(public_dh_key), recipient_rsa_public_key))
    
    return derive_shared_secret(private_dh_key, public_dh_key, other_dh_public_key)


def receive_encrypted_dh_key(sock, private_rsa_key):
    # Receive the encrypted DH public key from the server
    encrypted_dh_public_key = sock.recv(1024)
    # Decrypt the DH public key using the client's own RSA private key
    decrypted_dh_public_key = decrypt_message_rsa(decrypt_message_rsa(encrypted_dh_public_key, private_rsa_key))
    return decrypted_dh_public_key