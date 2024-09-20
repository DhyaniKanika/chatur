"""
Client Module for Secure Chat Application

This module implements the client-side functionality of a secure chat application.
It handles user registration, login, initiating chats, and secure message exchange.

Key features:
1. Secure connection to the server using SSL/TLS
2. User registration and login
3. Initiating and accepting chat requests
4. Secure message exchange using symmetric encryption
5. Public key exchange for establishing shared secrets

Dependencies:
- socket: For network communications
- client_utils: Custom module containing utility functions (imported as *)
- getpass: For secure password input
- hashlib: For creating message digests (imported through client_utils)

Usage:
Run this script to start the client application. Follow the prompts to register
or login, and then initiate or wait for a chat session.
"""

import socket
from client_utils import *
import getpass

def main():
    """
    Main function to run the client-side chat application.
    
    This function handles the entire flow of the client application, including:
    - Connecting to the server
    - User authentication (registration or login)
    - Initiating or waiting for chat sessions
    - Secure message exchange
    """
    # Define the server's IP address for development
    server_ip = '192.168.11.130'
    # Define the server's hostname for production use
    server_hostname = "chat.chatur.com"
    # Define the server's port number
    server_port = 12345
    
    # Create an SSL context for secure connection
    context = create_ssl_context()

    # Prompt the user to enter the password for decrypting keys
    enc_password = getpass.getpass("Enter the password for decrypting keys: ")
    # Convert the password to bytes
    enc_password = enc_password.encode()
    # Load the private key using the provided password
    private_rsa_key = load_private_key_from_file(enc_password)

    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Wrap the socket with SSL and connect to the server
    with context.wrap_socket(client_socket, server_hostname=server_hostname) as sock:
        # Establish a connection to the server
        sock.connect((server_ip, server_port))
        # Print a message indicating successful connection
        print("Connected to server.")

        # Prompt the user to choose between registration and login
        action = input("Enter 'register' to register or 'login' to login: ").strip().lower()
        # Get the username from the user
        username = input("Enter your username: ")
        # Get the password from the user and hash it
        password = hash_password(input("Enter your password: "))

        # Handle user registration
        if action == 'register':
            # Define the path to the user's public key
            public_key_path = "keystore/public_key.pem"
            # Read the user's public RSA key from the file
            public_key = read_public_key(public_key_path)
            # Send registration details to the server and get the response
            response = register_user(sock, username, password, public_key)
            # Print the server's response to the registration attempt
            print(f"Server response: {response}")

        # Handle user login
        elif action == 'login':
            # Attempt to login the user and get the response
            response = login_user(sock, username, password)
            # Check if login was successful
            if response == 'LOGIN_SUCCESS':
                # Print a success message
                print("Login successful.")

                # Request a list of active users from the server
                sock.send(b'GET_USERS')
                # Wait for and process the server's response
                while True:
                    # Receive the server's response
                    response = sock.recv(1024).decode()
                    # Check if the response contains the list of users
                    if response.startswith('USERS'):
                        # Split the response to get the list of users
                        user_list = response.split(':')
                        # Print the list of active users
                        print("Active users:", user_list)
                        # Exit the loop after receiving the user list
                        break

                # Ask the user if they want to initiate a chat or wait for a request
                mode = input("Do you want to initiate a chat or wait for a request? (initiate/wait): ").strip().lower()

                # Handle chat initiation
                if mode == 'initiate':
                    # Get the name of the recipient from the user
                    recipient_name = input("Enter the recipient's name: ").strip()
                    # Initiate a chat with the specified recipient
                    chat_partner, recipient_public_key = initiate_chat(sock, username, recipient_name)

                    # If chat initiation was successful
                    if chat_partner and recipient_public_key:
                        # Print the recipient's public key
                        print(f"Recipient public key: {recipient_public_key}")
                        # Extract the actual key if it's prefixed with 'PUBLIC_KEY:'
                        if recipient_public_key.startswith('PUBLIC_KEY:'):
                            recipient_public_key = recipient_public_key.split(':', 1)[1].strip()
                        
                        # Perform symmetric key exchange with the recipient
                        shared_secret_key = symmetric_key_exchange(sock, username, chat_partner, private_rsa_key, recipient_public_key, True)

                        # Check if key exchange was successful
                        if shared_secret_key is None:
                            print("Error: Failed to establish a shared secret key. Exiting.")
                            return

                        try:
                            # Create a SHA-256 hash of the shared secret for integrity and authentication check
                            secret = hashlib.sha256(shared_secret_key).digest()
                        except Exception as e:
                            # Print an error message if secret creation fails
                            print(f"Error creating secret: {e}")
                            return
                        
                        # Main chat loop
                        while True:
                            # Prompt the user to enter a message to send
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt the outgoing message with the shared secret key
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                            # Send the encrypted message
                            send_message(sock, encrypted_message, chat_partner)

                            # Wait for and receive an incoming encrypted message
                            incoming_encrypted_message = receive_message(sock, username)
                            # If a message was received
                            if incoming_encrypted_message:
                                # Decrypt the incoming message and display it
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                                print(f"{recipient_name}: {decrypted_message}")
                            else:
                                # If no more messages, exit the loop
                                break

                # Handle waiting for chat requests
                elif mode == 'wait':
                    # Inform the user that they're waiting for a chat request
                    print("Waiting for an incoming chat request...")
                    # Listen for incoming chat requests
                    sender_name, sender_public_key = listen_for_incoming_requests(sock, username)

                    # If a chat request was received
                    if sender_name and sender_public_key:
                        # Perform symmetric key exchange after receiving a request
                        shared_secret_key = symmetric_key_exchange(sock, username, sender_name, private_rsa_key, sender_public_key, False)
                        # Check if key exchange was successful
                        if not shared_secret_key:
                            print("Failed to establish a secure connection. Exiting.")
                            return

                        try:
                            # Create a SHA-256 hash of the shared secret for integrity and authentication check
                            secret = hashlib.sha256(shared_secret_key).digest()
                        except Exception as e:
                            # Print an error message if secret creation fails
                            print(f"Error creating secret: {e}")
                            return

                        # Listen for incoming messages
                        while True:
                            # Receive an incoming encrypted message
                            incoming_encrypted_message = receive_message(sock, username)
                            # If a message was received
                            if incoming_encrypted_message:
                                # Decrypt the incoming message and display it
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                                print(f"{sender_name}: {decrypted_message}")
                            else:
                                # If no more messages, exit the loop
                                break

                            # Prompt the user to send a message in response
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt the message before sending
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                            # Send the encrypted message
                            send_message(sock, encrypted_message, sender_name)
                        
                else:
                    # Handle invalid mode input
                    print("Invalid mode selected.")
            else:
                # Handle login failure
                print("Login failed.")
        else:
            # Handle invalid action input
            print("Invalid action")

# Check if this script is being run directly
if __name__ == "__main__":
    # Call the main function to start the client application
    main()