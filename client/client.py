import socket
from client_utils import *  # Import utility functions like encryption, decryption, etc.
import getpass  # Import getpass to securely read password input

def main():
    # Server details
    server_ip = '192.168.11.130' # we will use ip address for development, replace this with your server ip
    server_hostname = "chat.chatur.com" # we will be using hostname in production
    server_port = 12345  # Define the server port number
    context = create_ssl_context()  # Create an SSL context for a secure connection

    # Ask the user for the password to decrypt their private RSA key
    enc_password = getpass.getpass("enter the password for decrypting keys: ")
    enc_password = enc_password.encode()  # Convert password to bytes
    private_rsa_key = load_private_key_from_file(enc_password)  # Load the private key using the password

    # Create a TCP socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with context.wrap_socket(client_socket, server_hostname=server_hostname) as sock:
        sock.connect((server_ip, server_port))  # Establish a connection to the server
        print("Connected to server.")

        # Ask the user if they want to register or login
        action = input("Enter 'register' to register or 'login' to login: ").strip().lower()
        username = input("Enter your username: ")  # Get the username
        password = hash_password(input("Enter your password: "))  # Hash the password for secure transmission

        if action == 'register':
            # Path to the user's public key
            public_key_path = "keystore/public_key.pem"
            public_key = read_public_key(public_key_path)  # Read the user's public RSA key

            # Send registration details to the server and wait for a response
            response = register_user(sock, username, password, public_key)
            print(f"Server response: {response}")

        elif action == 'login':
            # Attempt to login the user
            response = login_user(sock, username, password)
            if response == 'LOGIN_SUCCESS':
                print("Login successful.")

                # Request a list of active users from the server
                sock.send(b'GET_USERS')  # Send request to get active users
                while True:
                    response = sock.recv(1024).decode()  # Receive server response
                    if response.startswith('USERS'):  # Check if response contains the active users
                        user_list = response.split(':')
                        print("Active users", user_list)  # Print the list of active users
                        break

                # Ask the user if they want to initiate a chat or wait for a request
                mode = input("Do you want to initiate a chat or wait for a request? (initiate/wait): ").strip().lower()

                if mode == 'initiate':
                    # User initiates a chat session by entering the recipient's name
                    recipient_name = input("Enter the recipient's name: ").strip()
                    chat_partner, recipient_public_key = initiate_chat(sock, username, recipient_name)

                    if chat_partner and recipient_public_key:
                        print(f"Recipient public key: {recipient_public_key}")
                        if recipient_public_key.startswith('PUBLIC_KEY:'):
                            # Extract the recipient's public key from the response
                            recipient_public_key = recipient_public_key.split(':', 1)[1].strip()
                        
                        # Perform symmetric key exchange with the recipient
                        shared_secret_key = symmetric_key_exchange(sock, username, chat_partner, private_rsa_key, recipient_public_key, mode == 'initiate')

                        if shared_secret_key is None:
                            print("Error: Failed to establish a shared secret key. Exiting.")
                            return

                        try:
                            # Create a SHA-256 hash of the shared hared integrity and authentication check
                            secret = hashlib.sha256(shared_secret_key).digest()
                        except Exception as e:
                            print(f"Error creating secret: {e}")
                            return
                        
                        while True:
                            # Prompt the user to enter a message to send
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt the outgoing message with the shared secret key
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                            send_message(sock, encrypted_message, chat_partner)  # Send the encrypted message

                            # Wait for and receive an incoming encrypted message
                            incoming_encrypted_message = receive_message(sock, username)
                            if incoming_encrypted_message:
                                # Decrypt the incoming message and display it
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                                print(f"{recipient_name}: {decrypted_message}")
                            else:
                                break  # If no more messages, exit the loop

                elif mode == 'wait':
                    # User waits for an incoming chat request
                    print("Waiting for an incoming chat request...")
                    sender_name, sender_public_key = listen_for_incoming_requests(sock, username)

                    if sender_name and sender_public_key:
                        # Perform symmetric key exchange after receiving a request
                        shared_secret_key = symmetric_key_exchange(sock, username, sender_name, private_rsa_key, sender_public_key, False)
                        if not shared_secret_key:
                            print("Failed to establish a secure connection. Exiting.")
                            return

                        try:
                            # Create a SHA-256 hash of the shared integrity and authentication check
                            secret = hashlib.sha256(shared_secret_key).digest()
                        except Exception as e:
                            print(f"Error creating secret: {e}")
                            return

                        # Listen for incoming messages
                        while True:
                            incoming_encrypted_message = receive_message(sock, username)
                            if incoming_encrypted_message:
                                # Decrypt the incoming message and display it
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                                print(f"{sender_name}: {decrypted_message}")
                            else:
                                break  # If no more messages, exit the loop

                            # Prompt the user to send a message in response
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt the message before sending
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                            send_message(sock, encrypted_message, sender_name)  # Send the encrypted message
                        
                else:
                    print("Invalid mode selected.")  # Handle invalid mode input
            else:
                print("Login failed.")  # Handle login failure
        else:
            print("Invalid action")  # Handle invalid action input

if __name__ == "__main__":
    main()  # Call the main function when the script is run
