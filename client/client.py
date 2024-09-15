# client.py
import socket
from client_utils import *
def main():
    # Server details
    server_hostname = 'chat.chatur.com'
    server_port = 12345
    context = create_ssl_context()
    enc_password = input("enter the password for decrypting keys").encode()
    private_rsa_key = load_private_key_from_file(enc_password)

    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with context.wrap_socket(client_socket, server_hostname) as sock:
        sock.connect((server_hostname, server_port))
        print("Connected to server.")

        # Register or login
        action = input("Enter 'register' to register or 'login' to login: ").strip().lower()
        username = input("Enter your username: ")
        password = hash_password(input("Enter your password: "))

        if action == 'register':
            # Read the public key from the file system
            public_key_path = "/home/chatur/public_key.pem"
            public_key = read_public_key(public_key_path)

            # Register the user and receive server response
            response = register_user(sock, username, password, public_key)
            print(f"Server response: {response}")

        elif action == 'login':
            response = login_user(sock, username, password)
            if response == 'LOGIN_SUCCESS':
                print("Login successful.")

                # Request and display the list of active users
                sock.send(b'GET_USERS')
                response = sock.recv(1024)
                user_list = response.decode().split(':')
                print("Active users", user_list)

                # Ask the user if they want to initiate a chat or wait for a request
                mode = input("Do you want to initiate a chat or wait for a request? (initiate/wait): ").strip().lower()

                if mode == 'initiate':
                    # User initiates chat by providing the recipient's name
                    recipient_name = input("Enter the recipient's name: ").strip()
                    chat_partner, recipient_public_key = initiate_chat(sock, recipient_name)

                    if chat_partner and recipient_public_key:
                        # Perform Diffie-Hellman key exchange to derive a shared secret key
                        shared_secret_key = diffie_hellman_key_exchange(sock, private_rsa_key, recipient_public_key, True)
                        
                        while True:
                            # User inputs a message to send
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt and send the message
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, username)
                            send_message(sock, encrypted_message, chat_partner)

                            # Listen for incoming messages
                            incoming_encrypted_message = receive_message(sock)
                            if incoming_encrypted_message:
                                # Decrypt the received message
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, recipient_name)
                                print(f"{recipient_name}: {decrypted_message}")
                            else:
                                break

                elif mode == 'wait':
                    # User waits for an incoming chat request
                    print("Waiting for an incoming chat request...")
                    sender_name, sender_public_key = listen_for_incoming_requests(sock)

                    if sender_name and sender_public_key:
                        # Perform Diffie-Hellman key exchange to derive a shared secret key
                        shared_secret_key = diffie_hellman_key_exchange(sock, private_rsa_key, sender_public_key, False)
                        
                        while True:
                            # Listen for incoming messages
                            incoming_encrypted_message = receive_message(sock)
                            if incoming_encrypted_message:
                                # Decrypt the received message
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, sender_name)
                                print(f"{sender_name}: {decrypted_message}")
                            else:
                                break

                            # User inputs a message to send
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt and send the message
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, username)
                            send_message(sock, encrypted_message, sender_name)
                else:
                    print("Invalid mode selected.")
                    
            else:
                print("Login failed.")
        else:
            print("Invalid action")

if __name__ == "__main__":
    main()
