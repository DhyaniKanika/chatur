import socket
from client_utils import *
import getpass

def main():
    # Server details
    print("Test_git")
    server_hostname = 'server.localdomain'
    server_port = 12345
    context = create_ssl_context()
    enc_password = getpass.getpass("enter the password for decrypting keys: ")
    enc_password = enc_password.encode()
    private_rsa_key = load_private_key_from_file(enc_password)

    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with context.wrap_socket(client_socket, server_hostname=server_hostname) as sock:
        sock.connect((server_hostname, server_port))
        print("Connected to server.")

        # Register or login
        action = input("Enter 'register' to register or 'login' to login: ").strip().lower()
        username = input("Enter your username: ")
        password = hash_password(input("Enter your password: "))

        if action == 'register':
            # Read the public key from the file system
            public_key_path = "keystore/public_key.pem"
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
                # response = sock.recv(1024)
                # print(response.decode())
                # user_list = response.decode().split(':')
                
                while True:
                    response = sock.recv(1024).decode()
                    if response.startswith('USERS'):
                        user_list = response.split(':')
                        print("Active users", user_list)
                        break

                # Ask the user if they want to initiate a chat or wait for a request
                mode = input("Do you want to initiate a chat or wait for a request? (initiate/wait): ").strip().lower()

                if mode == 'initiate':
                    # User initiates chat by providing the recipient's name
                    recipient_name = input("Enter the recipient's name: ")
                    recipient_name = recipient_name.strip()
                    chat_partner, recipient_public_key = initiate_chat(sock, username, recipient_name)

                    if chat_partner and recipient_public_key:
                        # Perform Diffie-Hellman key exchange to derive a shared secret key
                        shared_secret_key = symmetric_key_exchange(sock, username, chat_partner, private_rsa_key, recipient_public_key, True)
                        secret = hashlib.sha256(shared_secret_key).hexdigest().encode()
                        
                        while True:
                            # User inputs a message to send
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt and send the message
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                            print(encrypted_message)
                            send_message(sock, encrypted_message, chat_partner)

                            # Listen for incoming messages
                            incoming_encrypted_message = receive_message(sock, username)
                            if incoming_encrypted_message:
                                # Decrypt the received message
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                                print(f"{recipient_name}: {decrypted_message}")
                            else:
                                break

                elif mode == 'wait':
                    # User waits for an incoming chat request
                    print("Waiting for an incoming chat request...")
                    sender_name, sender_public_key = listen_for_incoming_requests(sock, username)

                    if sender_name and sender_public_key:
                        # Perform Diffie-Hellman key exchange to derive a shared secret key
                        shared_secret_key = symmetric_key_exchange(sock, username, sender_name, private_rsa_key, sender_public_key, False)
                        secret = hashlib.sha256(shared_secret_key).hexdigest().encode()

                        
                        while True:
                            # Listen for incoming messages
                            incoming_encrypted_message = receive_message(sock, username)
                            if incoming_encrypted_message:
                                # Decrypt the received message
                                decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                                print(f"{sender_name}: {decrypted_message}")
                            else:
                                break

                            # User inputs a message to send
                            outgoing_message = input(f"{username}: ").strip()
                            
                            # Encrypt and send the message
                            encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                            send_message(sock, encrypted_message, sender_name)
                else:
                    print("Invalid mode selected.")
                    
            else:
                print("Login failed.")
        else:
            print("Invalid action")

if __name__ == "__main__":
    main()
