import socket
from client_utils import *
import getpass

def main():
    # Server details
    server_hostname = 'server.localdomain'
    server_port = 12345
    context = create_ssl_context()
    # enc_password = getpass.getpass("enter the password for decrypting keys: ")
    # enc_password = enc_password.encode()
    # private_rsa_key = load_private_key_from_file(enc_password)
    
    enc_password = getpass.getpass("enter the password for decrypting keys: ")
    enc_password = enc_password.encode()
    private_rsa_key = load_private_key_from_file(enc_password)
    if private_rsa_key is None:
        print("Failed to load private key. Exiting.")
        return
    print(f"Loaded private key successfully. Key size: {private_rsa_key.key_size}")

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
                        print(f"Recipient public key: {recipient_public_key}")
                        if recipient_public_key.startswith('PUBLIC_KEY:'):
                            recipient_public_key = recipient_public_key.split(':', 1)[1].strip()
                        
                        # Perform symmetric key exchange
                        shared_secret_key = symmetric_key_exchange(sock, username, chat_partner, private_rsa_key, recipient_public_key, mode == 'initiate')
                        
                        print(f"sock: {sock}")
                        print(f"username: {username}")
                        print(f"chat_partner: {chat_partner}")
                        print(f"recipient_public_key: {recipient_public_key}")
                        print(f"Value of shared_secret_key: {shared_secret_key.hex() if shared_secret_key else None}")

                        if shared_secret_key is None:
                            print("Error: Failed to establish a shared secret key. Exiting.")
                            return

                        try:
                            print(f"Creating secret from shared_secret_key: {shared_secret_key.hex()}")
                            secret = hashlib.sha256(shared_secret_key).digest()
                            print(f"Secret created successfully. Length: {len(secret)}")
                            print(f"Secret (hex): {secret.hex()}")
                            print(f"First 8 bytes of secret: {secret[:8].hex()}")
                        except Exception as e:
                            print(f"Error creating secret: {e}")
                            return

                        print("Symmetric key exchange completed successfully.")
                        
                        # Test message
                        test_message = "Hello, this is a test message!"
                        print(f"Original test message: {test_message}")
                        encrypted_message = encrypt_message_symmetric(secret, test_message)
                        print(f"Sending encrypted message: {encrypted_message}")
                        send_message(sock, encrypted_message, chat_partner,secret)
                        
                        # while True:
                        #     # User inputs a message to send
                        #     outgoing_message = input(f"{username}: ").strip()
                            
                        #     # Encrypt and send the message
                        #     encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                        #     print(encrypted_message)
                        #     send_message(sock, encrypted_message, chat_partner,secret)

                        #     # Listen for incoming messages
                        #     incoming_encrypted_message = receive_message(sock, username)
                        #     if incoming_encrypted_message:
                        #         # Decrypt the received message
                        #         decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                        #         print(f"{recipient_name}: {decrypted_message}")
                        #     else:
                        #         break

                elif mode == 'wait':                   
                    # if sender_name and sender_public_key:
                    #     shared_secret_key = symmetric_key_exchange(sock, username, sender_name, private_rsa_key, sender_public_key, False)
                    #     secret = hashlib.sha256(shared_secret_key).hexdigest().encode()

                    #     print(f"secret: {secret}")
                        
                    #     while True:
                    #         # Listen for incoming messages
                    #         incoming_encrypted_message = receive_message(sock, username)
                    #         if incoming_encrypted_message:
                    #             # Decrypt the received message
                    #             decrypted_message = decrypt_message_symmetric(shared_secret_key, incoming_encrypted_message, secret)
                    #             print(f"{sender_name}: {decrypted_message}")
                    #         else:
                    #             break
                    
                    # # User inputs a message to send
                    # outgoing_message = input(f"{username}: ").strip()
                    
                    # # Encrypt and send the message
                    # encrypted_message = encrypt_message_symmetric(shared_secret_key, outgoing_message, secret)
                    # send_message(sock, encrypted_message, sender_name)

                    # User waits for an incoming chat request
                    print("Waiting for an incoming chat request...")
                    sender_name, sender_public_key = listen_for_incoming_requests(sock, username)
                    
                    if sender_name and sender_public_key:
                        print(f"Initiating key exchange with {sender_name}")
                        shared_secret_key = symmetric_key_exchange(sock, username, sender_name, private_rsa_key, sender_public_key, False)
                        if not shared_secret_key:
                            print("Failed to establish a secure connection. Exiting.")
                            return

                        print(f"Shared secret key established. Length: {len(shared_secret_key)}")
                        secret = hashlib.sha256(shared_secret_key).digest()
                        print(f"First 8 bytes of secret: {secret[:8].hex()}")
                        print(f"Derived secret length: {len(secret)}")
                        
                        print("Waiting for test message...")

                        encrypted_message = receive_message(sock, username, secret)
                        decoded_message = base64.urlsafe_b64decode(encrypted_message)
                        if encrypted_message:
                            print(f"Received message: {decoded_message}")
                        else:
                            print("Failed to decrypt the message.")
                        
                else:
                    print("Invalid mode selected.")
            else:
                print("Login failed.")
        else:
            print("Invalid action")

if __name__ == "__main__":
    main()
