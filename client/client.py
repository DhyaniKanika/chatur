# client.py
import socket
from client_utils import create_ssl_context, hash_password, read_public_key, register_user, login_user, send_message, receive_message, initiate_chat, listen_for_incoming_requests

def main():
    # Server details
    server_hostname = 'chat.chatur.com'
    server_port = 12345
    context = create_ssl_context()

    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with context.wrap_socket(client_socket, server_hostname) as sock:
        sock.connect((server_hostname, server_port))
        print("Connected to server.")

        # Register or login
        action = input("Enter 'register' to register or 'login' to login: ")
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
                    recipient_name = input("Enter the recipient's name: ").strip()
                    chat_with = initiate_chat(sock, recipient_name)

                    if chat_with:
                        while True:
                            message = input(f"Message to {chat_with}: ").strip()
                            send_message(sock, message, chat_with)

                            # Listen for incoming messages
                            receive_message(sock)

                elif mode == 'wait':
                    print("Waiting for an incoming chat request...")
                    sender_name = listen_for_incoming_requests(sock)

                    if sender_name:
                        while True:
                            message = input(f"Message to {sender_name}: ").strip()
                            send_message(sock, message, sender_name)

                            # Listen for incoming messages
                            receive_message(sock)

                else:
                    print("Invalid mode selected.")
                    
            else:
                print("Login failed.")
        else:
            print("Invalid action")

if __name__ == "__main__":
    main()
