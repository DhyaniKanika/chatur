import socket
import hashlib

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
    # Send the message to the server
    sock.send(message.encode())
    # Wait for the server's response
    response = sock.recv(1024).decode()
    return response

def login_user(sock, username, password):
    message = f'LOGIN:{username}:{password}'
    sock.sendall(message.encode())
    response = sock.recv(1024).decode()
    return response

def send_message(client_socket, message, recipient_name):
    try:
        # Format the message and send it to the server
        client_socket.send(f'MESSAGE_TO:{recipient_name}:{message}'.encode())
    except Exception as e:
        print(f"Error sending message to {recipient_name}: {e}")


def receive_message(client_socket):
    try:
        # Receive a message from the server
        server_message = client_socket.recv(1024).decode()

        # Split the message to get the sender and the message text
        if server_message.startswith('MESSAGE_FROM'):
            _, sender_name, message = server_message.split(':', 2)
            print(f"Message from {sender_name}: {message}")
        else:
            print(f"Unexpected message: {server_message}")

    except Exception as e:
        print(f"Error receiving message: {e}")

def listen_for_incoming_requests(client_socket):
    try:
        while True:
            # Listen for incoming chat requests from the server
            server_message = client_socket.recv(1024).decode()

            if server_message.startswith('CHAT_REQUEST'):
                # Extract the sender's name from the message
                _, sender_name = server_message.split(':')
                print(f"{sender_name} wants to chat with you.")

                # Ask the user to accept or reject the chat
                response = input(f"Accept chat from {sender_name}? (yes/no): ").strip().lower()

                if response == 'yes':
                    # Notify the server that the chat request is accepted
                    client_socket.send(f'ACCEPT_CHAT:{sender_name}'.encode())

                    # Receive the sender's public key
                    public_key_pem = client_socket.recv(1024).decode()

                    # Save the public key for future use
                    with open(f'{sender_name}_public_key.pem', 'w') as f:
                        f.write(public_key_pem)
                        
                    print(f"Chat with {sender_name} accepted. You can start messaging.")
                    return sender_name  # Return the sender's name

                else:
                    print(f"Rejected chat from {sender_name}.")
                    client_socket.send(f'REJECT_CHAT:{sender_name}'.encode())

            else:
                print(f"Unexpected server message: {server_message}")

    except Exception as e:
        print(f"Error while listening for incoming requests: {e}")


def initiate_chat(client_socket, recipient_name):
    try:
        # Send a request to the server to chat with the recipient
        request = f'REQUEST_CHAT:{recipient_name}'
        client_socket.send(request.encode())  # Send request to server

        # Receive a response from the server
        server_response = client_socket.recv(1024).decode()

        if server_response == 'USER_NOT_FOUND':
            print(f"User {recipient_name} not found.")
            return None
        elif server_response == 'USER_BUSY':
            print(f"User {recipient_name} is currently busy.")
            return None
        elif server_response == 'CHAT_READY':
            # Send request to the server for the recipient's public key
            request = f'GET_PUBLIC_KEY:{recipient_name}'
            client_socket.send(request.encode())  # Send request to server

            # Receive the public key response from the server
            public_key_pem = client_socket.recv(1024).decode()

            if public_key_pem == 'PUBLIC_KEY_NOT_FOUND':
                print(f"Public key for {recipient_name} not found on the server.")
                return None

            # Save the public key to a PEM file for future use
            with open(f'{recipient_name}_public_key.pem', 'w') as f:
                f.write(public_key_pem)
            print(f"Chat initiated with {recipient_name}. You can start messaging.")
            return recipient_name

    except Exception as e:
        print(f"Error initiating chat with {recipient_name}: {e}")
        return None



# Main function to connect to the server and register
def main():
    # Server details
    server_ip = 'chat.chatur.com'
    server_port = 12345       

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, server_port))
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
