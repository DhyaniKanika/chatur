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
               
            else:
                print("Login failed.")
        else:
            print("Invalid action")


if __name__ == "__main__":
    main()
