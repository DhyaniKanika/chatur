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
    hashed_password = hash_password(password)
    # Construct the registration message
    message = f'REGISTER:{username}:{hashed_password}:{public_key}'
    # Send the message to the server
    sock.send(message.encode())
    # Wait for the server's response
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

        # User input for registration
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        
        # Read the public key from the file system
        public_key_path = "/home/chatur/public_key.pem"
        public_key = read_public_key(public_key_path)
        print(public_key)

        # Register the user and receive server response
        response = register_user(sock, username, password, public_key)
        print(f"Server response: {response}")

if __name__ == "__main__":
    main()
