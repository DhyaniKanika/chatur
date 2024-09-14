import socket
import threading
import json

# File to store user data (e.g., username and password)
USER_DATA_FILE = 'user_data.json'

# Function to load user data from a file (returns a dictionary)
def load_user_data():
    try:
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)  # Load JSON file and return as a dictionary
    except FileNotFoundError:
        return {}  # If file doesn't exist, return an empty dictionary

# Function to save user data to a file
def save_user_data(user_data):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file)  # Save dictionary as JSON to the file

# Function to handle communication with the connected client
def handle_client(client_socket,clients, user_data):
    # Using 'with' to automatically close the socket after the connection ends
    with client_socket:
        print(f'Handling connection from {client_socket.getpeername()}')  # Log client's IP and port
        while True:
            try:
                # Receive a message from the client (up to 1024 bytes)
                message = client_socket.recv(1024)
                
                if not message:
                    break  # If no message is received, break the loop
                
                # Split the message into command and additional parts
                command, *message_parts = message.decode().split(':')
                
                # Handle registration command
                if command == 'REGISTER':
                    client_name = message_parts[0]  # Username
                    client_password = message_parts[1]  # Password
                    client_public_key = message_parts[2]  # Public key
                    
                    # Check if the username is already registered
                    if client_name in user_data:
                        client_socket.send(b'USER_EXISTS')  # Notify client that the user already exists
                    else:
                        # Register the new user
                        user_data[client_name] = client_password  # Save username and password
                        save_user_data(user_data)  # Save the updated user data

                        # Save the client's public key to a file
                        with open(f'client_{client_name}_public_key.pem', 'w') as f:
                            f.write(client_public_key)  # Write public key to a PEM file
                        
                        # Send confirmation to the client
                        client_socket.send(b'REGISTERED')

                elif command == 'LOGIN':
                    client_name = message_parts[0]  # Username
                    client_password = message_parts[1]  # Password
                    if client_name in user_data and user_data[client_name] == client_password:
                        clients[client_name] = client_socket
                        client_socket.send(b'LOGIN_SUCCESS')
                    else:
                        client_socket.send(b'LOGIN_FAILED')

            except Exception as e:
                # Log any error that occurs during client handling
                print(f"Error handling client: {e}")
                break

# Main function to start the server
def main():
    # Create a TCP socket for the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to an IP address and port
    server_socket.bind(('10.10.1.12', 12345))
    
    # Set the server to listen for incoming connections (queue up to 5)
    server_socket.listen(5)
    
    # Load any existing user data from the file
    user_data = load_user_data()

    clients = {}

    print("Server started, waiting for connections...")

    # Main loop to accept incoming connections
    while True:
        # Accept a new connection from a client
        client_socket, addr = server_socket.accept()
        print(f'Connection from {addr}')  # Log client's address
        
        # Start a new thread to handle each connected client
        client_thread = threading.Thread(target=handle_client, args=(client_socket, clients, user_data))
        client_thread.start()  # Run the handle_client function in a separate thread

if __name__ == "__main__":
    # Run the main server function
    main()
