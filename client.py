import socket

def connect_to_server():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Get local machine name
    host = 'localhost'
    port = 12345
    
    # Connect to the server
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")
    
    # Close the connection
    client_socket.close()

if __name__ == "__main__":
    connect_to_server()
