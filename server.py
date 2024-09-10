import socket

def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Get local machine name
    host = 'localhost'
    port = 12345
    
    # Bind to the port
    server_socket.bind((host, port))
    
    # Start listening for connections
    server_socket.listen(5)
    print(f"Server started on {host}:{port}. Waiting for connections...")
    
    # Accept a connection
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr} has been established!")
    
    # Close the connection
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
