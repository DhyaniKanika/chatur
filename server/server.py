import socket
import threading
import server_utils as server_utils
from server_handlers import handle_client

# Shared dictionaries to store active clients and public keys
clients = {}
user_public_keys = {}
server_ip = '192.168.11.130' # we will use ip address for development, replace this with your server ip
server_hostname = "chat.chatur.com" # we will be using hostname in production
port=12345

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, port))
    server_socket.listen(5) 

    # Load user data from file
    user_data = server_utils.load_user_data()

    # Create SSL context
    context = server_utils.create_ssl_context()

    print("Server started, waiting for connections...")

    with context.wrap_socket(server_socket, server_side=True) as server:
        print("Server started, waiting for connections...")
        while True:
            client_socket, addr = server.accept()
            print(f'Connection from {addr}')
            # Start a new thread to handle each connected client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, clients, user_data, user_public_keys))
            client_thread.start()



if __name__ == "__main__":
    main()
