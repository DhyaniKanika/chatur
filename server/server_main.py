import socket
import threading
from utils import load_user_data, load_user_public_key, remove_client
from handlers import handle_client

# Shared dictionaries to store active clients and public keys
clients = {}
user_public_keys = {}

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('10.10.1.12', 12345))
    server_socket.listen(5)

    # Load user data from file
    user_data = load_user_data()

    print("Server started, waiting for connections...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f'Connection from {addr}')

        # Start a new thread to handle each connected client
        client_thread = threading.Thread(target=handle_client, args=(client_socket, clients, user_data, user_public_keys))
        client_thread.start()

if __name__ == "__main__":
    main()
