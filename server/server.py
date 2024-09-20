"""
Server Script for Secure Chat Application

This script sets up and runs the server side of a secure chat application.
It handles client connections, user authentication, and message routing.

Key features:
1. SSL/TLS encrypted connections
2. Multi-threaded client handling
3. User authentication
4. Public key management for secure communication

Dependencies:
- socket: For network communications
- threading: For handling multiple client connections
- server_utils: Custom module for server utility functions
- server_handlers: Custom module containing the handle_client function

Usage:
Run this script to start the chat server. Ensure that all required
certificates and keys are in place before starting the server.
"""

import socket
import threading
import server_utils
from server_handlers import handle_client

# Shared dictionaries to store active clients and public keys
clients = {}
user_public_keys = {}

# Server configuration
server_ip = '192.168.11.130'  # IP address for development
server_hostname = "chat.chatur.com"  # Hostname for production use
port = 12345  # Port number for the server to listen on

def main():
    """
    Main function to set up and run the chat server.
    
    This function performs the following tasks:
    1. Creates a server socket
    2. Loads user data from file
    3. Sets up SSL context
    4. Listens for incoming connections
    5. Spawns a new thread for each connected client
    """
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to a specific address and port
    server_socket.bind((server_ip, port))
    
    # Listen for incoming connections (queue up to 5 connections)
    server_socket.listen(5)

    # Load user data from file
    user_data = server_utils.load_user_data()

    # Create SSL context for secure communications
    context = server_utils.create_ssl_context()

    print(f"Server started on {server_ip}:{port}, waiting for connections...")

    # Wrap the socket with SSL/TLS
    with context.wrap_socket(server_socket, server_side=True) as secure_server:
        while True:
            try:
                # Accept incoming client connections
                client_socket, addr = secure_server.accept()
                print(f'New connection from {addr}')
                
                # Start a new thread to handle the connected client
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, clients, user_data, user_public_keys)
                )
                client_thread.start()
            except Exception as e:
                print(f"Error accepting client connection: {e}")

if __name__ == "__main__":
    main()