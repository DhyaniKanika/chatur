"""
Server Handlers Module for Secure Chat Application

This module contains handler functions for various client requests and actions
in the secure chat application. It manages user registration, login, message
routing, and other client-server interactions.

The module provides the following main functionalities:
1. Client connection handling
2. User registration and login
3. Chat request management
4. Message routing between clients
5. Public key distribution

Each function in this module is designed to handle a specific aspect of the
chat application's server-side logic, ensuring secure and efficient communication
between clients.
"""

# Import necessary functions from server_utils module
from server_utils import save_user_data, load_user_public_key
# Import traceback for detailed error reporting
import traceback

def handle_client(client_socket, clients, user_data, user_public_keys):
    """
    Main function to handle communication with a connected client.

    This function acts as the central hub for processing all client requests.
    It continuously listens for messages from the client, decodes them, and
    routes them to the appropriate handler function based on the command received.

    Args:
        client_socket (socket): The socket object for the connected client.
        clients (dict): A dictionary of all active client connections.
        user_data (dict): A dictionary containing user credentials.
        user_public_keys (dict): A dictionary of user public keys.

    Returns:
        None

    Raises:
        Exception: Any unexpected errors during client handling are caught and logged.
    """
    # Use a context manager to ensure the socket is properly closed after handling
    with client_socket:
        # Log the connection details
        print(f'Handling connection from {client_socket.getpeername()}')
        # Continuous loop to handle client requests
        while True:
            try:
                # Receive up to 1024 bytes of data from the client
                message = client_socket.recv(1024)
                # If no data is received, the client has disconnected
                if not message:
                    break

                # Decode the message and split it into command and parts
                command, *message_parts = message.decode().split(':')

                # Route the command to the appropriate handler function
                if command == 'REGISTER':
                    # Handle user registration
                    handle_registration(client_socket, message_parts, user_data)
                elif command == 'LOGIN':
                    # Handle user login
                    handle_login(client_socket, message_parts, clients, user_data, user_public_keys)
                elif command == 'GET_USERS':
                    # Handle request for list of active users
                    handle_get_users(client_socket, clients)
                elif command == 'GET_PUBLIC_KEY':
                    # Handle request for a user's public key
                    handle_get_public_key(client_socket, message_parts, user_public_keys)
                elif command == 'REQUEST_CHAT':
                    # Handle chat request between users
                    handle_chat_request(message_parts[0], message_parts[1], client_socket, clients)
                elif command == 'ACCEPT_CHAT':
                    # Handle acceptance of a chat request
                    handle_accept_chat(message_parts[0], message_parts[1], clients)
                elif command == 'REJECT_CHAT':
                    # Handle rejection of a chat request
                    handle_reject_chat(message_parts[0], message_parts[1], clients)
                elif command == 'MESSAGE':
                    # Handle message sending between users
                    handle_message(client_socket, message_parts[0], message_parts[1], clients)
                elif command == 'CHAT_READY':
                    # Handle notification that a chat is ready to begin
                    # Reconstruct the data part which may contain colons
                    tmp_message_parts = [message_parts[0], ':'.join(message_parts[1:])]
                    handle_chat_ready(tmp_message_parts[0], tmp_message_parts[1], clients)

            except Exception as e:
                # Log any errors that occur during client handling
                print(f"Error handling client: {e}")
                # Print the full traceback for debugging
                print(traceback.format_exc())
                # Exit the loop if an error occurs
                break

def handle_registration(client_socket, message_parts, user_data):
    """
    Handle the user registration process.

    This function processes a registration request from a client. It checks if
    the username is available, and if so, adds the new user to the user_data
    dictionary and saves their public key.

    Args:
        client_socket (socket): The socket object for the client requesting registration.
        message_parts (list): A list containing the username, password, and public key.
        user_data (dict): A dictionary containing all user credentials.

    Returns:
        None

    Side effects:
        - Updates the user_data dictionary with the new user's credentials.
        - Saves the new user's public key to a file.
        - Sends a response to the client indicating success or failure.
    """
    # Unpack the message parts
    client_name, client_password, client_public_key = message_parts

    # Check if the username already exists
    if client_name in user_data:
        # Send a message indicating the user already exists
        client_socket.send(b'USER_EXISTS')
    else:
        # Add the new user to the user_data dictionary
        user_data[client_name] = client_password
        # Save the updated user data to persistent storage
        save_user_data(user_data)

        # Save the client's public key to a file
        with open(f'truststore/client_{client_name}_public_key.pem', 'w') as f:
            f.write(client_public_key)

        # Send a confirmation message to the client
        client_socket.send(b'REGISTERED')
        # Log the successful registration
        print(f'{client_name} registered successfully')

def handle_login(client_socket, message_parts, clients, user_data, user_public_keys):
    """
    Handle the user login process.

    This function authenticates a user's login attempt. If successful, it adds
    the user to the active clients list and loads their public key.

    Args:
        client_socket (socket): The socket object for the client attempting to log in.
        message_parts (list): A list containing the username and password.
        clients (dict): A dictionary of all active client connections.
        user_data (dict): A dictionary containing all user credentials.
        user_public_keys (dict): A dictionary to store user public keys.

    Returns:
        None

    Side effects:
        - Updates the clients dictionary if login is successful.
        - Loads the user's public key into user_public_keys.
        - Sends a response to the client indicating success or failure.
    """
    # Unpack the message parts
    client_name, client_password = message_parts

    # Check if the username exists and the password is correct
    if client_name in user_data and user_data[client_name] == client_password:
        # Add the client to the active clients dictionary
        clients[client_name] = client_socket
        # Load the user's public key
        user_public_keys[client_name] = load_user_public_key(client_name)
        # Check if the public key was successfully loaded
        if user_public_keys[client_name] is None:
            # Notify the client that their public key is missing
            client_socket.send(b'PUBLIC_KEY_MISSING')
        else:
            # Log the successful login
            print(f'{client_name} has LOGGED IN')
            # Send a login success message to the client
            client_socket.send(b'LOGIN_SUCCESS')
    else:
        # Send a login failed message if credentials are incorrect
        client_socket.send(b'LOGIN_FAILED')

def handle_get_users(client_socket, clients):
    """
    Handle a request for the list of active users.

    This function sends a list of all currently active users to the requesting client.

    Args:
        client_socket (socket): The socket object for the client requesting the user list.
        clients (dict): A dictionary of all active client connections.

    Returns:
        None

    Side effects:
        Sends a message to the client with the list of active users.
    """
    # Create a string of active usernames separated by colons
    user_list = f"USERS:{':'.join(clients.keys())}"
    # Send the list of users to the client
    client_socket.send(user_list.encode())

def handle_get_public_key(client_socket, message_parts, user_public_keys):
    """
    Handle a request for a user's public key.

    This function responds to a client's request for another user's public key.

    Args:
        client_socket (socket): The socket object for the client requesting the public key.
        message_parts (list): A list containing the username of the requested public key.
        user_public_keys (dict): A dictionary of user public keys.

    Returns:
        None

    Side effects:
        Sends a message to the client with the requested public key or a not found message.
    """
    # Get the username of the requested public key
    recipient_name = message_parts[0]
    # Check if the public key for the requested user exists
    if recipient_name in user_public_keys:
        # Send the public key to the client
        client_socket.send(str(f"PUBLIC_KEY:{user_public_keys[recipient_name]}").encode())
    else:
        # Send a message indicating the public key was not found
        client_socket.send(b'PUBLIC_KEY_NOT_FOUND')

def handle_chat_request(sender_username, recipient_username, sender_socket, clients):
    """
    Handle a chat request between users.

    This function processes a chat request from one user to another, notifying
    the recipient if they are online.

    Args:
        sender_username (str): The username of the client sending the chat request.
        recipient_username (str): The username of the intended chat recipient.
        sender_socket (socket): The socket object for the sending client.
        clients (dict): A dictionary of all active client connections.

    Returns:
        None

    Side effects:
        - Sends a chat request to the recipient if they are online.
        - Notifies the sender if the recipient is not found.
    """
    # Check if the recipient is currently online
    if recipient_username in clients:
        # Get the recipient's socket
        recipient_socket = clients[recipient_username]
        # Log the chat request
        print(f'CHAT_REQUEST from {sender_username} to {recipient_username}')
        # Send the chat request to the recipient
        recipient_socket.send(f'CHAT_REQUEST:{sender_username}'.encode())
    else:
        # Notify the sender that the recipient was not found
        sender_socket.send(f'USER_NOT_FOUND:{recipient_username}'.encode())

def handle_accept_chat(sender_username, recipient_username, clients):
    """
    Handle the acceptance of a chat request.

    This function processes the acceptance of a chat request, notifying both
    the sender and the recipient that the chat has been established.

    Args:
        sender_username (str): The username of the client who sent the original chat request.
        recipient_username (str): The username of the client who accepted the chat request.
        clients (dict): A dictionary of all active client connections.

    Returns:
        None

    Side effects:
        - Notifies both the sender and recipient that the chat has been accepted.
        - Logs the established chat connection.
    """
    # Check if the sender is still online
    if sender_username in clients:
        # Get the sender's socket
        sender_socket = clients[sender_username]
        # Notify the sender that the chat was accepted
        sender_socket.send(f'CHAT_ACCEPT:{recipient_username}'.encode())
        # Get the recipient's socket
        recipient_socket = clients[recipient_username]
        # Notify the recipient that the chat was accepted
        recipient_socket.send(f'CHAT_ACCEPT:{sender_username}'.encode())
        # Log the established chat
        print(f'{sender_username} is TALKING to {recipient_username}')
    else:
        # If the sender is no longer online, notify the recipient
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'USER_NOT_FOUND:{sender_username}'.encode())

def handle_reject_chat(sender_username, recipient_username, clients):
    """
    Handle the rejection of a chat request.

    This function processes the rejection of a chat request, notifying the
    sender that their request was declined.

    Args:
        sender_username (str): The username of the client who sent the original chat request.
        recipient_username (str): The username of the client who rejected the chat request.
        clients (dict): A dictionary of all active client connections.

    Returns:
        None

    Side effects:
        Notifies the sender that their chat request was rejected.
    """
    # Check if the sender is still online
    if sender_username in clients:
        # Get the sender's socket
        sender_socket = clients[sender_username]
        # Notify the sender that their chat request was rejected
        sender_socket.send(f'CHAT_REJECTED:{recipient_username}'.encode())

def handle_message(sender_socket, recipient_username, message_body, clients):
    """
    Handle sending a message from one client to another.

    This function forwards a message from the sender to the recipient if the
    recipient is online.

    Args:
        sender_socket (socket): The socket object for the sending client.
        recipient_username (str): The username of the intended message recipient.
        message_body (str): The content of the message to be sent.
        clients (dict): A dictionary of all active client connections.

    Returns:
        None

    Side effects:
        - Forwards the message to the recipient if they are online.
        - Notifies the sender if the recipient is not found.
    """
    # Check if the recipient is currently online
    if recipient_username in clients:
        # Get the recipient's socket
        recipient_socket = clients[recipient_username]
        # Forward the message to the recipient
        recipient_socket.send(f'MESSAGE:{recipient_username}:{message_body}'.encode())
    else:
        # Notify the sender that the recipient was not found
        sender_socket.send(f'USER_NOT_FOUND:{recipient_username}'.encode())

def handle_chat_ready(recipient_username, data, clients):
    """
    Handle notifying a client that the chat is ready to begin.

    This function is called when the key exchange is completed and the chat
    is ready to start. It notifies the recipient that they can begin chatting.

    Args:
        recipient_username (str): The username of the client to be notified.
        data (str): Additional data to be sent with the chat ready notification.
        clients (dict): A dictionary of all active client connections.

    Returns:
        None

    Side effects:
        Sends a 'CHAT_READY' message to the recipient if they are online.
    """
    # Check if the recipient is currently online
    if recipient_username in clients:
        # Get the recipient's socket
        recipient_socket = clients[recipient_username]
        # Notify the recipient that the chat is ready
        recipient_socket.send(f'CHAT_READY:{recipient_username}:{data}'.encode())

def remove_client(client_socket, clients):
    """
    Remove a client from the list of active clients.

    This function is called when a client disconnects or needs to be removed
    from the active clients list for any reason.

    Args:
        client_socket (socket): The socket object for the client to be removed.
        clients (dict): A dictionary of all active client connections.

    Returns:
        None

    Side effects:
        - Removes the client from the clients dictionary.
        - Closes the client's socket connection.
    """
    # Iterate through the clients dictionary
    for username, sock in clients.items():
        # If the socket matches the client_socket, remove the client
        if sock == client_socket:
            del clients[username]
            break
    # Terminate client socket connection
    client_socket.close()