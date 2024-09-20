from server_utils import save_user_data, load_user_public_key
import traceback

# Main function to handle communication with a connected client.
# Handles different commands from the client such as registration, login, chat requests, etc.
def handle_client(client_socket, clients, user_data, user_public_keys):
    with client_socket:
        print(f'Handling connection from {client_socket.getpeername()}')
        while True:
            print(client_socket)
            try:
                # Receive the message from the client
                message = client_socket.recv(1024)
                if not message:
                    break

                # Split the message into command and parts
                command, *message_parts = message.decode().split(':')

                # Handle different commands sent by the client
                if command == 'REGISTER':
                    handle_registration(client_socket, message_parts, user_data)

                elif command == 'LOGIN':
                    handle_login(client_socket, message_parts, clients, user_data, user_public_keys)

                elif command == 'GET_USERS':
                    handle_get_users(client_socket, clients)

                elif command == 'GET_PUBLIC_KEY':
                    handle_get_public_key(client_socket, message_parts, user_public_keys)

                elif command == 'REQUEST_CHAT':
                    handle_chat_request(message_parts[0], message_parts[1], client_socket, clients)

                elif command == 'ACCEPT_CHAT':
                    handle_accept_chat(message_parts[0], message_parts[1], clients)

                elif command == 'REJECT_CHAT':
                    handle_reject_chat(message_parts[0], message_parts[1], clients)

                elif command == 'MESSAGE':
                    handle_message(client_socket, message_parts[0], message_parts[1], clients)

                elif command == 'CHAT_READY':
                    # Handle when a client is ready to start a chat with the recipient
                    tmp_message_parts = [message_parts[0], ':'.join(message_parts[1:])]
                    handle_chat_ready(tmp_message_parts[0], tmp_message_parts[1], clients)

            except Exception as e:
                # Handle any exceptions that occur during client communication
                print(f"Error handling client: {e}")
                print(traceback.format_exc())
                break

# Handle user registration process
# This function registers a new user, saves their password and public key
def handle_registration(client_socket, message_parts, user_data):
    client_name = message_parts[0]
    client_password = message_parts[1]
    client_public_key = message_parts[2]

    # Check if the username already exists
    if client_name in user_data:
        client_socket.send(b'USER_EXISTS')
    else:
        # Save the user credentials
        user_data[client_name] = client_password
        save_user_data(user_data)

        # Save client's public key to a file
        with open(f'truststore/client_{client_name}_public_key.pem', 'w') as f:
            f.write(client_public_key)

        client_socket.send(b'REGISTERED')
        print(f'{client_name} registered successfully')

# Handle user login process
# This function checks the user's credentials and logs them in if valid
def handle_login(client_socket, message_parts, clients, user_data, user_public_keys):
    client_name = message_parts[0]
    client_password = message_parts[1]

    # Check if the username exists and the password is correct
    if client_name in user_data and user_data[client_name] == client_password:
        # Add the client to the active clients list
        clients[client_name] = client_socket
        user_public_keys[client_name] = load_user_public_key(client_name)
        if user_public_keys[client_name] is None:
            client_socket.send(b'PUBLIC_KEY_MISSING')
        else:
            print(f'{client_name} has LOGGED IN')
            client_socket.send(b'LOGIN_SUCCESS')
    else:
        client_socket.send(b'LOGIN_FAILED')

# Send the list of active users to the client
def handle_get_users(client_socket, clients):
    # Concatenate all active usernames and send them to the client
    user_list = f"USERS:{':'.join(clients.keys())}"
    client_socket.send(user_list.encode())

# Handle a request to get the public key of a specific user
def handle_get_public_key(client_socket, message_parts, user_public_keys):
    recipient_name = message_parts[0]
    # Check if the recipient's public key exists and send it, otherwise return an error
    if recipient_name in user_public_keys:
        client_socket.send(str(f"PUBLIC_KEY:{user_public_keys[recipient_name]}").encode())
    else:
        client_socket.send(b'PUBLIC_KEY_NOT_FOUND')

# Handle a chat request between users
def handle_chat_request(sender_username, recipient_username, sender_socket, clients):
    # Check if the recipient user is online
    if recipient_username in clients:
        recipient_socket = clients[recipient_username]
        print(f'CHAT_REQUEST from {sender_username} to {recipient_username}')
        # Notify the recipient of the chat request
        recipient_socket.send(f'CHAT_REQUEST:{sender_username}'.encode())
    else:
        sender_socket.send(f'USER_NOT_FOUND:{recipient_username}'.encode())

# Handle when a chat request is accepted
def handle_accept_chat(sender_username, recipient_username, clients):
    if sender_username in clients:
        # Notify both sender and recipient that the chat has been accepted
        sender_socket = clients[sender_username]
        sender_socket.send(f'CHAT_ACCEPT:{recipient_username}'.encode())
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'CHAT_ACCEPT:{sender_username}'.encode())
        print(f'{sender_username} is TALKING to {recipient_username}')
    else:
        # Notify the recipient that the sender is not found
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'USER_NOT_FOUND:{sender_username}'.encode())

# Handle when a chat request is rejected
def handle_reject_chat(sender_username, recipient_username, clients):
    # Notify the sender that their chat request was rejected
    if sender_username in clients:
        sender_socket = clients[sender_username]
        sender_socket.send(f'CHAT_REJECTED:{recipient_username}'.encode())

# Handle sending a message from one client to another
def handle_message(sender_socket, recipient_username, message_body, clients):
    # Check if the recipient is online
    if recipient_username in clients:
        recipient_socket = clients[recipient_username]
        # Forward the message to the recipient
        recipient_socket.send(f'MESSAGE:{recipient_username}:{message_body}'.encode())
    else:
        # Notify the sender that the recipient was not found
        sender_socket.send(f'USER_NOT_FOUND:{recipient_username}'.encode())

# Handle notifying a client that the chat is ready (key exchange completed)
def handle_chat_ready(recipient_username, data, clients):
    # Check if the recipient is online and notify them
    if recipient_username in clients:
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'CHAT_READY:{recipient_username}:{data}'.encode())

# Remove a client from the list of active clients
def remove_client(client_socket, clients):
    # Iterate through the list of clients to find the client to remove
    for username, sock in clients.items():
        if sock == client_socket:
            del clients[username]
            break
    client_socket.close()
