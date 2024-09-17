from server.server_utils import save_user_data, load_user_public_key

def handle_client(client_socket, clients, user_data, user_public_keys):
    with client_socket:
        print(f'Handling connection from {client_socket.getpeername()}')
        while True:
            try:
                message = client_socket.recv(1024)
                if not message:
                    break

                command, *message_parts = message.decode().split(':')

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
                    handle_message(message_parts[0], message_parts[1], message_parts[2], clients)
                    
                elif command == 'CHAT_READY':
                    handle_chat_ready(message_parts[0], message_parts[1], message_parts[2], clients)
                    

            except Exception as e:
                print(f"Error handling client: {e}")
                break
            finally:
                remove_client(client_socket, clients)

def handle_registration(client_socket, message_parts, user_data):
    client_name = message_parts[0]
    client_password = message_parts[1]
    client_public_key = message_parts[2]

    if client_name in user_data:
        client_socket.send(b'USER_EXISTS')
    else:
        user_data[client_name] = client_password
        save_user_data(user_data)

        # Save client's public key to a file
        with open(f'truststore/client_{client_name}_public_key.pem', 'w') as f:
            f.write(client_public_key)

        client_socket.send(b'REGISTERED')

def handle_login(client_socket, message_parts, clients, user_data, user_public_keys):
    client_name = message_parts[0]
    client_password = message_parts[1]

    if client_name in user_data and user_data[client_name] == client_password:
        clients[client_name] = client_socket
        user_public_keys[client_name] = load_user_public_key(client_name)
        client_socket.send(b'LOGIN_SUCCESS')
    else:
        client_socket.send(b'LOGIN_FAILED')

def handle_get_users(client_socket, clients):
    user_list = 'USERS:'.join(clients.keys())
    client_socket.send(user_list.encode())

def handle_get_public_key(client_socket, message_parts, user_public_keys):
    recipient_name = message_parts[0]
    if recipient_name in user_public_keys:
        client_socket.send(f'PUBLIC_KEY:{user_public_keys[recipient_name]}'.encode())
    else:
        client_socket.send(b'PUBLIC_KEY_NOT_FOUND')

def handle_chat_request(sender_username, recipient_username, sender_socket, clients):
    if recipient_username in clients:
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'CHAT_REQUEST:{sender_username}'.encode())
    else:
        sender_socket.send(f'USER_NOT_FOUND:{recipient_username}'.encode())

def handle_accept_chat(sender_username, recipient_username, clients):
    if sender_username in clients:
        sender_socket = clients[sender_username]
        sender_socket.send(f'CHAT_ACCEPT:{recipient_username}'.encode())
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'CHAT_ACCEPT:{sender_username}'.encode())
    else:
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'USER_NOT_FOUND:{sender_username}'.encode())

def handle_reject_chat(sender_username, recipient_username, clients):
    if sender_username in clients:
        sender_socket = clients[sender_username]
        sender_socket.send(f'CHAT_REJECTED:{recipient_username}'.encode())

def handle_message(sender_username, recipient_username, message_body, clients):
    if recipient_username in clients:
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'MESSAGE:{sender_username}:{recipient_username}:{message_body}'.encode())
    else:
        sender_socket = clients[sender_username]
        sender_socket.send(f'USER_NOT_FOUND:{recipient_username}'.encode())
        
def handle_chat_ready( message_parts, clients):
    sender_username = message_parts[0]
    recipient_username = message_parts[1]
    client_message = message_parts[2]

    if recipient_username in clients:
        recipient_socket = clients[recipient_username]
        recipient_socket.send(f'CHAT_READY:{sender_username}:{recipient_username}:{client_message}'.encode())
    else:
        sender_socket = clients[sender_username]
        sender_socket.send(f'USER_NOT_FOUND:{recipient_username}'.encode())

def remove_client(client_socket, clients):
    for username, sock in clients.items():
        if sock == client_socket:
            del clients[username]
            break
    client_socket.close()