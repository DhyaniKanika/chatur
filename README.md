# Chatur: A Secure Chat Application

**Chatur** is a secure chat application designed for encrypted communication between users over an untrusted network. It implements end-to-end encryption using symmetric keys, message integrity checks, and secure authentication mechanisms. This project is a university assignment aimed at demonstrating secure chat practices and modern cryptographic techniques.

## Features

- **End-to-End Symmetric Encryption**: Messages are encrypted using a symmetric key that is only known to the communicating clients.
- **Message Integrity**: Uses AESGCM's additional data to ensure message integrity and detect tampering.
- **Secure Authentication**: Users authenticate with a username and hashed password, with credentials stored securely on the server.
- **Dynamic Key Exchange**: Utilizes assymmetric key exchange using RSA to establish a shared secret symmetric key between clients.
- **Active User List**: Clients can view and connect to active users, excluding those who are already in a conversation.