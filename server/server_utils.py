"""
Server Utilities Module for Secure Chat Application

This module provides utility functions for the server-side operations of the
secure chat application. It handles user data management, public key loading,
and SSL context creation for secure communication.

Key functionalities:
1. Loading and saving user credentials
2. Loading user public keys
3. Creating and configuring SSL context for the server

The module uses JSON for data storage and the ssl module for secure communication setup.
"""

import json
import ssl

# Path to the file where user data (e.g., usernames and passwords) is stored
USER_DATA_FILE = 'truststore/user_data.json'

# Path to the keystore where the server's certificate and private key are stored
KEYSTORE_PATH = 'keystore/keystore.pem'

def load_user_data():
    """
    Load user data (credentials) from a JSON file.

    This function attempts to read user credentials from a JSON file. If the file
    doesn't exist, it returns an empty dictionary, allowing for a fresh start
    if no user data has been saved yet.

    Returns:
        dict: A dictionary containing user credentials, where keys are usernames
              and values are passwords. Returns an empty dict if the file is not found.

    Raises:
        json.JSONDecodeError: If the file exists but contains invalid JSON.
    """
    try:
        # Open and read the user data file
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        # Return an empty dictionary if the file is not found
        return {}

def save_user_data(user_data):
    """
    Save user data (credentials) to a JSON file.

    This function writes the provided user data to a JSON file, overwriting
    any existing data in the file.

    Args:
        user_data (dict): A dictionary containing user credentials, where
                          keys are usernames and values are passwords.

    Raises:
        IOError: If there's an issue writing to the file.
        TypeError: If the user_data is not JSON serializable.
    """
    # Open the user data file in write mode and save the updated data
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file)

def load_user_public_key(client_name):
    """
    Load a specific user's public key from a PEM file.

    This function attempts to read the public key for a given user from a PEM file.
    The filename is constructed based on the client's name.

    Args:
        client_name (str): The name of the client whose public key is to be loaded.

    Returns:
        str: The content of the public key file as a string.
        None: If the file is not found.

    Raises:
        IOError: If there's an issue reading the file (other than FileNotFound).
    """
    try:
        # Open and read the public key file for the specified client
        with open(f'truststore/client_{client_name}_public_key.pem', 'r') as f:
            return f.read()
    except FileNotFoundError:
        # Print an error message and return None if the public key file is missing
        print(f"Public key for {client_name} not found!")
        return None

def create_ssl_context():
    """
    Create and configure the SSL context for the server.

    This function sets up the server for secure communication (TLS) using
    its certificate and private key. It configures a one-way SSL handshake,
    where the server presents its certificate but doesn't verify client certificates.

    Returns:
        ssl.SSLContext: A configured SSL context ready for use by the server.

    Raises:
        ssl.SSLError: If there's an issue loading the certificate or private key.
        FileNotFoundError: If the keystore file is not found.
    """
    # Create an SSL context with TLS for secure server communication
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Load the server's certificate and private key from the keystore
    context.load_cert_chain(certfile=KEYSTORE_PATH, keyfile=KEYSTORE_PATH)
    
    # Configure SSL settings: 
    # - No need to verify client certificates (one-way SSL handshake)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Return the configured SSL context
    return context