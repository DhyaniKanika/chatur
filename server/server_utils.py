import json
import ssl

# Path to the file where user data (e.g., usernames and passwords) is stored
USER_DATA_FILE = 'truststore/user_data.json'

# Path to the keystore where the server's certificate and private key are stored
KEYSTORE_PATH = 'keystor/keystore.pem'

# Load user data (credentials) from the JSON file
# If the file doesn't exist, return an empty dictionary
def load_user_data():
    try:
        # Open and read the user data file
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        # Return an empty dictionary if the file is not found
        return {}

# Save user data (credentials) to the JSON file
def save_user_data(user_data):
    # Open the user data file in write mode and save the updated data
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file)

# Load a specific user's public key from a PEM file
# Returns the public key as a string, or None if the file is not found
def load_user_public_key(client_name):
    try:
        # Open and read the public key file for the specified client
        with open(f'truststore/client_{client_name}_public_key.pem', 'r') as f:
            return f.read()
    except FileNotFoundError:
        # Print an error message and return None if the public key file is missing
        print(f"Public key for {client_name} not found!")
        return None

# Create and configure the SSL context for the server
# This sets up the server for secure communication (TLS) using its certificate and private key
def create_ssl_context():
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
