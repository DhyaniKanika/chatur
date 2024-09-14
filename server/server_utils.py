import json
import ssl

USER_DATA_FILE = 'user_data.json'
KEYSTORE_PATH = 'keystore.pem'
TRUSTSTORE_PATH = 'truststore.pem'

def load_user_data():
    try:
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_user_data(user_data):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file)

def load_user_public_key(client_name):
    try:
        with open(f'client_{client_name}_public_key.pem', 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Public key for {client_name} not found!")
        return None


def create_ssl_context():
    # Create SSL context for server authentication (client certificates are not required)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Load the server's certificate and private key
    context.load_cert_chain(certfile=KEYSTORE_PATH, keyfile=KEYSTORE_PATH)
    
    # Optionally, load CA certificates if we want to verify any client certificates in the future
    # In this case, we are not expecting client certificates, but this is for completeness
    context.load_verify_locations(cafile=TRUSTSTORE_PATH)
    
    # The server will not request client certificates
    context.verify_mode = ssl.CERT_NONE  # No client certificates required
    
    return context