import json

USER_DATA_FILE = 'user_data.json'

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
