#!/bin/bash

# Function to prompt for a password
prompt_for_password() {
    echo -n "Enter password for key encryption and keystore/truststore: "
    read -s PASSWORD
    echo
}

# Function to encrypt files with OpenSSL
encrypt_with_openssl() {
    local file="$1"
    local password="$2"
    if openssl enc -aes-256-cbc -salt -in "$file" -out "$file.enc" -pass pass:"$password"; then
        rm "$file"
    else
        echo "Failed to encrypt $file"
        exit 1
    fi
}

# Function to create a PKCS#12 keystore
create_p12_keystore() {
    local key_file="$1"
    local cert_file="$2"
    local p12_file="$3"
    local p12_pass="$4"

    if openssl pkcs12 -export -out "$p12_file" -inkey "$key_file" -in "$cert_file" -passout pass:"$p12_pass"; then
        echo "PKCS#12 keystore created successfully."
    else
        echo "Failed to create PKCS#12 keystore."
        exit 1
    fi
}

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Update and upgrade package lists
echo "Updating system..."
if ! sudo apt-get update -y && sudo apt-get upgrade -y; then
    echo "Failed to update and upgrade system packages."
    exit 1
fi

# Install Python 3 and pip if not already installed
echo "Installing Python 3 and pip..."
if ! sudo apt-get install python3 python3-pip -y; then
    echo "Failed to install Python 3 and pip."
    exit 1
fi

# Install necessary Python packages
echo "Installing Python packages..."
if ! pip3 install cryptography; then
    echo "Failed to install Python packages."
    exit 1
fi

# Install OpenSSL for generating keys and encryption tools
echo "Installing OpenSSL..."
if ! sudo apt-get install openssl -y; then
    echo "Failed to install OpenSSL."
    exit 1
fi

# Install Java and Keytool for managing keystore/truststore (if not installed)
echo "Installing Java for keytool..."
if ! sudo apt-get install default-jdk -y; then
    echo "Failed to install Java."
    exit 1
fi

# Create directories for the keystore and certificate files
echo "Setting up keystore directories..."
mkdir -p ~/keystore

# Prompt user for password
prompt_for_password

# Generate server private key and CSR
echo "Generating server private key and CSR..."
if ! openssl req -newkey rsa:2048 -keyout ~/keystore/server.key -out ~/keystore/server.csr -nodes -subj "/CN=server"; then
    echo "Failed to generate server private key and CSR."
    exit 1
fi

# Generate a self-signed certificate using the CSR
echo "Generating self-signed certificate for server..."
if ! openssl x509 -req -days 365 -in ~/keystore/server.csr -signkey ~/keystore/server.key -out ~/keystore/server.crt; then
    echo "Failed to generate self-signed certificate."
    exit 1
fi

#generate the keystore.pem file and encrypt that too...
echo "Generating keystore.pem..."
if ! cat ~/keystore/server.crt  ~/keystore/server.key > ~/keystore/keystore.pem; then
    echo "Failed to generate keystore..pem."
    exit 1
fi

# Encrypt the server private key
echo "Encrypting server private key..."
encrypt_with_openssl ~/keystore/server.key "$PASSWORD"

# Create a PKCS#12 keystore
echo "Creating PKCS#12 keystore..."
create_p12_keystore ~/keystore/server.key ~/keystore/server.crt ~/keystore/server.p12 "$PASSWORD"

# Clean up
rm ~/keystore/server.csr

# Output success message and provide the server certificate for manual import
echo "Setup complete!"
echo "The server PKCS#12 keystore has been created at ~/keystore/server.p12."
echo "The server certificate (server.crt) can be manually imported into the client if needed."
