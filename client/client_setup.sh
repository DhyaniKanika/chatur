#!/bin/bash

# Function to prompt for a password
prompt_for_password() {
    echo -n "Enter password for key encryption and truststore: "
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

# Function to create a PKCS#12 truststore from a certificate
create_p12_truststore() {
    local cert_file="$1"
    local p12_file="$2"
    local p12_pass="$3"
    
    # Create PKCS#12 truststore from server certificate
    if openssl pkcs12 -export -out "$p12_file" -in "$cert_file" -passout pass:"$p12_pass"; then
        echo "PKCS#12 truststore created successfully."
    else
        echo "Failed to create PKCS#12 truststore."
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

# Create directories for the keystore and truststore
echo "Setting up keystore and truststore directories..."
mkdir -p ~/keystore
mkdir -p ~/truststore

# Prompt user for password
prompt_for_password

# Generate client RSA key pair
echo "Generating client RSA key pair..."
if openssl genpkey -algorithm RSA -out ~/keystore/client.key -aes256 -pass pass:"$PASSWORD" && \
   openssl rsa -in ~/keystore/client.key -pubout -out ~/keystore/client.pub; then
    echo "Client RSA key pair generated successfully."
else
    echo "Failed to generate client RSA key pair."
    exit 1
fi

# Encrypt the client private key
echo "Encrypting client private key..."
encrypt_with_openssl ~/keystore/client.key "$PASSWORD"

# Prompt user for server certificate path
echo -n "Enter the path to the server certificate file: "
read SERVER_CERT_PATH

# Create PKCS#12 truststore and import server certificate
echo "Creating PKCS#12 truststore and importing server certificate..."
create_p12_truststore "$SERVER_CERT_PATH" ~/truststore/truststore.p12 "$PASSWORD"

# Output success message
echo "Setup complete!"
echo "The client RSA key pair has been generated and encrypted."
echo "The server certificate has been imported into the client PKCS#12 truststore."
