#!/bin/bash

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


# Create directories for the keystore and certificate files
echo "Setting up keystore directories..."
mkdir -p keystore
mkdir -p truststore

# Generate server private key and CSR
echo "Generating server private key and CSR..."
if ! openssl genpkey -algorithm RSA -out keystore/server.key -aes256; then
    echo "Failed to generate server private key and CSR."
    exit 1
fi

if ! openssl req -new -key keystore/server.key -out keystore/server.csr -subj "/CN=chat.chatur.com"; then
    echo "Failed to generate server CSR."
    exit 1
fi


# Generate a self-signed certificate using the CSR
echo "Generating self-signed certificate for server..."
if ! openssl x509 -req -days 365 -in keystore/server.csr -signkey keystore/server.key -out keystore/server.pem; then
    echo "Failed to generate self-signed certificate."
    exit 1
fi

#generate the keystore.pem file and encrypt that too...
echo "Generating keystore.pem..."
if ! cat keystore/server.pem  keystore/server.key > keystore/keystore.pem; then
    echo "Failed to generate keystore..pem."
    exit 1
fi

# Clean up
rm keystore/server.csr

# Output success message and provide the server certificate for manual import
echo "Setup complete!"
echo "The server certificate (server.pem) can be manually imported into the client if needed."
