#!/bin/bash

# Function to prompt for a password
prompt_for_password() {
    echo -n "Enter password for key encryption and truststore: "
    read -s PASSWORD
    echo
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
mkdir -p keystore
mkdir -p truststore

# Prompt user for password
prompt_for_password

# Generate client RSA key pair
echo "Generating client RSA key pair..."
if openssl genpkey -algorithm RSA -out keystore/client.key -aes256 -pass pass:"$PASSWORD" && \
   openssl rsa -in keystore/client.key -pubout -out keystore/public_key.pem; then
    echo "Client RSA key pair generated successfully."
else
    echo "Failed to generate client RSA key pair."
    exit 1
fi

# Output success message
echo "Setup complete!"
echo "The client RSA key pair has been generated and encrypted."
