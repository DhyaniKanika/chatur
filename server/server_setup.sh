#!/bin/bash

# Server Setup Script for Secure Chat Application
#
# This script automates the setup process for the server side of a secure chat application.
# It performs the following tasks:
# 1. Checks for root privileges
# 2. Updates the system packages
# 3. Installs necessary software (Python 3, pip, OpenSSL)
# 4. Sets up directories for key and certificate storage
# 5. Generates server private key, CSR, and self-signed certificate
# 6. Creates a combined keystore file
#
# Usage: 
#   Run this script with root privileges:
#   sudo ./server_setup.sh
#
# Note: This script should be run on the server machine where the chat server will be hosted.

# Check if the script is being run with root privileges
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

# Install necessary Python packages (cryptography in this case)
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
mkdir -p keystore  # Create keystore directory if it doesn't exist
mkdir -p truststore  # Create truststore directory if it doesn't exist

# Generate server private key and Certificate Signing Request (CSR)
echo "Generating server private key and CSR..."
if ! openssl genpkey -algorithm RSA -out keystore/server.key -aes256; then
    # Generate an RSA private key with AES-256 encryption
    echo "Failed to generate server private key and CSR."
    exit 1
fi

if ! openssl req -new -key keystore/server.key -out keystore/server.csr -subj "/CN=chat.chatur.com"; then
    # Create a CSR using the private key, with the Common Name set to chat.chatur.com
    echo "Failed to generate server CSR."
    exit 1
fi

# Generate a self-signed certificate using the CSR
echo "Generating self-signed certificate for server..."
if ! openssl x509 -req -days 365 -in keystore/server.csr -signkey keystore/server.key -out keystore/server.pem; then
    # Create a self-signed certificate valid for 365 days
    echo "Failed to generate self-signed certificate."
    exit 1
fi

# Generate the keystore.pem file by combining the certificate and private key
echo "Generating keystore.pem..."
if ! cat keystore/server.pem keystore/server.key > keystore/keystore.pem; then
    # Concatenate the certificate and private key into a single file
    echo "Failed to generate keystore.pem."
    exit 1
fi

# Clean up temporary files
rm keystore/server.csr  # Remove the CSR as it's no longer needed

# Output success message and provide instructions
echo "Setup complete!"
echo "The server certificate (server.pem) can be manually imported into the client if needed."

# End of script