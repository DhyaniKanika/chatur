#!/bin/bash

# Client Setup Script for Secure Chat Application
#
# This script automates the setup process for the client side of a secure chat application.
# It performs the following tasks:
# 1. Checks for root privileges
# 2. Updates the system packages
# 3. Installs necessary software (Python 3, pip, OpenSSL)
# 4. Sets up directories for key and certificate storage
# 5. Prompts for a password to encrypt the client's private key
# 6. Generates client RSA key pair (encrypted private key and public key)
#
# Usage: 
#   Run this script with root privileges:
#   sudo ./client_setup.sh
#
# Note: This script should be run on each client machine that will use the chat application.

# Function to securely prompt for a password
prompt_for_password() {
    # Prompt the user to enter a password without echoing it to the screen
    echo -n "Enter password for key encryption and truststore: "
    read -s PASSWORD  # -s flag makes the input silent
    echo  # Print a newline after password input
}

# Check if the script is being run with root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Update and upgrade package lists
echo "Updating system..."
if ! sudo apt-get update -y && sudo apt-get upgrade -y; then
    # Update package lists and upgrade installed packages
    echo "Failed to update and upgrade system packages."
    exit 1
fi

# Install Python 3 and pip if not already installed
echo "Installing Python 3 and pip..."
if ! sudo apt-get install python3 python3-pip -y; then
    # Install Python 3 and pip package manager
    echo "Failed to install Python 3 and pip."
    exit 1
fi

# Install necessary Python packages
echo "Installing Python packages..."
if ! pip3 install cryptography; then
    # Install the cryptography package using pip
    echo "Failed to install Python packages."
    exit 1
fi

# Install OpenSSL for generating keys and encryption tools
echo "Installing OpenSSL..."
if ! sudo apt-get install openssl -y; then
    # Install OpenSSL for cryptographic operations
    echo "Failed to install OpenSSL."
    exit 1
fi

# Create directories for the keystore and truststore
echo "Setting up keystore and truststore directories..."
mkdir -p keystore  # Create keystore directory if it doesn't exist
mkdir -p truststore  # Create truststore directory if it doesn't exist

# Prompt user for password to encrypt the private key
prompt_for_password

# Generate client RSA key pair
echo "Generating client RSA key pair..."
if openssl genpkey -algorithm RSA -out keystore/client.key -aes256 -pass pass:"$PASSWORD" && \
   openssl rsa -in keystore/client.key -pubout -out keystore/public_key.pem; then
    # Generate an RSA private key encrypted with AES-256 using the provided password
    # Then extract the public key from the private key
    echo "Client RSA key pair generated successfully."
else
    echo "Failed to generate client RSA key pair."
    exit 1
fi

# Output success message
echo "Setup complete!"
echo "The client RSA key pair has been generated and encrypted."

# End of script