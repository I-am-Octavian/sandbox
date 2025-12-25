#!/bin/bash

# Exit on error
set -e

echo "=== eBPF Handler Setup and Execution ==="
echo ""

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo $ID
    else
        echo "unknown"
    fi
}

# Function to install dependencies
install_dependencies() {
    echo "Checking and installing dependencies..."
    
    OS=$(detect_os)
    
    case $OS in
        ubuntu|debian)
            echo "Detected Debian/Ubuntu system"
            sudo apt update
            sudo apt install -y clang libelf1 libelf-dev zlib1g-dev llvm libjson-c-dev git make gcc
            ;;
        fedora|rhel|centos)
            echo "Detected Fedora/RHEL/CentOS system"
            sudo dnf install -y clang elfutils-libelf elfutils-libelf-devel zlib-devel llvm json-c-devel git make gcc
            ;;
        arch|manjaro)
            echo "Detected Arch Linux system"
            sudo pacman -S --noconfirm clang libelf zlib llvm json-c git make gcc
            ;;
        *)
            echo "Unknown OS. Please install dependencies manually:"
            echo "  - clang, libelf, zlib, llvm, json-c, git, make, gcc"
            echo ""
            read -p "Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    echo "Dependencies installed successfully!"
    echo ""
}

# Install dependencies
install_dependencies

# Clone the repository
REPO_DIR="libbpf-bootstrap"
if [ -d "$REPO_DIR" ]; then
    echo "Directory $REPO_DIR already exists. Removing it..."
    rm -rf "$REPO_DIR"
fi

echo "Cloning libbpf-bootstrap repository..."
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap.git
cd "$REPO_DIR"

# Copy your custom files to examples/c
echo "Copying custom files to examples/c..."
cp ../handler.h examples/c/
cp ../handler.c examples/c/
cp ../handler.bpf.c examples/c/
cp ../policy.json examples/c/

# Copy or modify the Makefile
if [ -f "../Makefile" ]; then
    echo "Copying custom Makefile to examples/c..."
    cp ../Makefile examples/c/
else
    echo "Custom Makefile not found. Please ensure your Makefile is in the same directory as this script."
    echo "Alternatively, I can help you modify the existing Makefile."
    echo "Would you like to continue with the existing Makefile? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Exiting. Please provide your custom Makefile and run again."
        exit 1
    fi
fi

# Change to examples/c directory
cd examples/c

# Build the handler
echo "Building handler..."
make handler

# Run the handler with policy.json
echo "Running handler with policy.json..."
sudo ./handler policy.json

echo "=== Complete ==="
