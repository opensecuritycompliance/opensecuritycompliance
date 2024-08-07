#!/bin/bash


# Check if pip is available
if command -v pip &>/dev/null; then
    PIP_COMMAND="pip"
elif command -v pip3 &>/dev/null; then
    PIP_COMMAND="pip3"
else
    echo "Error: Neither pip nor pip3 found. Please install pip."
    exit 1
fi

$PIP_COMMAND install -r ./src/compliancecowcards/requirements.txt
$PIP_COMMAND install -r ./src/compliancecow-data-library/requirements.txt
$PIP_COMMAND install -r ./catalog/appconnections/python/requirements.txt

$PIP_COMMAND install ./src/compliancecowcards
$PIP_COMMAND install ./src/compliancecow-data-library/compliancecow
$PIP_COMMAND install ./catalog/appconnections/python

GO_VERSION="1.21.3"


# Function to check if Go is installed
check_go_installed() {
    if command -v go &>/dev/null; then
        echo "Go is already installed."
        return 0
    else
        echo "Go is not installed."
        return 1
    fi
}

# Function to install Go on Linux
install_go_linux() {
    echo "Installing Go on Linux..."
    # Download and install Go for Linux (adjust the URL as needed)
    curl -O https://golang.org/dl/go$GO_VERSION.linux-amd64.tar.gz
    tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
    rm go$GO_VERSION.linux-amd64.tar.gz

    if check_go_installed; then
        echo "Go installed successfully."
    else
        echo "Failed to install Go."
        exit 1
    fi
}

# Function to install Go on macOS
install_go_macos() {
    echo "Installing Go on macOS..."
    # Download and install Go for macOS (adjust the URL as needed)
    curl -O https://golang.org/dl/go$GO_VERSION.darwin-amd64.tar.gz
    tar -C /usr/local -xzf go$GO_VERSION.darwin-amd64.tar.gz
    rm go$GO_VERSION.darwin-amd64.tar.gz

    if check_go_installed; then
        echo "Go installed successfully."
    else
        echo "Failed to install Go."
        exit 1
    fi
}

# Function to install Go on Windows
install_go_windows() {
    echo "Windows OS is not supported in this script."
    exit 1
}

# Function to install Go based on OS
install_go_based_on_os() {
    case "$(uname -s)" in
        Linux*) install_go_linux ;;
        Darwin*) install_go_macos ;;
        CYGWIN*) install_go_windows ;;
        MINGW*) install_go_windows ;;
        *) echo "Unsupported OS." ;;
    esac
}

# Function to install Go packages
install_go_packages() {
    check_go_installed || install_go_based_on_os

    # echo "Go packages installed successfully."
}

# Main script
install_go_packages
