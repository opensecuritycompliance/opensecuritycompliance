#!/bin/bash

# Function to check if a command exists
function check_command() {
    command -v "$1" &>/dev/null
}

# Function to fix broken pip if necessary
function fix_pip_shebang() {
    local pip_cmd="$1"
    local python_path

    # Get the correct Python interpreter path
    python_path=$(command -v python3)
    if [ -z "$python_path" ]; then
        echo "Error: python3 not found. Please install Python 3."
        exit 1
    fi

    # Fix the pip shebang
    local pip_path
    pip_path=$(command -v "$pip_cmd")
    if [ -f "$pip_path" ]; then
        echo "Fixing shebang in $pip_path..."
        sed -i.bak "1s|.*|#!$python_path|" "$pip_path" || {
            echo "Error: Failed to update the shebang in $pip_path."
            exit 1
        }
        echo "Shebang fixed successfully."
    else
        echo "Error: Could not locate $pip_cmd executable."
        exit 1
    fi
}

# Check for pip or pip3
if check_command pip; then
    PIP_COMMAND="pip"
elif check_command pip3; then
    PIP_COMMAND="pip3"
else
    echo "Error: Neither pip nor pip3 found. Please install pip."
    exit 1
fi

# Verify if pip is functional
if ! $PIP_COMMAND --version &>/dev/null; then
    echo "Warning: $PIP_COMMAND is installed but not functional. Attempting to fix..."
    fix_pip_shebang "$PIP_COMMAND"
fi

# Re-check if pip is functional after fixing
if ! $PIP_COMMAND --version &>/dev/null; then
    echo "Error: Failed to fix $PIP_COMMAND. Please check your Python and pip installation."
    exit 1
fi

# Install requirements and packages
set -e  # Exit immediately if a command exits with a non-zero status
echo "Installing dependencies from requirements files..."
$PIP_COMMAND install -r ./src/compliancecowcards/requirements.txt
$PIP_COMMAND install -r ./catalog/appconnections/python/requirements.txt

echo "Installing packages..."
$PIP_COMMAND install ./src/compliancecowcards
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
