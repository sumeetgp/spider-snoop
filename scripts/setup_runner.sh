#!/bin/bash

# setup_runner.sh
# Automates the installation of a GitHub Actions Self-Hosted Runner on Linux x64

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$#" -ne 2 ]; then
    echo -e "${RED}Usage: $0 <REPO_URL> <RUNNER_TOKEN>${NC}"
    echo "Example: $0 https://github.com/user/repo A1B2C3D4E5..."
    exit 1
fi

REPO_URL=$1
TOKEN=$2
RUNNER_VERSION="2.321.0" # Update as needed from GitHub Actions UI
RUNNER_DIR="actions-runner"
RUNNER_NAME="spider-runner-$(hostname)"

echo -e "${BLUE}=== Starting Runner Setup ===${NC}"

# 1. Update & Install Dependencies
echo -e "${GREEN}[1/5] Installing dependencies...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y curl tar libdigest-sha-perl
elif command -v yum &> /dev/null; then
    sudo yum install -y curl tar perl-Digest-SHA
fi

# 2. Create Directory
echo -e "${GREEN}[2/5] Creating runner directory...${NC}"
mkdir -p $RUNNER_DIR && cd $RUNNER_DIR

# 3. Download Runner
echo -e "${GREEN}[3/5] Downloading runner v${RUNNER_VERSION}...${NC}"
curl -o actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz -L https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz

# Optional: Validate hash (Best practice)
# echo "ba46ba7ce3a2d7236b16fca444c3dc4d9337e348  actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" | shasum -a 256 -c

echo -e "${GREEN}[4/5] Extracting...${NC}"
tar xzf ./actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz

# 4. Configure Runner
echo -e "${GREEN}[5/5] Configuring runner...${NC}"
# --unattended: Don't ask questions
# --replace: Replace existing runner with same name
echo "Configuring connection to GitHub..."
./config.sh --url "${REPO_URL}" --token "${TOKEN}" --name "${RUNNER_NAME}" --work "_work" --unattended --replace

# 5. Install & Start Service
echo -e "${BLUE}=== Installing Systemd Service ===${NC}"
sudo ./svc.sh install
sudo ./svc.sh start

echo -e "${GREEN}SUCCESS! Runner '${RUNNER_NAME}' is active and listening.${NC}"
sudo ./svc.sh status
