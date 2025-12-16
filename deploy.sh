#!/bin/bash

# Configuration
APP_NAME="SPIDERCOB DLP"
DOCKER_COMPOSE_FILE="docker-compose.yml"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting deployment for $APP_NAME...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed.${NC}"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    # Try docker compose plugin
    if ! docker compose version &> /dev/null; then
         echo -e "${RED}Error: Docker Compose is not installed.${NC}"
         exit 1
    fi
    DOCKER_CMD="docker compose"
else
    DOCKER_CMD="docker-compose"
fi

# Setup Environment
if [ ! -f .env ]; then
    echo -e "${YELLOW}.env file not found. Creating from example...${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "${GREEN}.env created.${NC}"
    else
        echo -e "${RED}Error: .env.example not found.${NC}"
        exit 1
    fi
fi

# Check Critical Variables
if ! grep -q "OPENAI_API_KEY" .env || grep -q "OPENAI_API_KEY=$" .env; then
    echo -e "${YELLOW}OPENAI_API_KEY is missing or empty in .env${NC}"
    echo -n "Please enter your OpenAI API Key: "
    read api_key
    if [ -n "$api_key" ]; then
        # Replace or append
        if grep -q "OPENAI_API_KEY" .env; then
            sed -i.bak "s|OPENAI_API_KEY=.*|OPENAI_API_KEY=$api_key|" .env && rm .env.bak
        else
             echo "OPENAI_API_KEY=$api_key" >> .env
        fi
        echo -e "${GREEN}API Key saved.${NC}"
    else
        echo -e "${RED}Warning: No API Key provided. AI features may not work.${NC}"
    fi
fi

# Build and Start
echo -e "${GREEN}Building and starting services...${NC}"
$DOCKER_CMD -f $DOCKER_COMPOSE_FILE up --build -d

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Deployment successful!${NC}"
    echo -e "Access the application at: ${YELLOW}http://localhost${NC}"
    echo -e "API Documentation: ${YELLOW}http://localhost/api/docs${NC}"
else
    echo -e "${RED}Deployment failed.${NC}"
    exit 1
fi
