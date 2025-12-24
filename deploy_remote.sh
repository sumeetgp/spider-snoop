#!/bin/bash

# Configuration
REMOTE_HOST="linode-spider"
REMOTE_DIR="~/spider-snoop"
RSYNC_EXCLUDES="--exclude '.git' --exclude 'venv' --exclude '__pycache__' --exclude 'storage' --exclude '*.pyc' --exclude '.DS_Store'"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}Deploying to $REMOTE_HOST...${NC}"

# 1. Create Remote Directory
echo -e "${GREEN}Creating remote directory...${NC}"
ssh $REMOTE_HOST "mkdir -p $REMOTE_DIR"

# 2. Sync Files
echo -e "${GREEN}Syncing files...${NC}"
rsync -avz $RSYNC_EXCLUDES ./ $REMOTE_HOST:$REMOTE_DIR/

# 3. Deploy
echo -e "${GREEN}Executing Remote Build & Deploy...${NC}"
ssh $REMOTE_HOST "cd $REMOTE_DIR && \
    docker compose -f docker-compose.prod.yml up --build -d && \
    echo 'Running Database Migrations...' && \
    docker compose -f docker-compose.prod.yml exec api alembic upgrade head"

echo -e "${GREEN}Deployment Complete!${NC}"
