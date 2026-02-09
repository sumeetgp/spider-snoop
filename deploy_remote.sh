#!/bin/bash

# Configuration
REMOTE_HOST="hetzner-spider"
REMOTE_DIR="~/spider-snoop"
RSYNC_EXCLUDES="--exclude=.git --exclude=venv --exclude=.venv --exclude=__pycache__ --exclude=storage --exclude=*.pyc --exclude=.DS_Store --exclude=node_modules"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🕷️  Spider-Snoop Remote Deployment${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""

# 1. Build React Frontend Locally
echo -e "${YELLOW}📦 Building React frontend locally...${NC}"
cd frontend
npm install
npm run build
cd ..
echo -e "${GREEN}✅ React build complete${NC}"
echo ""

# 2. Create Remote Directory
echo -e "${YELLOW}📁 Creating remote directory...${NC}"
ssh $REMOTE_HOST "mkdir -p $REMOTE_DIR"
echo -e "${GREEN}✅ Remote directory ready${NC}"
echo ""

# 3. Sync Files (including built frontend)
echo -e "${YELLOW}🔄 Syncing files to $REMOTE_HOST...${NC}"
rsync -avz --progress $RSYNC_EXCLUDES \
    ./ $REMOTE_HOST:$REMOTE_DIR/
echo -e "${GREEN}✅ Files synced${NC}"
echo ""

# 4. Deploy on Remote Server
echo -e "${YELLOW}🚀 Executing remote deployment...${NC}"
ssh $REMOTE_HOST "cd $REMOTE_DIR && \
    echo '🐳 Building Docker containers...' && \
    docker compose build frontend nginx api && \
    echo '🔧 Fixing database permissions...' && \
    docker compose run --rm --user root db chown -R postgres:postgres /var/lib/postgresql/data && \
    echo '🔄 Starting services...' && \
    docker compose up -d"

# 5. Database Migrations (Separate Step for Safety)
echo -e "${YELLOW}📊 Applying database migrations...${NC}"
ssh $REMOTE_HOST "cd $REMOTE_DIR && docker compose exec -T api alembic upgrade head" || {
    echo -e "${RED}⚠️  Migration warning. Check logs.${NC}"
}
echo ""

# 6. Final Status Check
echo -e "${YELLOW}🔍 Checking container status...${NC}"
ssh $REMOTE_HOST "cd $REMOTE_DIR && docker compose ps"
echo ""

echo -e "${GREEN}✅ Remote Deployment Complete!${NC}"
echo ""
echo -e "${GREEN}🌐 Application Links:${NC}"
echo -e "   - Dashboard: https://spidercob.com/dashboard"
echo -e "   - API Docs:  https://spidercob.com/api/docs"
echo ""
