#!/bin/bash

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/letsencrypt/renewal.log"

# Ensure we are in the project directory
cd "$PROJECT_DIR"

echo "----------------------------------------------------------------" >> "$LOG_FILE"
echo "[$(date)] Starting certificate renewal check..." >> "$LOG_FILE"

# Run Certbot Renew
# --post-hook only runs if certificates were actually renewed
# We use 'docker compose kill -s SIGHUP nginx' to reload Nginx configuration without downtime
sudo certbot renew --quiet --post-hook "docker compose kill -s SIGHUP nginx && echo '[$(date)] Nginx reloaded successfully' >> $LOG_FILE"

echo "[$(date)] Renewal check completed." >> "$LOG_FILE"
