#!/bin/bash
REMOTE_HOST="hetzner-spider"
REMOTE_DIR="~/spider-snoop"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="spider_snoop_stable_${TIMESTAMP}.sql"

echo "📦 Streaming database backup from remote server..."

# Run pg_dump and stream directly to local file
# -T disables pseudo-tty allocation (crucial for clean stdout piping)
ssh $REMOTE_HOST "cd $REMOTE_DIR && docker compose exec -T db pg_dump -U postgres -d spider_snoop -F p" > "$BACKUP_FILE"

# Verify file size
if [ -s "$BACKUP_FILE" ]; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "✅ Backup success!"
    echo "   File: $(pwd)/$BACKUP_FILE"
    echo "   Size: $SIZE"
else
    echo "❌ Backup failed. File is empty or connection error."
    rm -f "$BACKUP_FILE"
    exit 1
fi
