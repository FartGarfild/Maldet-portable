#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
inspath="${MALDET_HOME:-$SCRIPT_DIR/maldetect}"

if [ ! -d "files" ]; then
    echo "Error: 'files' directory not found"
    exit 1
fi

echo "Creating portable Linux Malware Detect installation..."
mkdir -p "$inspath"/{clean,pub,quarantine,sess,sigs,tmp,logs}
chmod 755 "$inspath"
chmod 750 "$inspath"/{quarantine,sess,tmp}

cp -pR files/* "$inspath/"
chmod 755 "$inspath/maldet"

cp -f CHANGELOG COPYING.GPL README "$inspath/"

cat > "$inspath/run-maldet.sh" << 'EOF'
#!/bin/bash
MALDET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$MALDET_DIR:$PATH"
"$MALDET_DIR/maldet" "$@"
EOF
chmod +x "$inspath/run-maldet.sh"

logf="$inspath/logs/event_log"
touch "$logf"

echo ""
echo "Portable Linux Malware Detect v1.6.6"
echo "Installation completed to: $inspath"
echo ""
echo "Usage:"
echo "  $inspath/run-maldet.sh [options]"
echo "  Or set: export PATH=\"$inspath:\$PATH\""
echo ""
echo "Config file: $inspath/conf.maldet"
echo "Logs: $inspath/logs/"
echo ""
echo "Note: ClamAV integration and cron jobs NOT installed (portable mode)"
echo ""

read -p "Update malware signatures now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    "$inspath/maldet" --update 1
fi
