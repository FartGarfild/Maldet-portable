#!/bin/bash

MALDET_PATH="/root/maldetect-1.6.6/maldet"
TARGET_DIR="/home/"
RESULT_LOG="/root/found_malware.txt"
FILE_QUEUE="/tmp/maldet_files.list"
WORKER_COUNT=4

COUNTER_FILE="/tmp/maldet_counter"
FOUND_FILE="/tmp/maldet_found"
LOCK_FILE="/tmp/maldet.lock"
EVENT_LOG="/usr/local/maldetect/logs/event_log"

echo 0 > "$COUNTER_FILE"
echo 0 > "$FOUND_FILE"
touch "$LOCK_FILE"

mkdir -p "$(dirname "$EVENT_LOG")"
truncate -s 0 "$EVENT_LOG"

echo "[*] Indexing files..."
find "$TARGET_DIR" -type f > "$FILE_QUEUE"
TOTAL_FILES=$(wc -l < "$FILE_QUEUE")

echo "[*] Run: $TOTAL_FILES files with $WORKER_COUNT workers."
echo "--- Scaned $(date) ---" >> "$RESULT_LOG"

WORKER_PIDS=()

worker() {
    local worker_id=$1

    while true; do
        local file
        file=$(
            flock "$LOCK_FILE" bash -c '
                file=$(head -1 "'"$FILE_QUEUE"'" 2>/dev/null)
                if [ -n "$file" ]; then
                    tail -n +2 "'"$FILE_QUEUE"'" > "'"$FILE_QUEUE"'.tmp" && mv "'"$FILE_QUEUE"'.tmp" "'"$FILE_QUEUE"'"
                fi
                echo "$file"
            '
        )

        [ -z "$file" ] && break

        flock "$LOCK_FILE" -c "echo \$(( \$(cat '$COUNTER_FILE') + 1 )) > '$COUNTER_FILE'"
        local counter found
        counter=$(cat "$COUNTER_FILE")
        found=$(cat "$FOUND_FILE")
        echo -ne "Progress: $counter/$TOTAL_FILES | Found: $found | W[$worker_id] | ${file: -50}\r"

        local lines_before
        lines_before=$(wc -l < "$EVENT_LOG" 2>/dev/null || echo 0)

        timeout 10s bash "$MALDET_PATH" --no-clamav -a "$file" > /dev/null 2>&1

        if [ -f "$EVENT_LOG" ] && awk "NR > $lines_before && /hits 1/" "$EVENT_LOG" | grep -q .; then
            flock "$LOCK_FILE" -c "
                echo \$(( \$(cat '$FOUND_FILE') + 1 )) > '$FOUND_FILE'
                echo '$file' >> '$RESULT_LOG'
            "
            local found_now
            found_now=$(cat "$FOUND_FILE")
            echo -e "\n[!] W[$worker_id] VIRUS #$found_now: $file"
        fi

        pgrep -f "maldet.*$file" 2>/dev/null | while read -r pid; do
            [ "$pid" != "$$" ] && kill -9 "$pid" 2>/dev/null
        done
    done
}

cleanup() {
    echo -e "\n[!] Interrupted! Killing workers..."
    for pid in "${WORKER_PIDS[@]}"; do
        pkill -KILL -P "$pid" 2>/dev/null
        kill -9 "$pid" 2>/dev/null
    done
    rm -f "$COUNTER_FILE" "$FOUND_FILE" "$LOCK_FILE" "${FILE_QUEUE}"*
    exit 1
}
trap cleanup SIGINT SIGTERM

for i in $(seq 1 "$WORKER_COUNT"); do
    worker "$i" &
    WORKER_PIDS+=($!)
done

wait "${WORKER_PIDS[@]}"

FOUND_COUNT=$(cat "$FOUND_FILE")
echo -e "\n\n[*] Done!"
echo "[*] All Malwares found: $FOUND_COUNT"
echo "[*] Malwares list: $RESULT_LOG"

rm -f "$COUNTER_FILE" "$FOUND_FILE" "$LOCK_FILE" "${FILE_QUEUE}"*